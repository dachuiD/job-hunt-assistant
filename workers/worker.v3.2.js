// ============================================================
// 求职小助 v3.1 Cloudflare Worker
// 架构：画像池中心 + 四层输入 + 四类AI输出
// 生成时间: 2026-04-25
//
// 部署说明：
// 1. 绑定 D1: binding="DB", database="job-hunt-db"
// 2. Secrets: DEEPSEEK_API_KEY / BAIDU_API_KEY / RESEND_API_KEY / JWT_SECRET / ADMIN_PASSWORD
// 3. Variables: EMAIL_FROM (默认 onboarding@resend.dev)
// 4. Cron Triggers（稍后配置）:
//    - 0 0 * * *    每天 UTC 00:00 画像池自审
//    - 0 */4 * * *  每 4 小时 面试未复盘提醒
// ============================================================

// ==================== 模型常量 ====================
// DeepSeek 官方模型名（2026-04-24 V4 已上线）
const LLM_MODELS = {
  FAST: 'deepseek-v4-flash',         // V4 Flash 快速模型（提取、分类、文案）
  PRO: 'deepseek-v4-pro',            // V4 Pro 推理模型（匹配、画像、复盘）
  FALLBACK_FAST: 'deepseek-chat',    // V4 Flash 失败兜底到 V3
  FALLBACK_PRO: 'deepseek-reasoner', // V4 Pro 失败兜底到 R1
};

// ==================== 通用工具 ====================
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-User-Fingerprint',
  'Access-Control-Max-Age': '86400',
};

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS },
  });
}

function errResp(message, status = 400, extra = {}) {
  return jsonResp({ error: message, ...extra }, status);
}

// 兼容 Secret（字符串）和 Secrets Store（对象 .get()）两种绑定类型
async function getSecret(v) {
  if (v == null) return '';
  if (typeof v === 'string') return v;
  if (typeof v.get === 'function') return await v.get();
  return String(v);
}

// 生成随机 ID（用于各表主键）
function genId(prefix = '') {
  const t = Date.now().toString(36);
  const r = Math.random().toString(36).slice(2, 10);
  return prefix ? `${prefix}_${t}${r}` : `${t}${r}`;
}

// 当前 ISO 时间
function now() {
  return new Date().toISOString();
}

// 解析 JSON Body，失败返回 null
async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

// 让异步后台任务不被 Worker 提前终止（必须用 ctx.waitUntil）
function runBackground(env, promise) {
  const p = Promise.resolve(promise).catch(err => {
    console.error('background task failed:', err?.message || err);
  });
  if (env.__ctx && typeof env.__ctx.waitUntil === 'function') {
    env.__ctx.waitUntil(p);
  }
  return p;
}

// ==================== JWT (轻量实现) ====================
// 用 HMAC-SHA256 签 token；payload 含 user_id + exp
async function hmacSign(key, data) {
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey(
    'raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );
  const sig = await crypto.subtle.sign('HMAC', k, enc.encode(data));
  return b64urlEncode(new Uint8Array(sig));
}

function b64urlEncode(bytes) {
  if (typeof bytes === 'string') {
    bytes = new TextEncoder().encode(bytes);
  }
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  return bin;
}

async function signToken(env, payload) {
  const secret = await getSecret(env.JWT_SECRET) || 'fallback_dev_secret_change_me';
  const header = { alg: 'HS256', typ: 'JWT' };
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const sig = await hmacSign(secret, `${h}.${p}`);
  return `${h}.${p}.${sig}`;
}

async function verifyToken(env, token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, sig] = parts;
  const secret = await getSecret(env.JWT_SECRET) || 'fallback_dev_secret_change_me';
  const expectedSig = await hmacSign(secret, `${h}.${p}`);
  if (expectedSig !== sig) return null;
  try {
    const payload = JSON.parse(b64urlDecode(p));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

// ==================== LLM 调用封装（带日志 + V4主/V3兜底 + BYOK） ====================
async function callLLM(env, {
  model = 'FAST',        // 'FAST' | 'PRO'
  messages,
  json = false,          // 是否要求 JSON 输出
  temperature = 0.3,
  purpose = 'unknown',   // 日志用途标记
  userId = null,
  maxRetry = 1,
  apiKey = null,         // 调用方可传入（BYOK），否则用 env.DEEPSEEK_API_KEY
}) {
  const effectiveKey = apiKey || await getSecret(env.DEEPSEEK_API_KEY);
  if (!effectiveKey) throw new Error('缺少 DEEPSEEK_API_KEY');

  const primaryModel = LLM_MODELS[model];
  const fallbackModel = LLM_MODELS[`FALLBACK_${model}`] || LLM_MODELS.FALLBACK_FAST;

  const startTs = Date.now();
  let lastError = null;
  let usedModel = primaryModel;
  let result = null;

  for (const currentModel of [primaryModel, fallbackModel].slice(0, maxRetry + 1)) {
    usedModel = currentModel;
    try {
      const body = {
        model: currentModel,
        messages,
        temperature,
      };
      if (json) body.response_format = { type: 'json_object' };

      const resp = await fetch('https://api.deepseek.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${effectiveKey}`,
        },
        body: JSON.stringify(body),
      });

      if (!resp.ok) {
        const errTxt = await resp.text();
        throw new Error(`LLM ${resp.status}: ${errTxt.slice(0, 200)}`);
      }

      const data = await resp.json();
      const content = data.choices?.[0]?.message?.content;
      if (!content) throw new Error('LLM 返回为空');

      result = {
        content,
        model: currentModel,
        usage: data.usage || {},
        duration_ms: Date.now() - startTs,
      };
      break; // 成功，跳出
    } catch (e) {
      lastError = e;
      // 继续尝试下一个模型（兜底）
    }
  }

  // 写日志
  try {
    await env.DB.prepare(`
      INSERT INTO llm_call_logs (id, user_id, model, purpose, input_tokens, output_tokens, duration_ms, status, error, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      genId('llm'),
      userId,
      usedModel,
      purpose,
      result?.usage?.prompt_tokens || null,
      result?.usage?.completion_tokens || null,
      Date.now() - startTs,
      result ? (usedModel === primaryModel ? 'success' : 'fallback') : 'failed',
      lastError ? String(lastError.message || lastError).slice(0, 500) : null,
      now()
    ).run();
  } catch (_) { /* 日志写失败不影响主流程 */ }

  if (!result) throw lastError || new Error('LLM 调用失败');
  return result;
}

// 从 LLM 返回中安全解析 JSON（兼容 markdown 包裹）
function safeParseJson(text) {
  if (!text) return null;
  let t = text.trim();
  // 去掉 ```json ... ``` 或 ``` ... ```
  const m = t.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/);
  if (m) t = m[1].trim();
  try {
    return JSON.parse(t);
  } catch {
    return null;
  }
}

// ==================== 认证中间件 ====================
// 从请求头解析 token，返回 user 对象；没登录返回 null
async function authUser(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return null;

  const payload = await verifyToken(env, token);
  if (!payload?.user_id) return null;

  const row = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(payload.user_id).first();
  if (!row) return null;
  return row;
}

// 需要登录的路由用这个包一下
async function requireAuth(request, env) {
  const user = await authUser(request, env);
  if (!user) return { error: errResp('unauthorized', 401) };
  return { user };
}

// ==================== 数据库迁移 ====================
// /api/admin/migrate —— 部署后访问一次，自动补齐 schema 增量字段/表
async function runMigration(env) {
  const log = [];

  async function hasColumn(table, col) {
    const cols = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
    return (cols.results || []).some(c => c.name === col);
  }

  async function hasIndex(name) {
    const r = await env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type='index' AND name = ?"
    ).bind(name).first();
    return !!r;
  }

  async function hasTable(name) {
    const r = await env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name = ?"
    ).bind(name).first();
    return !!r;
  }

  try {
    // 1) users.fingerprint（账号改造）
    if (!(await hasColumn('users', 'fingerprint'))) {
      await env.DB.prepare('ALTER TABLE users ADD COLUMN fingerprint TEXT').run();
      log.push('✅ users.fingerprint 已添加');
    } else log.push('⏭️  users.fingerprint 已存在');

    if (!(await hasIndex('idx_users_fingerprint'))) {
      await env.DB.prepare('CREATE UNIQUE INDEX idx_users_fingerprint ON users(fingerprint)').run();
      log.push('✅ idx_users_fingerprint 已创建');
    } else log.push('⏭️  idx_users_fingerprint 已存在');

    // 2) users.is_admin（管理员标识）
    if (!(await hasColumn('users', 'is_admin'))) {
      await env.DB.prepare('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0').run();
      log.push('✅ users.is_admin 已添加');
    } else log.push('⏭️  users.is_admin 已存在');

    // 3) users.own_api_key（BYOK 用户自带 Key）
    if (!(await hasColumn('users', 'own_api_key'))) {
      await env.DB.prepare('ALTER TABLE users ADD COLUMN own_api_key TEXT').run();
      log.push('✅ users.own_api_key 已添加');
    } else log.push('⏭️  users.own_api_key 已存在');

    // 4) jds.match_quick（Flash 粗匹配分数 + 档位）
    if (!(await hasColumn('jds', 'match_quick'))) {
      await env.DB.prepare('ALTER TABLE jds ADD COLUMN match_quick TEXT').run();
      log.push('✅ jds.match_quick 已添加');
    } else log.push('⏭️  jds.match_quick 已存在');

    // 5) usage_quota 表（每日配额记账）
    if (!(await hasTable('usage_quota'))) {
      await env.DB.prepare(`
        CREATE TABLE usage_quota (
          user_id TEXT NOT NULL,
          date TEXT NOT NULL,
          flash_used INTEGER DEFAULT 0,
          pro_used INTEGER DEFAULT 0,
          using_own_key INTEGER DEFAULT 0,
          updated_at TEXT NOT NULL,
          PRIMARY KEY (user_id, date)
        )
      `).run();
      log.push('✅ usage_quota 表已创建');
    } else log.push('⏭️  usage_quota 表已存在');

    if (!(await hasIndex('idx_uq_date'))) {
      await env.DB.prepare('CREATE INDEX idx_uq_date ON usage_quota(date DESC)').run();
      log.push('✅ idx_uq_date 已创建');
    } else log.push('⏭️  idx_uq_date 已存在');

    // 6) 修复 users.email 的 NOT NULL 约束（建表时写错，应允许匿名账号邮箱为空）
    // SQLite 不支持 ALTER COLUMN，要通过重建表来去除约束
    // 先检查约束是否真的有问题
    const userCols = await env.DB.prepare("PRAGMA table_info(users)").all();
    const emailCol = (userCols.results || []).find(c => c.name === 'email');
    if (emailCol && emailCol.notnull === 1) {
      // 检查是否已有用户（有用户就需要备份数据）
      const userCount = await env.DB.prepare('SELECT COUNT(*) AS c FROM users').first();
      if ((userCount?.c || 0) === 0) {
        // 无数据，直接重建
        await env.DB.prepare('DROP TABLE users').run();
        await env.DB.prepare(`
          CREATE TABLE users (
            id TEXT PRIMARY KEY,
            email TEXT,
            name TEXT,
            target_track TEXT,
            target_stage TEXT,
            school TEXT,
            major TEXT,
            graduation_year INTEGER,
            onboarded INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            last_active_at TEXT,
            fingerprint TEXT,
            is_admin INTEGER DEFAULT 0,
            own_api_key TEXT
          )
        `).run();
        await env.DB.prepare('CREATE UNIQUE INDEX idx_users_email ON users(email)').run();
        await env.DB.prepare('CREATE UNIQUE INDEX idx_users_fingerprint ON users(fingerprint)').run();
        log.push('🔧 users 表已重建，移除 email NOT NULL 约束');
      } else {
        // 有数据，用临时表迁移
        await env.DB.prepare(`
          CREATE TABLE users_new (
            id TEXT PRIMARY KEY,
            email TEXT,
            name TEXT,
            target_track TEXT,
            target_stage TEXT,
            school TEXT,
            major TEXT,
            graduation_year INTEGER,
            onboarded INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            last_active_at TEXT,
            fingerprint TEXT,
            is_admin INTEGER DEFAULT 0,
            own_api_key TEXT
          )
        `).run();
        await env.DB.prepare(`
          INSERT INTO users_new
          SELECT id, email, name, target_track, target_stage, school, major,
                 graduation_year, onboarded, created_at, last_active_at,
                 fingerprint, is_admin, own_api_key
          FROM users
        `).run();
        await env.DB.prepare('DROP TABLE users').run();
        await env.DB.prepare('ALTER TABLE users_new RENAME TO users').run();
        await env.DB.prepare('CREATE UNIQUE INDEX idx_users_email ON users(email)').run();
        await env.DB.prepare('CREATE UNIQUE INDEX idx_users_fingerprint ON users(fingerprint)').run();
        log.push(`🔧 users 表已迁移重建（保留 ${userCount.c} 条数据），移除 email NOT NULL 约束`);
      }
    } else {
      log.push('⏭️  users.email 约束已正确（无需修复）');
    }

    return { ok: true, log };
  } catch (e) {
    log.push(`❌ ${e.message}`);
    return { ok: false, log };
  }
}

// ==================== 账号模块 ====================

// POST /api/auth/anon
// Body: { fingerprint: "xxx" }
// 如果 fingerprint 已存在 → 返回现有 user + token
// 如果不存在 → 创建新 user + token
async function handleAnonAuth(request, env) {
  const body = await readJson(request);
  const fingerprint = body?.fingerprint?.trim();
  if (!fingerprint || fingerprint.length < 8) {
    return errResp('fingerprint required (min 8 chars)');
  }

  let user = await env.DB.prepare('SELECT * FROM users WHERE fingerprint = ?').bind(fingerprint).first();

  if (!user) {
    const userId = genId('u');
    const ts = now();
    await env.DB.prepare(`
      INSERT INTO users (id, email, fingerprint, onboarded, created_at, last_active_at)
      VALUES (?, NULL, ?, 0, ?, ?)
    `).bind(userId, fingerprint, ts, ts).run();
    user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
  } else {
    // 更新活跃时间
    await env.DB.prepare('UPDATE users SET last_active_at = ? WHERE id = ?')
      .bind(now(), user.id).run();
  }

  // 签发 30 天 token
  const exp = Math.floor(Date.now() / 1000) + 30 * 24 * 3600;
  const token = await signToken(env, { user_id: user.id, exp });

  // 存入 sessions
  const sid = genId('s');
  await env.DB.prepare(`
    INSERT INTO sessions (token, user_id, expires_at, created_at)
    VALUES (?, ?, ?, ?)
  `).bind(token, user.id, new Date(exp * 1000).toISOString(), now()).run();

  return jsonResp({
    ok: true,
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      onboarded: user.onboarded,
      is_admin: user.is_admin || 0,
      target_track: user.target_track,
      target_stage: user.target_stage,
      school: user.school,
      major: user.major,
      graduation_year: user.graduation_year,
    },
  });
}

// GET /api/auth/me —— 读取当前登录用户
async function handleMe(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  return jsonResp({
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      onboarded: user.onboarded,
      is_admin: user.is_admin || 0,
      target_track: user.target_track,
      target_stage: user.target_stage,
      school: user.school,
      major: user.major,
      graduation_year: user.graduation_year,
    },
  });
}

// POST /api/auth/onboard —— 提交引导卡牌信息
async function handleOnboard(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  const { name, target_track, target_stage, school, major, graduation_year } = body;

  await env.DB.prepare(`
    UPDATE users SET
      name = COALESCE(?, name),
      target_track = COALESCE(?, target_track),
      target_stage = COALESCE(?, target_stage),
      school = COALESCE(?, school),
      major = COALESCE(?, major),
      graduation_year = COALESCE(?, graduation_year),
      onboarded = 1,
      last_active_at = ?
    WHERE id = ?
  `).bind(
    name || null,
    target_track || null,
    target_stage || null,
    school || null,
    major || null,
    graduation_year ? Number(graduation_year) : null,
    now(),
    user.id
  ).run();

  // 初始化通知偏好（如果还没有）
  const existingPref = await env.DB.prepare(
    'SELECT user_id FROM notification_preferences WHERE user_id = ?'
  ).bind(user.id).first();
  if (!existingPref) {
    await env.DB.prepare(`
      INSERT INTO notification_preferences (user_id, updated_at)
      VALUES (?, ?)
    `).bind(user.id, now()).run();
  }

  return jsonResp({ ok: true });
}

// POST /api/auth/bind-email/send —— 给邮箱发验证码
async function handleSendEmailCode(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  const email = (body.email || '').trim().toLowerCase();
  if (!/^[\w.+-]+@[\w-]+\.[\w.-]+$/.test(email)) {
    return errResp('invalid email');
  }

  // 生成 6 位验证码
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  await env.DB.prepare(`
    INSERT INTO email_verifications (id, email, code, purpose, expires_at, created_at)
    VALUES (?, ?, ?, 'bind', ?, ?)
  `).bind(genId('ev'), email, code, expiresAt, now()).run();

  // 调 Resend 发邮件
  const resendKey = await getSecret(env.RESEND_API_KEY);
  const from = env.EMAIL_FROM || 'onboarding@resend.dev';

  if (!resendKey) {
    // 开发模式：没配 Resend 时返回验证码本身
    return jsonResp({ ok: true, dev_code: code, note: 'RESEND_API_KEY not set, returning code for dev only' });
  }

  try {
    const resendResp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${resendKey}`,
      },
      body: JSON.stringify({
        from,
        to: [email],
        subject: '【求职小助】验证码',
        html: `
          <div style="font-family: -apple-system, sans-serif; max-width: 480px; margin: 0 auto; padding: 32px;">
            <h2 style="color: #111;">求职小助 - 绑定邮箱</h2>
            <p style="color: #555;">你好，你的验证码是：</p>
            <div style="font-size: 32px; font-weight: 700; letter-spacing: 4px; color: #2563eb; padding: 16px; background: #f0f7ff; border-radius: 8px; text-align: center; margin: 16px 0;">${code}</div>
            <p style="color: #999; font-size: 14px;">10 分钟内有效。如果不是本人操作，请忽略。</p>
          </div>
        `,
      }),
    });

    if (!resendResp.ok) {
      const errTxt = await resendResp.text();
      return errResp(`发送失败：${errTxt.slice(0, 200)}`, 500);
    }

    return jsonResp({ ok: true, message: '验证码已发送' });
  } catch (e) {
    return errResp(`发送异常：${e.message}`, 500);
  }
}

// POST /api/auth/bind-email/verify
// Body: { email, code }
async function handleVerifyEmailCode(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  const email = (body.email || '').trim().toLowerCase();
  const code = (body.code || '').trim();
  if (!email || !code) return errResp('email and code required');

  const vrow = await env.DB.prepare(`
    SELECT * FROM email_verifications
    WHERE email = ? AND code = ? AND used = 0 AND expires_at > ?
    ORDER BY created_at DESC LIMIT 1
  `).bind(email, code, now()).first();

  if (!vrow) return errResp('验证码错误或已过期', 400);

  // 检查该邮箱是否已被别的用户绑定
  const other = await env.DB.prepare('SELECT id FROM users WHERE email = ? AND id != ?')
    .bind(email, user.id).first();
  if (other) return errResp('该邮箱已被其他账号绑定', 409);

  // 绑定邮箱
  await env.DB.prepare('UPDATE users SET email = ?, last_active_at = ? WHERE id = ?')
    .bind(email, now(), user.id).run();

  // 标记验证码已用
  await env.DB.prepare('UPDATE email_verifications SET used = 1 WHERE id = ?')
    .bind(vrow.id).run();

  return jsonResp({ ok: true, email });
}

// POST /api/auth/recover-by-email
// Body: { email, code }
// 已绑定邮箱的用户在新设备上通过邮箱验证码恢复登录
async function handleRecoverByEmail(request, env) {
  const body = await readJson(request) || {};
  const email = (body.email || '').trim().toLowerCase();
  const code = (body.code || '').trim();
  const newFingerprint = body.fingerprint?.trim();

  if (!email || !code) return errResp('email and code required');

  // 验证码校验
  const vrow = await env.DB.prepare(`
    SELECT * FROM email_verifications
    WHERE email = ? AND code = ? AND used = 0 AND expires_at > ?
    ORDER BY created_at DESC LIMIT 1
  `).bind(email, code, now()).first();
  if (!vrow) return errResp('验证码错误或已过期', 400);

  // 找到绑定该邮箱的用户
  const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  if (!user) return errResp('该邮箱未绑定任何账号', 404);

  // 更新 fingerprint（允许换设备）
  if (newFingerprint) {
    await env.DB.prepare('UPDATE users SET fingerprint = ?, last_active_at = ? WHERE id = ?')
      .bind(newFingerprint, now(), user.id).run();
  }
  await env.DB.prepare('UPDATE email_verifications SET used = 1 WHERE id = ?').bind(vrow.id).run();

  // 签 token
  const exp = Math.floor(Date.now() / 1000) + 30 * 24 * 3600;
  const token = await signToken(env, { user_id: user.id, exp });
  await env.DB.prepare(`
    INSERT INTO sessions (token, user_id, expires_at, created_at)
    VALUES (?, ?, ?, ?)
  `).bind(token, user.id, new Date(exp * 1000).toISOString(), now()).run();

  return jsonResp({
    ok: true,
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      onboarded: user.onboarded,
      target_track: user.target_track,
      target_stage: user.target_stage,
    },
  });
}

// POST /api/auth/recover-send —— 触发发恢复验证码（不需要登录，用于新设备）
async function handleRecoverSend(request, env) {
  const body = await readJson(request) || {};
  const email = (body.email || '').trim().toLowerCase();
  if (!/^[\w.+-]+@[\w-]+\.[\w.-]+$/.test(email)) return errResp('invalid email');

  // 邮箱必须已被绑定过
  const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (!user) return errResp('该邮箱未绑定任何账号', 404);

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  await env.DB.prepare(`
    INSERT INTO email_verifications (id, email, code, purpose, expires_at, created_at)
    VALUES (?, ?, ?, 'recover', ?, ?)
  `).bind(genId('ev'), email, code, expiresAt, now()).run();

  const resendKey = await getSecret(env.RESEND_API_KEY);
  const from = env.EMAIL_FROM || 'onboarding@resend.dev';
  if (!resendKey) return jsonResp({ ok: true, dev_code: code });

  try {
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${resendKey}`,
      },
      body: JSON.stringify({
        from,
        to: [email],
        subject: '【求职小助】恢复账号',
        html: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;">
          <h2>求职小助 - 恢复账号</h2>
          <p>你的恢复验证码：</p>
          <div style="font-size:32px;font-weight:700;letter-spacing:4px;color:#2563eb;padding:16px;background:#f0f7ff;border-radius:8px;text-align:center;margin:16px 0;">${code}</div>
          <p style="color:#999;font-size:14px;">10 分钟内有效。</p>
        </div>`,
      }),
    });
    if (!resp.ok) {
      const txt = await resp.text();
      return errResp(`发送失败：${txt.slice(0, 200)}`, 500);
    }
    return jsonResp({ ok: true });
  } catch (e) {
    return errResp(e.message, 500);
  }
}

// ==================== 简历模块 ====================

// GET /api/resumes —— 列出当前用户所有简历
async function handleListResumes(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const { results } = await env.DB.prepare(`
    SELECT id, title, is_primary, parse_status, parse_error, created_at, updated_at,
           CASE WHEN parsed_json IS NOT NULL THEN 1 ELSE 0 END AS has_parsed,
           substr(raw_text, 1, 200) AS preview
    FROM resumes WHERE user_id = ?
    ORDER BY is_primary DESC, updated_at DESC
  `).bind(user.id).all();

  return jsonResp({ resumes: results || [] });
}

// GET /api/resumes/:id
async function handleGetResume(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const row = await env.DB.prepare('SELECT * FROM resumes WHERE id = ? AND user_id = ?')
    .bind(id, user.id).first();
  if (!row) return errResp('not found', 404);

  return jsonResp({
    resume: {
      ...row,
      parsed: row.parsed_json ? safeParseJson(row.parsed_json) : null,
    },
  });
}

// POST /api/resumes —— 创建简历并触发解析
// Body: { title, raw_text, is_primary? }
async function handleCreateResume(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  const title = (body.title || '').trim() || '未命名简历';
  const raw_text = (body.raw_text || '').trim();
  const is_primary = body.is_primary ? 1 : 0;

  if (raw_text.length < 20) return errResp('简历内容太短（至少20字）');
  if (raw_text.length > 20000) return errResp('简历内容过长（最多20000字）');

  // 限制每用户最多 5 份简历
  const cnt = await env.DB.prepare('SELECT COUNT(*) as c FROM resumes WHERE user_id = ?')
    .bind(user.id).first();
  if ((cnt?.c || 0) >= 5) return errResp('最多 5 份简历，请先删除旧的', 400);

  // v3.2: 首份简历自动设为主简历
  const effectivePrimary = is_primary || (cnt?.c === 0) ? 1 : 0;

  const id = genId('r');
  const ts = now();

  if (effectivePrimary) {
    await env.DB.prepare('UPDATE resumes SET is_primary = 0 WHERE user_id = ?')
      .bind(user.id).run();
  }

  await env.DB.prepare(`
    INSERT INTO resumes (id, user_id, title, is_primary, raw_text, parse_status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 'processing', ?, ?)
  `).bind(id, user.id, title, effectivePrimary, raw_text, ts, ts).run();

  // 同步解析
  try {
    const parsed = await parseResume(env, raw_text, user);
    await env.DB.prepare(`
      UPDATE resumes SET parsed_json = ?, parse_status = 'done', updated_at = ?
      WHERE id = ?
    `).bind(JSON.stringify(parsed), now(), id).run();

    // 触发画像池更新（后台异步，通过 waitUntil 保证不被 Worker 终止）
    const resumeRow = { id, parsed_json: JSON.stringify(parsed), raw_text };
    runBackground(env, updateProfileFromResume(env, resumeRow, user));

    return jsonResp({ ok: true, id, parsed });
  } catch (e) {
    const quotaResp = handleQuotaError(e);
    if (quotaResp) {
      // 删掉刚插入的空记录，避免脏数据
      await env.DB.prepare('DELETE FROM resumes WHERE id = ?').bind(id).run();
      return quotaResp;
    }
    await env.DB.prepare(`
      UPDATE resumes SET parse_status = 'failed', parse_error = ?, updated_at = ?
      WHERE id = ?
    `).bind(String(e.message || e).slice(0, 500), now(), id).run();
    return jsonResp({ ok: false, id, error: String(e.message || e) });
  }
}

// PUT /api/resumes/:id —— 更新简历（title/is_primary/重新解析）
async function handleUpdateResume(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  const row = await env.DB.prepare('SELECT * FROM resumes WHERE id = ? AND user_id = ?')
    .bind(id, user.id).first();
  if (!row) return errResp('not found', 404);

  const updates = [];
  const bindings = [];

  if (typeof body.title === 'string') {
    updates.push('title = ?');
    bindings.push(body.title.trim());
  }
  if (body.is_primary === true || body.is_primary === 1) {
    await env.DB.prepare('UPDATE resumes SET is_primary = 0 WHERE user_id = ?').bind(user.id).run();
    updates.push('is_primary = 1');
  }
  if (typeof body.raw_text === 'string' && body.raw_text.trim().length >= 20) {
    updates.push('raw_text = ?', 'parse_status = ?');
    bindings.push(body.raw_text.trim(), 'processing');
  }

  if (updates.length === 0) return jsonResp({ ok: true, unchanged: true });

  updates.push('updated_at = ?');
  bindings.push(now());
  bindings.push(id);

  await env.DB.prepare(`UPDATE resumes SET ${updates.join(', ')} WHERE id = ?`)
    .bind(...bindings).run();

    // 如果内容变了，重新解析
  if (typeof body.raw_text === 'string') {
    try {
      const parsed = await parseResume(env, body.raw_text.trim(), user);
      await env.DB.prepare(`
        UPDATE resumes SET parsed_json = ?, parse_status = 'done', updated_at = ?
        WHERE id = ?
      `).bind(JSON.stringify(parsed), now(), id).run();

      // 触发画像池更新
      const resumeRow = { id, parsed_json: JSON.stringify(parsed), raw_text: body.raw_text.trim() };
      runBackground(env, updateProfileFromResume(env, resumeRow, user));
    } catch (e) {
      const quotaResp = handleQuotaError(e);
      if (quotaResp) return quotaResp;
      await env.DB.prepare(`
        UPDATE resumes SET parse_status = 'failed', parse_error = ?, updated_at = ?
        WHERE id = ?
      `).bind(String(e.message || e).slice(0, 500), now(), id).run();
    }
  }

  return jsonResp({ ok: true });
}

// DELETE /api/resumes/:id
async function handleDeleteResume(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const res = await env.DB.prepare('DELETE FROM resumes WHERE id = ? AND user_id = ?')
    .bind(id, user.id).run();
  return jsonResp({ ok: true, deleted: res.meta?.changes || 0 });
}

// LLM: 解析简历
async function parseResume(env, rawText, user) {
  const prompt = `你是一个求职助手，请从以下简历文本中提取结构化信息。

要求：
1. 只输出 JSON，不要添加任何说明文字
2. 字段严格按下面 schema 输出，缺失的字段输出 null 或空数组
3. 经历/项目描述尽量保留原文关键数字和成果

输出 JSON 结构：
{
  "basic": {
    "name": "姓名",
    "email": "邮箱",
    "phone": "手机",
    "city": "当前城市"
  },
  "education": [
    {"school": "学校", "major": "专业", "degree": "学历", "period": "起止时间", "gpa": "GPA或排名"}
  ],
  "experiences": [
    {"company": "公司", "role": "职位", "period": "时间", "description": "工作内容概述", "achievements": ["关键成果1", "关键成果2"]}
  ],
  "projects": [
    {"name": "项目名", "role": "角色", "period": "时间", "description": "简介", "tech_stack": ["技术1"]}
  ],
  "skills": ["技能1", "技能2"],
  "awards": ["奖项/证书"],
  "target_position": "目标岗位（如简历里写了）"
}

简历原文：
"""
${rawText}
"""`;

  const { content } = await runLLMWithQuota(env, user, 'FAST', {
    messages: [
      { role: 'system', content: '你是一个严谨的简历解析助手，只输出 JSON，不说废话。' },
      { role: 'user', content: prompt },
    ],
    json: true,
    temperature: 0.2,
    purpose: 'parse_resume',
  });

  const parsed = safeParseJson(content);
  if (!parsed) throw new Error('LLM 返回格式无法解析');
  return parsed;
}

// ==================== JD 模块 ====================

// GET /api/jds
async function handleListJDs(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const url = new URL(request.url);
  const q = url.searchParams.get('q')?.trim() || '';

  let sql = `
    SELECT j.id, j.company, j.position_title, j.city, j.job_type, j.match_score, j.match_quick,
           j.parse_status, j.created_at, j.updated_at,
           CASE WHEN j.match_detail IS NOT NULL THEN 1 ELSE 0 END AS has_deep_match,
           substr(j.raw_text, 1, 200) AS preview,
           (SELECT p.id FROM positions p WHERE p.jd_id = j.id AND p.user_id = j.user_id LIMIT 1) AS position_id
    FROM jds j WHERE j.user_id = ?
  `;
  const bindings = [user.id];
  if (q) {
    sql += ' AND (j.company LIKE ? OR j.position_title LIKE ?)';
    bindings.push(`%${q}%`, `%${q}%`);
  }
  sql += ' ORDER BY j.created_at DESC';

  const { results } = await env.DB.prepare(sql).bind(...bindings).all();
  return jsonResp({ jds: results || [] });
}

// GET /api/jds/:id
async function handleGetJD(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const row = await env.DB.prepare('SELECT * FROM jds WHERE id = ? AND user_id = ?')
    .bind(id, user.id).first();
  if (!row) return errResp('not found', 404);

  return jsonResp({
    jd: {
      ...row,
      parsed: row.parsed_json ? safeParseJson(row.parsed_json) : null,
      match_quick: row.match_quick ? safeParseJson(row.match_quick) : null,
      match_detail: row.match_detail ? safeParseJson(row.match_detail) : null,
    },
  });
}

// POST /api/jds —— 创建 JD（异步解析+粗匹配，立刻返回，后台跑）
// Body: {
//   raw_text,
//   company?, position_title?,  // 用户预填，优先级高于 AI 解析
//   create_position?: true,     // 是否同步创建岗位到看板
//   position_status?: 'pending' // 创建岗位时的初始状态
// }
async function handleCreateJD(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  const raw_text = (body.raw_text || '').trim();
  if (raw_text.length < 20) return errResp('JD 内容太短');
  if (raw_text.length > 15000) return errResp('JD 内容过长');

  const prefilledCompany = (body.company || '').trim() || null;
  const prefilledTitle = (body.position_title || '').trim() || null;

  const id = genId('j');
  const ts = now();

  // 先写入数据库，状态 processing，预填字段立即可见
  await env.DB.prepare(`
    INSERT INTO jds (id, user_id, company, position_title, raw_text, parse_status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 'processing', ?, ?)
  `).bind(id, user.id, prefilledCompany, prefilledTitle, raw_text, ts, ts).run();

  // ==================== JD 解析重试辅助 v3.2 ====================
  // 自动重试 LLM 调用（网络超时/模型繁忙），不重试配额超限
  async function retryJDParse(fn, maxRetries = 3) {
    let lastError;
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await fn();
      } catch (e) {
        lastError = e;
        // 配额超限不重试
        if (e?.quotaCheck) throw e;
        if (i < maxRetries - 1) {
          console.log(`JD parse retry ${i + 1}/${maxRetries}: ${e.message?.slice(0, 50)}`);
          await new Promise(r => setTimeout(r, 2000));
        }
      }
    }
    throw lastError;
  }

  // 异步后台跑：解析 + 粗匹配 + 画像 + 可选创建岗位
  runBackground(env, (async () => {
    try {
      // 合并调用：一次 LLM 完成解析 + 粗匹配（如果有主简历）
      const primaryResume = await env.DB.prepare(
        "SELECT * FROM resumes WHERE user_id = ? AND is_primary = 1 AND parse_status = 'done' LIMIT 1"
      ).bind(user.id).first();

      const combined = await retryJDParse(() =>
        parseAndMatchJD(env, raw_text, primaryResume, user, {
          prefilledCompany, prefilledTitle,
        })
      );

      const parsed = combined.parsed;
      const quick = combined.quick;

      // 更新 JD：用预填覆盖 AI 解析
      await env.DB.prepare(`
        UPDATE jds SET
          company = ?, position_title = ?, city = ?, job_type = ?,
          parsed_json = ?,
          match_score = ?, match_quick = ?,
          parse_status = 'done', updated_at = ?
        WHERE id = ?
      `).bind(
        prefilledCompany || parsed?.company || null,
        prefilledTitle || parsed?.position_title || null,
        parsed?.city || null,
        parsed?.job_type || null,
        parsed ? JSON.stringify(parsed) : null,
        quick?.score || null,
        quick ? JSON.stringify(quick) : null,
        now(),
        id
      ).run();

      // 触发画像池更新
      if (parsed) {
        runBackground(env, updateProfileFromJD(env, id, parsed, user));
      }

      // 同步创建岗位到看板（如果用户要求）
      if (body.create_position) {
        const company = prefilledCompany || parsed?.company || '未填公司';
        const positionTitle = prefilledTitle || parsed?.position_title || '未填岗位名';
        const status = body.position_status || 'pending';
        if (POSITION_STATUSES.includes(status)) {
          const posId = genId('p');
          await env.DB.prepare(`
            INSERT INTO positions (id, user_id, jd_id, company, position_title, status,
                                   applied_at, current_round, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            posId, user.id, id, company, positionTitle, status,
            status === 'applied' ? now() : null,
            roundFromStatus(status), now(), now()
          ).run();
          await env.DB.prepare(`
            INSERT INTO position_status_history (id, position_id, from_status, to_status, changed_at)
            VALUES (?, ?, NULL, ?, ?)
          `).bind(genId('psh'), posId, status, now()).run();
        }
      }
    } catch (e) {
      const errMsg = e?.quotaCheck ? 'quota_exceeded' : String(e.message || e).slice(0, 300);
      await env.DB.prepare(`
        UPDATE jds SET parse_status = 'failed', updated_at = ? WHERE id = ?
      `).bind(now(), id).run();
      console.error('JD async process failed:', errMsg);
    }
  })());

  // 立刻返回（不等 AI），前端用 id 轮询直到 parse_status=done
  return jsonResp({
    ok: true, id,
    status: 'processing',
    message: 'JD 已创建，AI 正在后台分析',
  });
}

// POST /api/jds/:id/match —— 手动触发深度匹配（Pro，消耗配额）
// Body: { resume_id? } 不传则用主简历
async function handleMatchJD(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  const jd = await env.DB.prepare('SELECT * FROM jds WHERE id = ? AND user_id = ?')
    .bind(id, user.id).first();
  if (!jd) return errResp('jd not found', 404);

  let resume;
  if (body.resume_id) {
    resume = await env.DB.prepare('SELECT * FROM resumes WHERE id = ? AND user_id = ?')
      .bind(body.resume_id, user.id).first();
  } else {
    resume = await env.DB.prepare(
      "SELECT * FROM resumes WHERE user_id = ? AND is_primary = 1 AND parse_status = 'done' LIMIT 1"
    ).bind(user.id).first();
  }
  if (!resume) return errResp('no resume found', 404);

  try {
    const result = await computeDeepMatch(env, resume, {
      parsed: jd.parsed_json ? safeParseJson(jd.parsed_json) : null,
      raw_text: jd.raw_text,
    }, user);

    await env.DB.prepare(`UPDATE jds SET match_detail = ? WHERE id = ?`)
      .bind(JSON.stringify(result), id).run();

    return jsonResp({ ok: true, match: result });
  } catch (e) {
    const quotaResp = handleQuotaError(e);
    if (quotaResp) return quotaResp;
    throw e;
  }
}

// POST /api/jds/:id/quick-match —— 手动重跑粗匹配（切主简历后可用）
async function handleQuickMatchJD(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const jd = await env.DB.prepare('SELECT * FROM jds WHERE id = ? AND user_id = ?')
    .bind(id, user.id).first();
  if (!jd) return errResp('jd not found', 404);

  const resume = await env.DB.prepare(
    "SELECT * FROM resumes WHERE user_id = ? AND is_primary = 1 AND parse_status = 'done' LIMIT 1"
  ).bind(user.id).first();
  if (!resume) return errResp('no primary resume found', 404);

  try {
    const quick = await computeQuickMatch(env, resume, jd, user);
    await env.DB.prepare(`UPDATE jds SET match_score = ?, match_quick = ? WHERE id = ?`)
      .bind(quick.score, JSON.stringify(quick), id).run();
    return jsonResp({ ok: true, quick });
  } catch (e) {
    const quotaResp = handleQuotaError(e);
    if (quotaResp) return quotaResp;
    throw e;
  }
}

// DELETE /api/jds/:id
async function handleDeleteJD(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const res = await env.DB.prepare('DELETE FROM jds WHERE id = ? AND user_id = ?')
    .bind(id, user.id).run();
  return jsonResp({ ok: true, deleted: res.meta?.changes || 0 });
}

// PUT /api/jds/:id —— 编辑 JD（raw_text 变了会重跑解析+粗匹配）
// Body: { raw_text?, company?, position_title? }
async function handleUpdateJD(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  const existing = await env.DB.prepare('SELECT * FROM jds WHERE id = ? AND user_id = ?')
    .bind(id, user.id).first();
  if (!existing) return errResp('not found', 404);

  const updates = [];
  const bindings = [];
  let rawTextChanged = false;
  let newRawText = existing.raw_text;

  if (typeof body.raw_text === 'string' && body.raw_text.trim().length >= 20 && body.raw_text.trim() !== existing.raw_text) {
    newRawText = body.raw_text.trim();
    updates.push('raw_text = ?', 'parse_status = ?');
    bindings.push(newRawText, 'processing');
    rawTextChanged = true;
  }
  if (typeof body.company === 'string') {
    updates.push('company = ?');
    bindings.push(body.company.trim() || null);
  }
  if (typeof body.position_title === 'string') {
    updates.push('position_title = ?');
    bindings.push(body.position_title.trim() || null);
  }

  if (updates.length === 0) return jsonResp({ ok: true, unchanged: true });

  updates.push('updated_at = ?');
  bindings.push(now());
  bindings.push(id);
  await env.DB.prepare(`UPDATE jds SET ${updates.join(', ')} WHERE id = ?`).bind(...bindings).run();

  // 如果 raw_text 变了，异步重新跑解析+粗匹配
  if (rawTextChanged) {
    runBackground(env, (async () => {
      try {
        const primaryResume = await env.DB.prepare(
          "SELECT * FROM resumes WHERE user_id = ? AND is_primary = 1 AND parse_status = 'done' LIMIT 1"
        ).bind(user.id).first();

        const combined = await retryJDParse(() =>
          parseAndMatchJD(env, newRawText, primaryResume, user, {
            prefilledCompany: body.company || existing.company,
            prefilledTitle: body.position_title || existing.position_title,
          })
        );

        await env.DB.prepare(`
          UPDATE jds SET
            city = ?, job_type = ?, parsed_json = ?,
            match_score = ?, match_quick = ?,
            match_detail = NULL,
            parse_status = 'done', updated_at = ?
          WHERE id = ?
        `).bind(
          combined.parsed?.city || null,
          combined.parsed?.job_type || null,
          combined.parsed ? JSON.stringify(combined.parsed) : null,
          combined.quick?.score || null,
          combined.quick ? JSON.stringify(combined.quick) : null,
          now(), id
        ).run();

        if (combined.parsed) {
          runBackground(env, updateProfileFromJD(env, id, combined.parsed, user));
        }
      } catch (e) {
        await env.DB.prepare(`UPDATE jds SET parse_status = 'failed', updated_at = ? WHERE id = ?`)
          .bind(now(), id).run();
        console.error('JD update re-parse failed:', e.message);
      }
    })());
  }

  return jsonResp({ ok: true, reparsing: rawTextChanged });
}

// LLM: 解析 JD
async function parseJD(env, rawText, user) {
  const prompt = `请从以下 JD 文本中提取结构化信息，只输出 JSON。

{
  "company": "公司名（没写但能从'我们/我司/XX官网'等推断则推断；否则 null，不要编造）",
  "position_title": "岗位名",
  "city": "工作地点",
  "job_type": "internship | campus | social（实习/校招/社招）",
  "responsibilities": ["职责1", "职责2"],
  "requirements": ["要求1", "要求2"],
  "preferred": ["加分项1"],
  "tech_stack": ["技术栈关键词"],
  "salary": "薪资（如有）",
  "duration": "实习时长（如为实习岗）",
  "working_days": "每周几天（如为实习岗）"
}

JD 原文：
"""
${rawText}
"""`;

  const { content } = await runLLMWithQuota(env, user, 'FAST', {
    messages: [
      { role: 'system', content: '你是一个严谨的岗位JD解析助手，只输出 JSON。' },
      { role: 'user', content: prompt },
    ],
    json: true,
    temperature: 0.2,
    purpose: 'parse_jd',
  });

  const parsed = safeParseJson(content);
  if (!parsed) throw new Error('LLM 返回格式无法解析');
  return parsed;
}

// LLM: 合并调用 —— 一次跑完 JD 解析 + 粗匹配（节省一轮网络 + 只扣 1 次 Flash）
// 如果没主简历，只做解析
async function parseAndMatchJD(env, rawText, resume, user, opts = {}) {
  if (!resume) {
    // 只解析
    const parsed = await parseJD(env, rawText, user);
    return { parsed, quick: null };
  }

  const resumeParsed = resume.parsed_json ? safeParseJson(resume.parsed_json) : null;
  const resumeText = resumeParsed
    ? JSON.stringify({
        education: resumeParsed.education?.map(e => ({ school: e.school, major: e.major, degree: e.degree, period: e.period })),
        skills: resumeParsed.skills,
        experiences: resumeParsed.experiences?.map(e => ({ role: e.role, company: e.company, description: e.description })),
        projects: resumeParsed.projects?.map(p => ({ name: p.name, tech_stack: p.tech_stack })),
      }).slice(0, 1800)
    : resume.raw_text.slice(0, 1800);

  const prefilled = [];
  if (opts.prefilledCompany) prefilled.push('公司名：' + opts.prefilledCompany);
  if (opts.prefilledTitle) prefilled.push('岗位名：' + opts.prefilledTitle);

  const prompt = `你同时做两件事：
（A）从 JD 文本提取结构化信息
（B）基于候选人简历关键信息对这个 JD 做严苛匹配评估

【候选人简历关键信息】
${resumeText}

${prefilled.length ? '【用户预填（优先使用，不要改写）】\n' + prefilled.join('\n') + '\n' : ''}
【JD 原文】
"""
${rawText}
"""

---

【评分与匹配纪律（B 任务必须严格遵守）】

1. **身份条件的处理**：
   - "在读""届数（如 2027届）""学历（本科/硕士）" 等身份条件：**匹配时不算 matched_keywords 也不算 missing_keywords**。只有当候选人身份明显不符合时，才在 score 里扣分。
   - **专业匹配要考虑**：如果 JD 明确要求"计算机/软件/信息类相关专业"且候选人是别的专业，算 missing。
   
2. **废话型要求过滤**：
   - 类似 "对 XX 感兴趣""有 XX 热情""有责任心""团队合作能力" 这类 JD 通用客套词，**不纳入 matched/missing**。
   - 原因：候选人投递本身就代表感兴趣；软素质无法从简历证据判断。
   
3. **missing_keywords 只能是**：
   - 真实的硬技能（编程语言/工具/框架）
   - 具体业务经验（如"用户调研""PRD 撰写""竞品分析"）
   - 专业证书或学位（如 CFA、PMP）
   - 明确的项目类型经历（如"推荐系统项目""B端产品经验"）

4. 评分锚点（0-100）：
   - 95-100 全部核心要求命中 + 有亮点
   - 85-94 核心 80%+ 命中
   - 75-84 核心过半命中
   - 65-74 部分重合缺核心能力
   - 50-64 零星相关
   - 30-49 基本不匹配
   - <30 完全不对口

---

只输出 JSON：
{
  "parsed": {
    "company": "公司名（预填优先；没预填且 JD 没明说，可从'我们/我司'推断；都没有则 null，不要编造）",
    "position_title": "岗位名",
    "city": "工作地点",
    "job_type": "internship | campus | social",
    "responsibilities": ["职责1", ...],
    "requirements": ["要求1", ...],
    "preferred": ["加分项1", ...],
    "tech_stack": ["技术关键词1", ...],
    "salary": "薪资（如有）",
    "duration": "实习时长（如有）",
    "working_days": "每周几天（如有）"
  },
  "quick": {
    "score": 0-100整数,
    "matched_keywords": ["真实匹配的硬技能/经验，最多5个"],
    "missing_keywords": ["真实缺失的硬技能/经验/专业，最多5个（不要放身份条件和废话）"],
    "summary": "一句话客观评价（30字内，低匹配就直接说）"
  }
}`;

  const { content } = await runLLMWithQuota(env, user, 'FAST', {
    messages: [
      { role: 'system', content: '你是严苛的 JD 解析+评审助手，只输出 JSON。' },
      { role: 'user', content: prompt },
    ],
    json: true,
    temperature: 0.2,
    purpose: 'parse_match_combined',
  });

  const data = safeParseJson(content);
  if (!data || !data.parsed || !data.quick) throw new Error('合并解析返回格式异常');
  data.quick.score = Math.max(0, Math.min(100, Math.round(data.quick.score || 0)));
  data.quick.band = scoreToBand(data.quick.score);
  return data;
}

// LLM: 计算简历-JD匹配度（深度，Pro）
async function computeDeepMatch(env, resume, jd, user) {
  const resumeParsed = resume.parsed_json ? safeParseJson(resume.parsed_json) : null;

  const prompt = `你是一位经验丰富、严格且坦诚的招聘评审官。候选人粘贴了自己的简历和目标岗位JD，请做客观、有证据的深度评估。

【绝对纪律】
1. 不讨好候选人。发现问题直接点出，不要用"稍显不足""可以进一步加强"这种打太极的话。
2. 每一条结论都必须引用简历或JD的原文片段作为证据。
3. 学生常见毛病必须指出：
   - 技能只罗列没项目支撑（"熟悉Python"但无Python项目）
   - 项目描述没有量化成果（没有数字/百分比/对比基线）
   - 经历与目标岗位相关度低但强行往上靠
   - 时间线有明显空档或身份模糊
4. 不要"为了说优点而造优点"。候选人只有2-3条真匹配就老实说2-3条。

【评分锚点（严格遵守，不要全挤在70-85）】
- 95-100：JD核心要求全部命中 + 有亮点加分
- 85-94：核心要求 80%+ 命中，缺1-2次要能力
- 75-84：核心要求过半命中，主干能力达标
- 65-74：有部分重合但缺核心能力
- 50-64：只有零星相关，主要能力缺失
- 30-49：基本不匹配，仅词汇表面重合
- 0-29：完全不对口

【简历（结构化）】
${resumeParsed ? JSON.stringify(resumeParsed, null, 2) : resume.raw_text.slice(0, 3000)}

【目标JD（结构化）】
${jd.parsed ? JSON.stringify(jd.parsed, null, 2) : jd.raw_text.slice(0, 3000)}

只输出 JSON：
{
  "score": 严格打分（0-100整数）,
  "matched": [
    {"point": "具体匹配点", "resume_evidence": "简历里的原文片段", "jd_evidence": "JD里对应要求"}
  ],
  "missing": [
    {"gap": "候选人缺少的能力或经验", "jd_requirement": "JD里的原文", "severity": "critical|major|minor"}
  ],
  "red_flags": [
    "简历里让人怀疑的地方（如'主导某项目但无量化成果''时间线模糊'）"
  ],
  "suggestions": [
    "给候选人的建议，必须具体到'改哪句话/补什么数据'，不要'多写成果'这种废话"
  ],
  "summary": "一句话客观总评（50字内，可以直接说'匹配度偏低'）"
}`;

  const { content } = await runLLMWithQuota(env, user, 'PRO', {
    messages: [
      { role: 'system', content: '你是严苛、坦诚的招聘评审官。不讨好候选人，只输出JSON。' },
      { role: 'user', content: prompt },
    ],
    json: true,
    temperature: 0.3,
    purpose: 'match_deep',
  });

  const parsed = safeParseJson(content);
  if (!parsed) throw new Error('匹配分析返回格式无法解析');
  parsed.score = Math.max(0, Math.min(100, Math.round(parsed.score || 0)));
  parsed.band = scoreToBand(parsed.score);
  return parsed;
}

// ==================== 岗位状态管理模块 ====================

// 有效状态集合
const POSITION_STATUSES = [
  'pending', 'applied', 'written_test',
  'interview_1', 'interview_2', 'interview_3plus',
  'offer', 'onboard', 'rejected', 'withdrawn',
];

// 从状态推断当前轮次（用于前端展示和 Cron 判断"第几面"）
function roundFromStatus(status) {
  if (status === 'interview_1') return 1;
  if (status === 'interview_2') return 2;
  if (status === 'interview_3plus') return 3;
  return 0;
}

// GET /api/positions —— 列出所有岗位（支持 status 过滤）
async function handleListPositions(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const url = new URL(request.url);
  const status = url.searchParams.get('status');
  const q = url.searchParams.get('q')?.trim() || '';

  let sql = `
    SELECT p.*,
      (SELECT COUNT(*) FROM interview_rounds WHERE position_id = p.id) AS round_count,
      (SELECT COUNT(*) FROM reviews WHERE position_id = p.id) AS review_count
    FROM positions p
    WHERE p.user_id = ?
  `;
  const bindings = [user.id];
  if (status) { sql += ' AND p.status = ?'; bindings.push(status); }
  if (q) {
    sql += ' AND (p.company LIKE ? OR p.position_title LIKE ?)';
    bindings.push(`%${q}%`, `%${q}%`);
  }
  sql += ' ORDER BY p.updated_at DESC';

  const { results } = await env.DB.prepare(sql).bind(...bindings).all();
  return jsonResp({ positions: results || [] });
}

// GET /api/positions/:id —— 岗位详情（含所有轮次和复盘）
async function handleGetPosition(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const position = await env.DB.prepare(
    'SELECT * FROM positions WHERE id = ? AND user_id = ?'
  ).bind(id, user.id).first();
  if (!position) return errResp('not found', 404);

  const [{ results: rounds }, { results: reviews }, { results: history }] = await Promise.all([
    env.DB.prepare(
      'SELECT * FROM interview_rounds WHERE position_id = ? ORDER BY round_number ASC'
    ).bind(id).all(),
    env.DB.prepare(
      'SELECT id, round_id, parse_status, created_at, substr(raw_text, 1, 200) AS preview FROM reviews WHERE position_id = ? ORDER BY created_at DESC'
    ).bind(id).all(),
    env.DB.prepare(
      'SELECT * FROM position_status_history WHERE position_id = ? ORDER BY changed_at DESC LIMIT 20'
    ).bind(id).all(),
  ]);

  let jd = null;
  if (position.jd_id) {
    jd = await env.DB.prepare(
      'SELECT id, company, position_title, city, job_type, match_score, parsed_json FROM jds WHERE id = ?'
    ).bind(position.jd_id).first();
    if (jd && jd.parsed_json) jd.parsed = safeParseJson(jd.parsed_json);
  }

  return jsonResp({
    position,
    jd,
    rounds: rounds || [],
    reviews: reviews || [],
    status_history: history || [],
  });
}

// POST /api/positions —— 创建岗位（可来自 JD 或手动录入）
// Body: { jd_id? | company + position_title, status?, applied_at?, notes? }
async function handleCreatePosition(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  let { jd_id, company, position_title, status, applied_at, notes } = body;

  status = status || 'pending';
  if (!POSITION_STATUSES.includes(status)) return errResp(`invalid status: ${status}`);

  // 如果带 jd_id，自动从 JD 继承字段 + 去重防止同一 JD 重复加入看板
  if (jd_id) {
    const jd = await env.DB.prepare('SELECT * FROM jds WHERE id = ? AND user_id = ?')
      .bind(jd_id, user.id).first();
    if (!jd) return errResp('jd not found', 404);

    // 查是否已存在该 JD 对应的岗位
    const existed = await env.DB.prepare(
      'SELECT id FROM positions WHERE jd_id = ? AND user_id = ? LIMIT 1'
    ).bind(jd_id, user.id).first();
    if (existed) {
      return jsonResp({
        ok: false,
        code: 'already_exists',
        msg: '这个岗位已经在看板里了',
        position_id: existed.id,
      }, 409);
    }

    company = company || jd.company || '未知公司';
    position_title = position_title || jd.position_title || '未知岗位';
  }

  if (!company || !position_title) return errResp('company and position_title required');

  const id = genId('p');
  const ts = now();
  await env.DB.prepare(`
    INSERT INTO positions (id, user_id, jd_id, company, position_title, status,
                           applied_at, current_round, notes, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id, user.id, jd_id || null, company, position_title, status,
    applied_at || null, roundFromStatus(status), notes || null, ts, ts
  ).run();

  // 记一条状态历史
  await env.DB.prepare(`
    INSERT INTO position_status_history (id, position_id, from_status, to_status, changed_at)
    VALUES (?, ?, NULL, ?, ?)
  `).bind(genId('psh'), id, status, ts).run();

  return jsonResp({ ok: true, id });
}

// PUT /api/positions/:id —— 更新岗位（含状态流转）
// Body: { status?, company?, position_title?, applied_at?, notes? }
async function handleUpdatePosition(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  const position = await env.DB.prepare(
    'SELECT * FROM positions WHERE id = ? AND user_id = ?'
  ).bind(id, user.id).first();
  if (!position) return errResp('not found', 404);

  const updates = [];
  const bindings = [];
  let statusChanged = false;

  if (body.status && body.status !== position.status) {
    if (!POSITION_STATUSES.includes(body.status)) return errResp(`invalid status: ${body.status}`);
    updates.push('status = ?', 'current_round = ?');
    bindings.push(body.status, roundFromStatus(body.status));
    statusChanged = true;

    // 第一次从 pending 切到 applied，补个默认投递时间
    if (position.status === 'pending' && body.status === 'applied' && !position.applied_at) {
      updates.push('applied_at = ?');
      bindings.push(now());
    }
  }
  if (typeof body.company === 'string') { updates.push('company = ?'); bindings.push(body.company.trim()); }
  if (typeof body.position_title === 'string') { updates.push('position_title = ?'); bindings.push(body.position_title.trim()); }
  if (typeof body.applied_at === 'string' || body.applied_at === null) { updates.push('applied_at = ?'); bindings.push(body.applied_at); }
  if (typeof body.notes === 'string' || body.notes === null) { updates.push('notes = ?'); bindings.push(body.notes); }

  if (updates.length === 0) return jsonResp({ ok: true, unchanged: true });

  updates.push('updated_at = ?'); bindings.push(now());
  bindings.push(id);

  await env.DB.prepare(`UPDATE positions SET ${updates.join(', ')} WHERE id = ?`)
    .bind(...bindings).run();

  // 写状态变更历史
  if (statusChanged) {
    await env.DB.prepare(`
      INSERT INTO position_status_history (id, position_id, from_status, to_status, changed_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(genId('psh'), id, position.status, body.status, now()).run();

    // 进入面试阶段但还没录对应轮次，自动建一条
    const roundNum = roundFromStatus(body.status);
    if (roundNum > 0) {
      const existingRound = await env.DB.prepare(
        'SELECT id FROM interview_rounds WHERE position_id = ? AND round_number = ?'
      ).bind(id, roundNum).first();
      if (!existingRound) {
        await env.DB.prepare(`
          INSERT INTO interview_rounds (id, position_id, round_number, result, created_at)
          VALUES (?, ?, ?, 'pending', ?)
        `).bind(genId('rnd'), id, roundNum, now()).run();
      }
    }

    // 触发站内通知
    await createNotification(env, user.id, {
      type: 'status_change',
      title: `${position.company} · ${position.position_title} 状态更新`,
      content: `已从「${statusLabel(position.status)}」变更为「${statusLabel(body.status)}」`,
      link: `/position/${id}`,
    });
  }

  return jsonResp({ ok: true });
}

// DELETE /api/positions/:id
async function handleDeletePosition(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const res = await env.DB.prepare('DELETE FROM positions WHERE id = ? AND user_id = ?')
    .bind(id, user.id).run();
  return jsonResp({ ok: true, deleted: res.meta?.changes || 0 });
}

// 状态中文标签
function statusLabel(s) {
  const map = {
    pending: '待投递', applied: '已投递', written_test: '笔试中',
    interview_1: '一面', interview_2: '二面', interview_3plus: '三面及以上',
    offer: 'Offer', onboard: '已入职', rejected: '已拒绝', withdrawn: '主动放弃',
  };
  return map[s] || s;
}

// ==================== 面试轮次模块 ====================

// GET /api/positions/:pid/rounds
async function handleListRounds(request, env, pid) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const pos = await env.DB.prepare('SELECT id FROM positions WHERE id = ? AND user_id = ?')
    .bind(pid, user.id).first();
  if (!pos) return errResp('position not found', 404);

  const { results } = await env.DB.prepare(
    'SELECT * FROM interview_rounds WHERE position_id = ? ORDER BY round_number ASC'
  ).bind(pid).all();

  return jsonResp({ rounds: results || [] });
}

// POST /api/positions/:pid/rounds —— 新增一轮面试
// Body: { round_number?, round_type?, scheduled_at?, notes? }
async function handleCreateRound(request, env, pid) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const pos = await env.DB.prepare('SELECT id FROM positions WHERE id = ? AND user_id = ?')
    .bind(pid, user.id).first();
  if (!pos) return errResp('position not found', 404);

  const body = await readJson(request) || {};
  let round_number = body.round_number;
  if (!round_number) {
    const last = await env.DB.prepare(
      'SELECT MAX(round_number) AS m FROM interview_rounds WHERE position_id = ?'
    ).bind(pid).first();
    round_number = (last?.m || 0) + 1;
  }

  const id = genId('rnd');
  await env.DB.prepare(`
    INSERT INTO interview_rounds (id, position_id, round_number, round_type,
                                  scheduled_at, result, notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id, pid, round_number, body.round_type || null,
    body.scheduled_at || null, body.result || 'pending',
    body.notes || null, now()
  ).run();

  return jsonResp({ ok: true, id, round_number });
}

// PUT /api/rounds/:id
async function handleUpdateRound(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  // 验证该轮属于当前用户的岗位
  const row = await env.DB.prepare(`
    SELECT r.* FROM interview_rounds r
    JOIN positions p ON r.position_id = p.id
    WHERE r.id = ? AND p.user_id = ?
  `).bind(id, user.id).first();
  if (!row) return errResp('not found', 404);

  const body = await readJson(request) || {};
  const updates = [];
  const bindings = [];

  for (const [k, col] of [
    ['round_type', 'round_type'],
    ['scheduled_at', 'scheduled_at'],
    ['result', 'result'],
    ['notes', 'notes'],
  ]) {
    if (k in body) { updates.push(`${col} = ?`); bindings.push(body[k]); }
  }

  if (updates.length === 0) return jsonResp({ ok: true, unchanged: true });
  bindings.push(id);
  await env.DB.prepare(`UPDATE interview_rounds SET ${updates.join(', ')} WHERE id = ?`)
    .bind(...bindings).run();

  return jsonResp({ ok: true });
}

// DELETE /api/rounds/:id
async function handleDeleteRound(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const row = await env.DB.prepare(`
    SELECT r.id FROM interview_rounds r
    JOIN positions p ON r.position_id = p.id
    WHERE r.id = ? AND p.user_id = ?
  `).bind(id, user.id).first();
  if (!row) return errResp('not found', 404);

  await env.DB.prepare('DELETE FROM interview_rounds WHERE id = ?').bind(id).run();
  return jsonResp({ ok: true });
}

// ==================== 复盘模块 ====================

// GET /api/reviews —— 列出当前用户所有复盘
async function handleListReviews(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const { results } = await env.DB.prepare(`
    SELECT r.id, r.position_id, r.round_id, r.parse_status, r.created_at,
           p.company, p.position_title,
           substr(r.raw_text, 1, 200) AS preview
    FROM reviews r
    LEFT JOIN positions p ON r.position_id = p.id
    WHERE r.user_id = ?
    ORDER BY r.created_at DESC
  `).bind(user.id).all();

  return jsonResp({ reviews: results || [] });
}

// GET /api/reviews/:id
async function handleGetReview(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const row = await env.DB.prepare('SELECT * FROM reviews WHERE id = ? AND user_id = ?')
    .bind(id, user.id).first();
  if (!row) return errResp('not found', 404);

  return jsonResp({
    review: {
      ...row,
      parsed: row.parsed_json ? safeParseJson(row.parsed_json) : null,
      insights: row.ai_insights ? safeParseJson(row.ai_insights) : null,
    },
  });
}

// POST /api/reviews —— 粘贴复盘文本并分析
// Body: { position_id, round_id?, raw_text }
async function handleCreateReview(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  const position_id = body.position_id;
  const round_id = body.round_id || null;
  const raw_text = (body.raw_text || '').trim();

  if (!position_id) return errResp('position_id required');
  if (raw_text.length < 30) return errResp('复盘内容太短（至少30字）');
  if (raw_text.length > 30000) return errResp('复盘内容过长（最多30000字）');

  // 验证岗位归属
  const position = await env.DB.prepare(
    'SELECT * FROM positions WHERE id = ? AND user_id = ?'
  ).bind(position_id, user.id).first();
  if (!position) return errResp('position not found', 404);

  const id = genId('rv');
  const ts = now();
  await env.DB.prepare(`
    INSERT INTO reviews (id, user_id, position_id, round_id, raw_text, parse_status, created_at)
    VALUES (?, ?, ?, ?, ?, 'processing', ?)
  `).bind(id, user.id, position_id, round_id, raw_text, ts).run();

  try {
    // 先拉简历+JD+历史画像用于洞察
    const resume = await env.DB.prepare(
      "SELECT * FROM resumes WHERE user_id = ? AND is_primary = 1 AND parse_status = 'done' LIMIT 1"
    ).bind(user.id).first();
    const jd = position.jd_id
      ? await env.DB.prepare('SELECT * FROM jds WHERE id = ?').bind(position.jd_id).first()
      : null;
    const recentReviews = await env.DB.prepare(`
      SELECT id, created_at, substr(raw_text, 1, 500) AS preview, ai_insights
      FROM reviews WHERE user_id = ? AND id != ?
      ORDER BY created_at DESC LIMIT 5
    `).bind(user.id, id).all();

    // LLM 结构化 + 洞察
    const { parsed, insights } = await analyzeReview(env, {
      raw_text,
      position,
      resume,
      jd,
      recent_reviews: recentReviews.results || [],
    }, user);

    await env.DB.prepare(`
      UPDATE reviews SET parsed_json = ?, ai_insights = ?, parse_status = 'done' WHERE id = ?
    `).bind(JSON.stringify(parsed), JSON.stringify(insights), id).run();

    // 触发画像池更新（复盘产出的画像候选标签）
    if (insights?.tags_for_profile) {
      runBackground(env, updateProfileFromReview(env, id, insights.tags_for_profile, user));
    }

    // 如果绑定了某一轮，自动把 result 补成 pending_feedback（用户可再改）
    if (round_id) {
      await env.DB.prepare(
        "UPDATE interview_rounds SET result = COALESCE(NULLIF(result, 'pending'), 'pending_feedback') WHERE id = ?"
      ).bind(round_id).run();
    }

    return jsonResp({ ok: true, id, parsed, insights });
  } catch (e) {
    const quotaResp = handleQuotaError(e);
    if (quotaResp) {
      await env.DB.prepare('DELETE FROM reviews WHERE id = ?').bind(id).run();
      return quotaResp;
    }
    await env.DB.prepare(
      "UPDATE reviews SET parse_status = 'failed' WHERE id = ?"
    ).bind(id).run();
    return jsonResp({ ok: false, id, error: String(e.message || e) });
  }
}

// DELETE /api/reviews/:id
async function handleDeleteReview(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const res = await env.DB.prepare('DELETE FROM reviews WHERE id = ? AND user_id = ?')
    .bind(id, user.id).run();
  return jsonResp({ ok: true, deleted: res.meta?.changes || 0 });
}

// LLM: 复盘分析（结构化 + 画像级洞察）
async function analyzeReview(env, ctx, user) {
  const { raw_text, position, resume, jd, recent_reviews } = ctx;

  const resumeSummary = resume
    ? (resume.parsed_json ? JSON.stringify(safeParseJson(resume.parsed_json)).slice(0, 2000) : resume.raw_text.slice(0, 1500))
    : '（用户未上传简历）';
  const jdSummary = jd
    ? (jd.parsed_json ? JSON.stringify(safeParseJson(jd.parsed_json)).slice(0, 1500) : jd.raw_text.slice(0, 1500))
    : '（无关联JD）';

  // 历史复盘的洞察摘要（避免过长）
  const historySummary = (recent_reviews || []).slice(0, 5).map(r => {
    const insights = r.ai_insights ? safeParseJson(r.ai_insights) : null;
    return {
      date: r.created_at,
      key_findings: insights?.key_findings || null,
      weaknesses: insights?.weaknesses || null,
    };
  });

  const prompt = `你是一个资深求职面试教练。用户刚完成一次面试，粘贴了面试转录/回忆文本。请完成两件事：

任务 1：结构化提取（问-答对）
任务 2：基于用户简历 + JD + 历史复盘，给出个性化洞察

---

【岗位】${position.company} · ${position.position_title}（当前状态：${statusLabel(position.status)}）

【用户主简历】
${resumeSummary}

【目标岗位JD】
${jdSummary}

【用户历史复盘摘要（最近5次）】
${historySummary.length > 0 ? JSON.stringify(historySummary, null, 2) : '（这是首次复盘）'}

【本次复盘原文】
"""
${raw_text}
"""

---

只输出 JSON，结构如下：
{
  "parsed": {
    "qa_pairs": [
      {
        "question": "面试官问的原题",
        "user_answer": "用户当时的回答（精简）",
        "category": "自我介绍|简历深挖|业务场景|产品思维|技术能力|压力测试|行为问题|其他"
      }
    ],
    "interviewer_style": "面试官风格一句话（温和/压迫/技术挖深/快速转换等）",
    "overall_self_rating": 1-10的整数
  },
  "insights": {
    "key_findings": [
      "本次最关键的3-5个观察（要结合JD和简历具体分析，不要套话）"
    ],
    "strengths": ["本次表现不错的地方"],
    "weaknesses": ["本次暴露的短板，具体到某个回答"],
    "patterns_vs_history": "如果有历史复盘，指出是否重复出现同类问题；如是首次，写 null",
    "next_actions": ["针对性建议，可操作的3-5条"],
    "tags_for_profile": [
      {"tag":"画像标签候选，如'不善于量化成果'","layer":"behavior","confidence":0.7}
    ]
  }
}

要求：
1. key_findings / weaknesses 不要写"建议提升表达""需要多练"这种废话，必须具体到某个回答或问题
2. patterns_vs_history 要点名是哪次复盘、相似点在哪
3. tags_for_profile 是给画像池的候选标签（第三轮会接入），confidence 0-1，preference 选 stable(稳定事实)/skill(技能)/behavior(行为表现)/dynamic(临时)`;

  const { content } = await runLLMWithQuota(env, user, 'PRO', {
    messages: [
      { role: 'system', content: '你是坦诚、尖锐的求职面试教练。指出真实问题，不说"总体不错"这种废话。只输出JSON。' },
      { role: 'user', content: prompt },
    ],
    json: true,
    temperature: 0.4,
    purpose: 'review_analyze',
  });

  const data = safeParseJson(content);
  if (!data || !data.parsed || !data.insights) throw new Error('复盘分析返回格式异常');
  return data;
}

// ==================== 通知辅助函数 ====================
async function createNotification(env, userId, { type, title, content = null, link = null }) {
  // 检查偏好
  const pref = await env.DB.prepare(
    'SELECT * FROM notification_preferences WHERE user_id = ?'
  ).bind(userId).first();
  if (pref && pref[type] === 0) return; // 用户关闭了这类

  await env.DB.prepare(`
    INSERT INTO notifications (id, user_id, type, title, content, link, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(genId('n'), userId, type, title, content, link, now()).run();
}

// ==================== 通知模块 CRUD ====================

// GET /api/notifications —— 列出通知
async function handleListNotifications(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const url = new URL(request.url);
  const onlyUnread = url.searchParams.get('unread') === '1';
  const limit = Math.min(parseInt(url.searchParams.get('limit')) || 50, 200);

  let sql = 'SELECT * FROM notifications WHERE user_id = ?';
  const bindings = [user.id];
  if (onlyUnread) sql += ' AND read = 0';
  sql += ' ORDER BY created_at DESC LIMIT ?';
  bindings.push(limit);

  const { results } = await env.DB.prepare(sql).bind(...bindings).all();
  const unreadRow = await env.DB.prepare(
    'SELECT COUNT(*) AS c FROM notifications WHERE user_id = ? AND read = 0'
  ).bind(user.id).first();

  return jsonResp({
    notifications: results || [],
    unread_count: unreadRow?.c || 0,
  });
}

// POST /api/notifications/:id/read —— 标记某条已读
async function handleMarkNotifRead(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  await env.DB.prepare('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?')
    .bind(id, user.id).run();
  return jsonResp({ ok: true });
}

// POST /api/notifications/read-all —— 全部标记已读
async function handleMarkAllNotifRead(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  await env.DB.prepare('UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0')
    .bind(user.id).run();
  return jsonResp({ ok: true });
}

// DELETE /api/notifications/:id
async function handleDeleteNotif(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  await env.DB.prepare('DELETE FROM notifications WHERE id = ? AND user_id = ?')
    .bind(id, user.id).run();
  return jsonResp({ ok: true });
}

// GET /api/notifications/preferences
async function handleGetNotifPref(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  let pref = await env.DB.prepare(
    'SELECT * FROM notification_preferences WHERE user_id = ?'
  ).bind(user.id).first();

  if (!pref) {
    // 默认开启全部
    pref = {
      user_id: user.id,
      resume_stale: 1,
      review_missing: 1,
      status_change: 1,
      profile_insight: 1,
      suggestion: 1,
    };
  }
  return jsonResp({ preferences: pref });
}

// POST /api/notifications/preferences
async function handleSetNotifPref(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  const allowedKeys = ['resume_stale', 'review_missing', 'status_change', 'profile_insight', 'suggestion'];

  const existing = await env.DB.prepare(
    'SELECT user_id FROM notification_preferences WHERE user_id = ?'
  ).bind(user.id).first();

  if (!existing) {
    // INSERT with defaults then UPDATE
    await env.DB.prepare(`
      INSERT INTO notification_preferences (user_id, updated_at) VALUES (?, ?)
    `).bind(user.id, now()).run();
  }

  const updates = [];
  const bindings = [];
  for (const k of allowedKeys) {
    if (k in body) {
      updates.push(`${k} = ?`);
      bindings.push(body[k] ? 1 : 0);
    }
  }
  if (updates.length > 0) {
    updates.push('updated_at = ?');
    bindings.push(now());
    bindings.push(user.id);
    await env.DB.prepare(
      `UPDATE notification_preferences SET ${updates.join(', ')} WHERE user_id = ?`
    ).bind(...bindings).run();
  }
  return jsonResp({ ok: true });
}

// ==================== 画像池引擎（核心护城河）====================
// 分层：stable（稳定事实） / skill（技能标签） / behavior（行为画像） / dynamic（临时洞察）
// 每个标签带 category、confidence、status、证据锚点（profile_evidences 表）

const PROFILE_LAYERS = ['stable', 'skill', 'behavior', 'dynamic'];

// GET /api/profile —— 读取当前用户画像池（按层分组）
async function handleGetProfile(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const url = new URL(request.url);
  const layer = url.searchParams.get('layer');
  const showArchived = url.searchParams.get('include_archived') === '1';

  let sql = 'SELECT * FROM profile_tags WHERE user_id = ?';
  const bindings = [user.id];
  if (!showArchived) sql += " AND status = 'active'";
  if (layer && PROFILE_LAYERS.includes(layer)) {
    sql += ' AND layer = ?';
    bindings.push(layer);
  }
  sql += ' ORDER BY confidence DESC, last_updated_at DESC';

  const { results: tags } = await env.DB.prepare(sql).bind(...bindings).all();

  // 批量拉证据
  const tagIds = (tags || []).map(t => t.id);
  let evidencesByTag = {};
  if (tagIds.length > 0) {
    const placeholders = tagIds.map(() => '?').join(',');
    const { results: evs } = await env.DB.prepare(
      `SELECT * FROM profile_evidences WHERE tag_id IN (${placeholders}) ORDER BY created_at DESC`
    ).bind(...tagIds).all();
    for (const ev of evs || []) {
      if (!evidencesByTag[ev.tag_id]) evidencesByTag[ev.tag_id] = [];
      evidencesByTag[ev.tag_id].push(ev);
    }
  }

  // 按层分组返回
  const grouped = { stable: [], skill: [], behavior: [], dynamic: [] };
  for (const t of tags || []) {
    t.evidences = evidencesByTag[t.id] || [];
    if (grouped[t.layer]) grouped[t.layer].push(t);
  }

  // 最近一次自审
  const lastAudit = await env.DB.prepare(
    'SELECT * FROM profile_audits WHERE user_id = ? ORDER BY created_at DESC LIMIT 1'
  ).bind(user.id).first();

  return jsonResp({
    layers: grouped,
    total: (tags || []).length,
    last_audit: lastAudit || null,
  });
}

// DELETE /api/profile/tags/:id —— 用户手动删除（实际是标为 rejected）
async function handleRejectTag(request, env, tagId) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const tag = await env.DB.prepare(
    'SELECT * FROM profile_tags WHERE id = ? AND user_id = ?'
  ).bind(tagId, user.id).first();
  if (!tag) return errResp('not found', 404);

  await env.DB.prepare(
    "UPDATE profile_tags SET status = 'rejected', last_updated_at = ? WHERE id = ?"
  ).bind(now(), tagId).run();
  return jsonResp({ ok: true });
}

// PUT /api/profile/tags/:id —— 用户修正（改 key/confidence）
async function handleUpdateTag(request, env, tagId) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const tag = await env.DB.prepare(
    'SELECT id FROM profile_tags WHERE id = ? AND user_id = ?'
  ).bind(tagId, user.id).first();
  if (!tag) return errResp('not found', 404);

  const body = await readJson(request) || {};
  const updates = [];
  const bindings = [];
  if (typeof body.key === 'string') { updates.push('key = ?'); bindings.push(body.key.trim()); }
  if (typeof body.value === 'string' || body.value === null) { updates.push('value = ?'); bindings.push(body.value); }
  if (typeof body.confidence === 'number') {
    updates.push('confidence = ?');
    bindings.push(Math.max(0, Math.min(1, body.confidence)));
  }
  if (updates.length === 0) return jsonResp({ ok: true, unchanged: true });
  updates.push('last_updated_at = ?');
  bindings.push(now());
  bindings.push(tagId);
  await env.DB.prepare(`UPDATE profile_tags SET ${updates.join(', ')} WHERE id = ?`)
    .bind(...bindings).run();
  return jsonResp({ ok: true });
}

// 内部辅助：写入/合并画像标签 + 证据
// 如果同 layer + 同 key 已存在，则提升 confidence 并追加证据
async function upsertProfileTag(env, userId, { layer, category, key, value, confidence }, evidence) {
  if (!PROFILE_LAYERS.includes(layer)) layer = 'dynamic';
  const keyNorm = (key || '').trim().slice(0, 200);
  if (!keyNorm) return null;

  const existing = await env.DB.prepare(
    "SELECT * FROM profile_tags WHERE user_id = ? AND layer = ? AND key = ? AND status != 'rejected'"
  ).bind(userId, layer, keyNorm).first();

  let tagId;
  if (existing) {
    // 已存在：提升 confidence（加权平均，偏向新证据），更新 value
    const oldConf = existing.confidence || 0.5;
    const newConf = Math.min(1, oldConf * 0.7 + (confidence || 0.5) * 0.5);
    tagId = existing.id;
    await env.DB.prepare(`
      UPDATE profile_tags SET
        confidence = ?,
        value = COALESCE(?, value),
        status = 'active',
        last_updated_at = ?
      WHERE id = ?
    `).bind(newConf, value || null, now(), tagId).run();
  } else {
    tagId = genId('pt');
    await env.DB.prepare(`
      INSERT INTO profile_tags (id, user_id, layer, category, key, value, confidence, status, created_at, last_updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
    `).bind(
      tagId, userId, layer, category || 'other', keyNorm, value || null,
      Math.max(0, Math.min(1, confidence || 0.5)),
      now(), now()
    ).run();
  }

  if (evidence && evidence.source_type && evidence.quote) {
    await env.DB.prepare(`
      INSERT INTO profile_evidences (id, tag_id, source_type, source_id, quote, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      genId('pe'), tagId, evidence.source_type, evidence.source_id || '',
      evidence.quote.slice(0, 500), now()
    ).run();
  }

  return tagId;
}

// 从简历提取画像（Flash）
async function extractProfileFromResume(env, resume, user) {
  const parsed = resume.parsed_json ? safeParseJson(resume.parsed_json) : null;
  const content = parsed ? JSON.stringify(parsed).slice(0, 3500) : resume.raw_text.slice(0, 3000);

  const prompt = `从用户简历里提取**用于长期追踪的画像标签**。不要把每一行简历都做成标签，只提取真正有辨识度、能在未来面试建议里用到的信号。

【四层定义】
- stable（稳定事实，几乎不变）：姓名、学校、专业、毕业年份、核心身份（如"计算机硕士在读"）
- skill（技能标签，半年级）：具体技术/工具/方法（Python/用户调研/PRD写作）
- behavior（行为画像，月级）：工作风格/偏好/短板（如"喜欢做C端产品"、"项目量化不足"）
- dynamic（动态洞察，周级，现阶段从简历提不到）

【纪律】
- 每个标签必须有证据（原文片段）。没证据不要瞎编。
- 技能要判断"真用过"还是"只了解"：简历明确写了项目使用场景 confidence≈0.85，只列在技能栏 confidence≈0.55
- 不要拍马屁造能力。没证据的能力不写进 skill，可以写进 dynamic 标"候补"

【简历内容】
${content}

只输出 JSON：
{
  "tags": [
    {
      "layer": "stable|skill|behavior|dynamic",
      "category": "identity|skill|experience|preference|weakness|strength",
      "key": "标签名（如'精通Python'/'C端产品偏好'/'量化成果不足'）",
      "value": "可选：细节或数字",
      "confidence": 0.0-1.0的小数,
      "quote": "简历里支撑这个标签的原文片段（30字内）"
    }
  ]
}`;

  const { content: resp } = await runLLMWithQuota(env, user, 'FAST', {
    messages: [
      { role: 'system', content: '你是严谨的画像提取助手，只输出JSON，不拍马屁。' },
      { role: 'user', content: prompt },
    ],
    json: true,
    temperature: 0.3,
    purpose: 'profile_from_resume',
  });

  return safeParseJson(resp);
}

// 从 JD 偏好提取画像（Flash）
async function extractProfileFromJD(env, jdParsed, user) {
  const prompt = `用户又粘贴了一个目标 JD。分析这个岗位反映出用户什么**求职偏好**。

规则：
- 只看"用户主动选择投这个岗位"这一行为本身反映的偏好
- 偏好标签要抽象一点，不要把具体公司名写进来（公司是一次性的，不代表长期偏好）
- 每次 JD 只提 1-3 个画像标签，够用即可

JD 摘要：
${JSON.stringify(jdParsed).slice(0, 1500)}

输出：
{
  "tags": [
    {
      "layer": "behavior",
      "category": "preference",
      "key": "目标岗位偏好（如'偏好B端产品'/'偏好AI应用方向'/'目标一线城市'）",
      "value": "备注",
      "confidence": 0.0-1.0,
      "quote": "JD里反映这个偏好的关键句"
    }
  ]
}

只输出 JSON。`;

  const { content: resp } = await runLLMWithQuota(env, user, 'FAST', {
    messages: [
      { role: 'system', content: '你是严谨的画像提取助手，只输出JSON。' },
      { role: 'user', content: prompt },
    ],
    json: true,
    temperature: 0.3,
    purpose: 'profile_from_jd',
  });

  return safeParseJson(resp);
}

// 触发：简历更新后 → 画像池写入
async function updateProfileFromResume(env, resume, user) {
  try {
    const data = await extractProfileFromResume(env, resume, user);
    const tags = data?.tags || [];
    for (const t of tags) {
      await upsertProfileTag(env, user.id, t, {
        source_type: 'resume',
        source_id: resume.id,
        quote: t.quote || '',
      });
    }
    return { ok: true, tags_added: tags.length };
  } catch (e) {
    return { ok: false, error: String(e.message || e) };
  }
}

// 触发：JD 创建后 → 画像池写入
async function updateProfileFromJD(env, jdId, jdParsed, user) {
  try {
    const data = await extractProfileFromJD(env, jdParsed, user);
    const tags = data?.tags || [];
    for (const t of tags) {
      await upsertProfileTag(env, user.id, t, {
        source_type: 'jd',
        source_id: jdId,
        quote: t.quote || '',
      });
    }
    return { ok: true, tags_added: tags.length };
  } catch (e) {
    return { ok: false, error: String(e.message || e) };
  }
}

// 触发：复盘分析完成 → 画像池写入（用 analyzeReview 已经输出的 tags_for_profile）
async function updateProfileFromReview(env, reviewId, insightsTagsForProfile, user) {
  try {
    const tags = insightsTagsForProfile || [];
    for (const t of tags) {
      await upsertProfileTag(env, user.id, {
        layer: t.layer || 'behavior',
        category: t.category || 'weakness',
        key: t.tag || t.key,
        value: t.value,
        confidence: t.confidence || 0.6,
      }, {
        source_type: 'review',
        source_id: reviewId,
        quote: t.quote || '',
      });
    }
    return { ok: true, tags_added: tags.length };
  } catch (e) {
    return { ok: false, error: String(e.message || e) };
  }
}

// POST /api/profile/audit —— 画像池自审（手动触发版；Cron 版在第四轮）
async function handleProfileAudit(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const result = await runProfileAudit(env, user);
  return jsonResp(result);
}

// 画像自审核心：找矛盾、归档长时间未用 + 低置信度的标签
async function runProfileAudit(env, user) {
  // 拉所有活跃标签
  const { results: tags } = await env.DB.prepare(
    "SELECT * FROM profile_tags WHERE user_id = ? AND status = 'active'"
  ).bind(user.id).all();

  if (!tags || tags.length === 0) {
    return { ok: true, message: '画像为空，无需自审', tags_archived: 0, conflicts: [] };
  }

  // 规则 1：归档低置信度 + 长期未引用的标签（>30天）
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString();
  let archivedCount = 0;
  for (const t of tags) {
    const lastUsed = t.last_used_at || t.last_updated_at;
    if (t.confidence < 0.4 && lastUsed < thirtyDaysAgo) {
      await env.DB.prepare(
        "UPDATE profile_tags SET status = 'archived', last_updated_at = ? WHERE id = ?"
      ).bind(now(), t.id).run();
      archivedCount++;
    }
  }

  // 规则 2：用 LLM 找矛盾标签
  let conflicts = [];
  const activeTags = tags.filter(t => t.confidence >= 0.4);
  if (activeTags.length >= 4) {
    try {
      const summary = activeTags.map(t => `[${t.layer}] ${t.key}（置信度${t.confidence.toFixed(2)}）`).join('\n');
      const prompt = `用户的画像标签如下，找出明显矛盾/重复/过时的组合。

${summary}

输出 JSON（最多 5 条）：
{
  "conflicts": [
    {
      "tag_keys": ["标签A的key", "标签B的key"],
      "reason": "为什么矛盾（30字内）",
      "suggestion": "建议保留哪个/归档哪个"
    }
  ]
}

如果没发现矛盾，输出 { "conflicts": [] }。`;
      const { content } = await runLLMWithQuota(env, user, 'PRO', {
        messages: [
          { role: 'system', content: '你是画像审查专家，只输出JSON。' },
          { role: 'user', content: prompt },
        ],
        json: true,
        temperature: 0.3,
        purpose: 'profile_audit',
      });
      const data = safeParseJson(content);
      conflicts = data?.conflicts || [];
    } catch (e) {
      // 自审失败不影响主流程
    }
  }

  // 写一条自审日志
  await env.DB.prepare(`
    INSERT INTO profile_audits (id, user_id, audit_type, conflicts_found, tags_archived, report, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(
    genId('pa'), user.id, 'triggered',
    conflicts.length, archivedCount,
    JSON.stringify({ conflicts, archived_count: archivedCount }),
    now()
  ).run();

  // 如果发现矛盾，给用户发通知
  if (conflicts.length > 0) {
    await createNotification(env, user.id, {
      type: 'profile_insight',
      title: `画像自审发现 ${conflicts.length} 处可疑点`,
      content: '点击查看并确认修正',
      link: '/profile',
    });
  }

  return { ok: true, tags_archived: archivedCount, conflicts };
}

// ==================== 陪练题生成 ====================

// POST /api/practice/generate —— 基于岗位生成陪练题
// Body: { position_id, sources?: ['resume_dig','web_search','user'], count?: 5 }
async function handleGeneratePractice(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  if (!body.position_id) return errResp('position_id required');

  const position = await env.DB.prepare(
    'SELECT * FROM positions WHERE id = ? AND user_id = ?'
  ).bind(body.position_id, user.id).first();
  if (!position) return errResp('position not found', 404);

  const sources = body.sources || ['resume_dig', 'web_search'];
  const count = Math.max(3, Math.min(15, body.count || 8));

  const resume = await env.DB.prepare(
    "SELECT * FROM resumes WHERE user_id = ? AND is_primary = 1 AND parse_status = 'done' LIMIT 1"
  ).bind(user.id).first();
  const jd = position.jd_id
    ? await env.DB.prepare('SELECT * FROM jds WHERE id = ?').bind(position.jd_id).first()
    : null;

  const generated = [];

  // 来源 1：基于简历深挖（LLM，Flash）
  if (sources.includes('resume_dig') && resume) {
    try {
      const questions = await generateQuestionsFromResume(env, {
        resume, jd, position, count: Math.ceil(count * 0.6),
      }, user);
      for (const q of questions) {
        const id = genId('pq');
        await env.DB.prepare(`
          INSERT INTO practice_questions (id, user_id, position_id, question, reference_answer, source, source_detail, created_at)
          VALUES (?, ?, ?, ?, ?, 'llm_resume_dig', ?, ?)
        `).bind(
          id, user.id, position.id, q.question, q.reference_answer || null,
          JSON.stringify({ category: q.category, difficulty: q.difficulty }),
          now()
        ).run();
        generated.push({ id, ...q, source: 'llm_resume_dig' });
      }
    } catch (e) {
      if (e?.quotaCheck) return handleQuotaError(e);
    }
  }

  // 来源 2：百度搜索真实面经
  if (sources.includes('web_search')) {
    try {
      const webQs = await searchBaiduQuestions(env, {
        company: position.company,
        position_title: position.position_title,
        count: Math.ceil(count * 0.4),
        user,
      });
      for (const q of webQs) {
        const id = genId('pq');
        await env.DB.prepare(`
          INSERT INTO practice_questions (id, user_id, position_id, question, reference_answer, source, source_detail, created_at)
          VALUES (?, ?, ?, ?, NULL, 'web_search', ?, ?)
        `).bind(
          id, user.id, position.id, q.question,
          JSON.stringify({ source_url: q.url, source_title: q.title }),
          now()
        ).run();
        generated.push({ id, question: q.question, source: 'web_search', source_url: q.url });
      }
    } catch (e) {
      console.error('Baidu search:', e.message);
    }
  }

  return jsonResp({ ok: true, count: generated.length, questions: generated });
}

// LLM: 基于简历深挖题目
async function generateQuestionsFromResume(env, ctx, user) {
  const { resume, jd, position, count } = ctx;
  const resumeParsed = resume.parsed_json ? safeParseJson(resume.parsed_json) : null;

  const prompt = `你是一位严格的面试官。请基于用户简历和目标岗位，设计 ${count} 道**深挖型面试题**。

【核心原则】
- **不要出套路题**（"请自我介绍""你的优缺点"这种禁止出现）
- 每道题必须针对简历里的某个具体经历/项目，或目标岗位的具体要求
- 难度覆盖：3 道基础追问 + 2 道压力挑战 + 1 道业务场景
- 参考答案要具体到"应该提什么数据/讲什么故事"，不要"建议突出STAR"这种废话

【简历】${resumeParsed ? JSON.stringify(resumeParsed).slice(0, 2000) : resume.raw_text.slice(0, 2000)}

【目标岗位】${position.company} · ${position.position_title}
${jd ? '【JD】' + (jd.parsed_json ? JSON.stringify(safeParseJson(jd.parsed_json)).slice(0, 1200) : jd.raw_text.slice(0, 1200)) : ''}

只输出 JSON：
{
  "questions": [
    {
      "question": "具体问题",
      "category": "简历深挖|业务场景|压力测试|产品思维|技术能力",
      "difficulty": 1-5,
      "reference_answer": "参考答题要点（不是标准答案，是'你应该提到哪些具体细节'）"
    }
  ]
}`;

  const { content } = await runLLMWithQuota(env, user, 'FAST', {
    messages: [
      { role: 'system', content: '你是严格、不讨好的面试官，只出深挖题，拒绝套路题。只输出JSON。' },
      { role: 'user', content: prompt },
    ],
    json: true,
    temperature: 0.7,
    purpose: 'practice_generate',
  });

  const data = safeParseJson(content);
  return data?.questions || [];
}

// 百度搜索面经 v3.2（替换 Tavily）
async function searchBaiduQuestions(env, { company, position_title, count, user }) {
  const baiduKey = await getSecret(env.BAIDU_API_KEY);
  if (!baiduKey) return [];

  // 构建搜索 query，控制在 72 字符内（百度 API 限制，中文占 2 字符）
  const suffix = ' 面试 面经';
  let q = `${company} ${position_title}${suffix}`;
  if (q.length > 72) {
    // 截断：优先保留 company + 面试面经，再尽量塞 position_title
    const maxQuery = 72 - suffix.length;
    q = `${company.slice(0, Math.max(4, maxQuery - 4))} ${position_title.slice(0, Math.max(2, maxQuery - company.length))}${suffix}`;
    if (q.length > 72) q = q.slice(0, 72);
  }

  const preferredDomains = ['nowcoder.com', 'xiaohongshu.com', 'zhihu.com'];

  async function doSearch(domains) {
    const body = {
      messages: [{ role: 'user', content: q }],
      search_source: 'baidu_search_v2',
      edition: 'lite',
      resource_type_filter: [{ type: 'web', top_k: 8 }],
    };
    if (domains) body.search_filter = { match: { site: domains } };

    const resp = await fetch('https://qianfan.baidubce.com/v2/ai_search/web_search', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${baiduKey}`,
      },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      const txt = await resp.text();
      console.error('Baidu search error:', resp.status, txt.slice(0, 200));
      return [];
    }
    const data = await resp.json();
    return data.references || [];
  }

  // 第一轮：限定牛客/小红书/知乎
  let results = await doSearch(preferredDomains);

  // 垂直社区搜到的太少，退回通用搜索兜底
  if (results.length < 3) {
    const fallback = await doSearch(null);
    const seen = new Set(results.map(r => r.url));
    for (const r of fallback) {
      if (!seen.has(r.url)) { results.push(r); seen.add(r.url); }
    }
  }

  if (results.length === 0) return [];

  // 拼素材让 LLM 精炼
  const corpus = results.slice(0, 6).map((r, i) =>
    `【来源${i + 1}】${r.title || '无标题'}\nURL: ${r.url || ''}\n内容: ${(r.content || r.snippet || '').slice(0, 400)}`
  ).join('\n\n');

  const want = Math.max(2, count);
  const prompt = `以下是从网上（优先牛客/小红书/知乎）搜到的关于"${company} · ${position_title}"岗位的面经素材（可能包含网页导航、广告、非面试内容）。

${corpus}

请严格筛选，提取出 ${want} 条**真实具体的面试题**，要求：
1. 必须是明确的面试问题（可以是行为问题/专业问题/案例题），不是网页导航/标题党/广告/文章引言
2. 题目必须**自带完整上下文**，脱离原文也能看懂
3. 题目长度 15-150 字，不要太短也不要超长
4. 避免重复或高度相似的题目
5. 如果素材里没有足够像样的题目，宁可少给，也不要凑数

输出 JSON：
{
  "questions": [
    {
      "question": "具体的面试问题",
      "source_index": 1,
      "topic": "行为面|专业面|案例分析|其他"
    }
  ]
}

如果素材完全无效，输出 {"questions": []}。`;

  let picked = [];
  try {
    const { content } = await runLLMWithQuota(env, user, 'FAST', {
      messages: [
        { role: 'system', content: '你是资深面试官，擅长从杂乱文本中甄别出真正的面试题。只输出 JSON。' },
        { role: 'user', content: prompt },
      ],
      json: true,
      temperature: 0.2,
      purpose: 'web_search_refine',
    });
    const parsed = safeParseJson(content);
    picked = (parsed?.questions || []).filter(q =>
      q.question && q.question.length >= 15 && q.question.length <= 200
    );
  } catch (e) {
    console.error('Baidu LLM refine failed:', e.message);
    return [];
  }

  return picked.slice(0, count).map(q => {
    const src = results[(q.source_index || 1) - 1] || results[0] || {};
    return {
      question: q.question.trim(),
      url: src.url || '',
      title: src.title || '',
      topic: q.topic || null,
    };
  });
}

// GET /api/practice —— 列出陪练题
async function handleListPractice(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const url = new URL(request.url);
  const positionId = url.searchParams.get('position_id');

  let sql = 'SELECT * FROM practice_questions WHERE user_id = ?';
  const bindings = [user.id];
  if (positionId) { sql += ' AND position_id = ?'; bindings.push(positionId); }
  sql += ' ORDER BY created_at DESC LIMIT 200';

  const { results } = await env.DB.prepare(sql).bind(...bindings).all();
  for (const q of results || []) {
    if (q.source_detail) q.source_detail = safeParseJson(q.source_detail);
  }
  return jsonResp({ questions: results || [] });
}

// POST /api/practice/user-paste —— 用户粘贴题目入库（个人面经）
// Body: { position_id?, question, reference_answer? }
async function handlePastePractice(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  const question = (body.question || '').trim();
  if (question.length < 5) return errResp('题目太短');

  const id = genId('pq');
  await env.DB.prepare(`
    INSERT INTO practice_questions (id, user_id, position_id, question, reference_answer, user_note, source, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 'user_pasted', ?)
  `).bind(
    id, user.id, body.position_id || null,
    question, body.reference_answer || null, body.user_note || null, now()
  ).run();

  return jsonResp({ ok: true, id });
}

// PUT /api/practice/:id —— 更新（笔记/参考答案）
async function handleUpdatePractice(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const q = await env.DB.prepare(
    'SELECT id FROM practice_questions WHERE id = ? AND user_id = ?'
  ).bind(id, user.id).first();
  if (!q) return errResp('not found', 404);

  const body = await readJson(request) || {};
  const updates = [];
  const bindings = [];
  for (const k of ['question', 'reference_answer', 'user_note']) {
    if (k in body) { updates.push(`${k} = ?`); bindings.push(body[k]); }
  }
  if (updates.length === 0) return jsonResp({ ok: true, unchanged: true });
  bindings.push(id);
  await env.DB.prepare(`UPDATE practice_questions SET ${updates.join(', ')} WHERE id = ?`)
    .bind(...bindings).run();
  return jsonResp({ ok: true });
}

// DELETE /api/practice/:id
async function handleDeletePractice(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  await env.DB.prepare('DELETE FROM practice_questions WHERE id = ? AND user_id = ?')
    .bind(id, user.id).run();
  return jsonResp({ ok: true });
}

// ==================== 岗位建议 ====================

// POST /api/suggestions/generate —— 基于画像生成建议
async function handleGenerateSuggestions(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  // 拉画像池（活跃）
  const { results: tags } = await env.DB.prepare(
    "SELECT * FROM profile_tags WHERE user_id = ? AND status = 'active' ORDER BY confidence DESC LIMIT 30"
  ).bind(user.id).all();

  if (!tags || tags.length < 3) {
    return errResp('画像数据不足，请先粘贴简历和 2-3 个 JD', 400);
  }

  // 最近岗位动态
  const { results: recentPositions } = await env.DB.prepare(
    'SELECT company, position_title, status FROM positions WHERE user_id = ? ORDER BY updated_at DESC LIMIT 10'
  ).bind(user.id).all();

  const prompt = `你是一位资深求职导师。基于用户画像和近期岗位动态，给出 3-5 条**具体可操作**的建议。

【用户画像】
${tags.map(t => `[${t.layer}] ${t.key} (conf=${t.confidence.toFixed(2)})`).join('\n')}

【近期岗位】
${recentPositions.map(p => `${p.company} · ${p.position_title} (${statusLabel(p.status)})`).join('\n')}

【建议类型】
- direction（方向建议）：你现在的画像适合/不适合哪类岗位
- skill_gap（能力补齐）：离目标岗位还缺什么，怎么补
- next_action（下一步行动）：明天/这周具体做什么

【纪律】
- 不要"加油""继续努力"这种废话
- 每条必须具体到"做什么"
- 引用画像里的证据（如"你画像里有'量化成果不足'，建议..."）

只输出 JSON：
{
  "suggestions": [
    {
      "suggestion_type": "direction|skill_gap|next_action",
      "title": "标题（15字内）",
      "content": "详细建议（150字内，具体可执行）",
      "based_on": ["引用的画像标签 key 数组"]
    }
  ]
}`;

  try {
    const { content } = await runLLMWithQuota(env, user, 'PRO', {
      messages: [
        { role: 'system', content: '你是严格、具体的求职导师。只输出JSON。' },
        { role: 'user', content: prompt },
      ],
      json: true,
      temperature: 0.5,
      purpose: 'suggestion_generate',
    });

    const data = safeParseJson(content);
    const suggestions = data?.suggestions || [];

    // 写入数据库
    const saved = [];
    for (const s of suggestions) {
      const id = genId('sg');
      await env.DB.prepare(`
        INSERT INTO position_suggestions (id, user_id, suggestion_type, title, content, based_on, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'new', ?)
      `).bind(
        id, user.id,
        s.suggestion_type || 'next_action',
        s.title || '',
        s.content || '',
        JSON.stringify(s.based_on || []),
        now()
      ).run();
      saved.push({ id, ...s });
    }

    // 发通知
    if (saved.length > 0) {
      await createNotification(env, user.id, {
        type: 'suggestion',
        title: `AI 为你生成了 ${saved.length} 条新建议`,
        content: '点击查看',
        link: '/suggestions',
      });
    }

    return jsonResp({ ok: true, count: saved.length, suggestions: saved });
  } catch (e) {
    const quotaResp = handleQuotaError(e);
    if (quotaResp) return quotaResp;
    throw e;
  }
}

// GET /api/suggestions
async function handleListSuggestions(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const url = new URL(request.url);
  const onlyNew = url.searchParams.get('new') === '1';

  let sql = 'SELECT * FROM position_suggestions WHERE user_id = ?';
  const bindings = [user.id];
  if (onlyNew) sql += " AND status = 'new'";
  sql += ' ORDER BY created_at DESC LIMIT 50';

  const { results } = await env.DB.prepare(sql).bind(...bindings).all();
  for (const s of results || []) {
    if (s.based_on) s.based_on = safeParseJson(s.based_on);
  }
  return jsonResp({ suggestions: results || [] });
}

// PUT /api/suggestions/:id —— 更新状态（viewed/adopted/dismissed）
async function handleUpdateSuggestion(request, env, id) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  const status = body.status;
  if (!['viewed', 'adopted', 'dismissed'].includes(status)) {
    return errResp('invalid status');
  }

  await env.DB.prepare(
    'UPDATE position_suggestions SET status = ? WHERE id = ? AND user_id = ?'
  ).bind(status, id, user.id).run();

  return jsonResp({ ok: true });
}

// ==================== 配额系统 ====================
// 全局配额配置（后续可移到管理员面板动态调整）
const DAILY_QUOTA = {
  FAST: 50,   // Flash 每日限额
  PRO: 5,     // Pro 每日限额
};

function todayDate() {
  // UTC+8 日期切换（用户在中国）
  const d = new Date(Date.now() + 8 * 3600 * 1000);
  return d.toISOString().slice(0, 10);
}

// 查询用户今日配额使用情况
async function getTodayQuota(env, userId) {
  const row = await env.DB.prepare(
    'SELECT * FROM usage_quota WHERE user_id = ? AND date = ?'
  ).bind(userId, todayDate()).first();
  return row || { user_id: userId, date: todayDate(), flash_used: 0, pro_used: 0, using_own_key: 0 };
}

// 检查配额 + 获取调用用的 API Key（BYOK 优先）
// 返回 { allow: true, apiKey, useOwnKey } 或 { allow: false, reason, quota }
async function checkQuotaAndKey(env, user, modelTier) {
  const ownKey = user.own_api_key?.trim();
  if (ownKey) {
    // 用户自己的 Key → 跳过配额，记录使用
    return { allow: true, apiKey: ownKey, useOwnKey: true };
  }

  const quota = await getTodayQuota(env, user.id);
  const used = modelTier === 'PRO' ? quota.pro_used : quota.flash_used;
  const limit = modelTier === 'PRO' ? DAILY_QUOTA.PRO : DAILY_QUOTA.FAST;

  if (used >= limit) {
    return {
      allow: false,
      reason: 'quota_exceeded',
      quota: { ...quota, flash_limit: DAILY_QUOTA.FAST, pro_limit: DAILY_QUOTA.PRO },
      tier: modelTier,
    };
  }

  const apiKey = await getSecret(env.DEEPSEEK_API_KEY);
  return { allow: true, apiKey, useOwnKey: false };
}

// 增加配额计数
async function incrementQuota(env, userId, modelTier, usingOwnKey = false) {
  const date = todayDate();
  const col = modelTier === 'PRO' ? 'pro_used' : 'flash_used';
  await env.DB.prepare(`
    INSERT INTO usage_quota (user_id, date, flash_used, pro_used, using_own_key, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, date) DO UPDATE SET
      ${col} = ${col} + 1,
      using_own_key = CASE WHEN ? = 1 THEN 1 ELSE using_own_key END,
      updated_at = ?
  `).bind(
    userId, date,
    modelTier === 'PRO' ? 0 : 1,
    modelTier === 'PRO' ? 1 : 0,
    usingOwnKey ? 1 : 0,
    now(),
    usingOwnKey ? 1 : 0,
    now()
  ).run();
}

// 配额超限统一响应
function quotaExceededResp(check) {
  return jsonResp({
    error: 'quota_exceeded',
    message: check.tier === 'PRO'
      ? `今日 AI 深度分析额度（${DAILY_QUOTA.PRO}次）已用完`
      : `今日 AI 快速任务额度（${DAILY_QUOTA.FAST}次）已用完`,
    tier: check.tier,
    quota: check.quota,
    suggestion: {
      title: '想立即继续使用？',
      options: [
        { label: '明天再来（免费）', action: 'wait' },
        { label: '填入自己的 DeepSeek API Key（无限使用）', action: 'byok' },
      ],
    },
  }, 429);
}

// 高层辅助：检查配额 → 调 LLM → 计数。业务层统一用这个
// 如果配额超限，抛出带 quotaCheck 的错误，路由层捕获后返回 quotaExceededResp
async function runLLMWithQuota(env, user, modelTier, llmOpts) {
  const check = await checkQuotaAndKey(env, user, modelTier);
  if (!check.allow) {
    const err = new Error('quota_exceeded');
    err.quotaCheck = check;
    throw err;
  }

  const result = await callLLM(env, {
    ...llmOpts,
    model: modelTier,
    userId: user.id,
    apiKey: check.apiKey,
  });

  // 调用成功后计数（失败不计）
  try {
    await incrementQuota(env, user.id, modelTier, check.useOwnKey);
  } catch (_) { /* 记账失败不影响主流程 */ }

  return result;
}

// 业务层捕获配额异常的辅助
function handleQuotaError(e) {
  if (e?.quotaCheck) return quotaExceededResp(e.quotaCheck);
  return null;
}

// GET /api/me/quota —— 前端查当前用户今日配额
async function handleGetQuota(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const quota = await getTodayQuota(env, user.id);
  return jsonResp({
    date: quota.date,
    flash: { used: quota.flash_used, limit: DAILY_QUOTA.FAST },
    pro: { used: quota.pro_used, limit: DAILY_QUOTA.PRO },
    using_own_key: !!user.own_api_key,
  });
}

// POST /api/me/byok —— 保存/清除用户自己的 API Key
async function handleSetBYOK(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  const key = typeof body.api_key === 'string' ? body.api_key.trim() : null;

  if (key && !/^sk-[\w-]{10,}$/.test(key)) {
    return errResp('看起来不是合法的 DeepSeek API Key（应以 sk- 开头）');
  }

  await env.DB.prepare('UPDATE users SET own_api_key = ? WHERE id = ?')
    .bind(key || null, user.id).run();

  return jsonResp({ ok: true, has_key: !!key });
}

// POST /api/me/reset —— 重置账号（清除所有数据，回到 onboarding）
async function handleResetMe(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return error;
  const db = env.DB;
  const uid = user.id;

  // 按依赖顺序删除：先删子表，再删主表
  // profile_evidences 依赖 profile_tags
  await db.prepare(
    `DELETE FROM profile_evidences WHERE tag_id IN (SELECT id FROM profile_tags WHERE user_id = ?)`
  ).bind(uid).run();
  await db.prepare(`DELETE FROM profile_tags WHERE user_id = ?`).bind(uid).run();
  await db.prepare(`DELETE FROM profile_audits WHERE user_id = ?`).bind(uid).run();

  // position_status_history / interview_rounds 依赖 positions
  await db.prepare(
    `DELETE FROM position_status_history WHERE position_id IN (SELECT id FROM positions WHERE user_id = ?)`
  ).bind(uid).run();
  await db.prepare(
    `DELETE FROM interview_rounds WHERE position_id IN (SELECT id FROM positions WHERE user_id = ?)`
  ).bind(uid).run();

  await db.prepare(`DELETE FROM resumes WHERE user_id = ?`).bind(uid).run();
  await db.prepare(`DELETE FROM jds WHERE user_id = ?`).bind(uid).run();
  await db.prepare(`DELETE FROM positions WHERE user_id = ?`).bind(uid).run();
  await db.prepare(`DELETE FROM practice_questions WHERE user_id = ?`).bind(uid).run();
  await db.prepare(`DELETE FROM reviews WHERE user_id = ?`).bind(uid).run();
  await db.prepare(`DELETE FROM position_suggestions WHERE user_id = ?`).bind(uid).run();
  await db.prepare(`DELETE FROM notifications WHERE user_id = ?`).bind(uid).run();
  await db.prepare(`DELETE FROM notification_preferences WHERE user_id = ?`).bind(uid).run();
  await db.prepare(`DELETE FROM llm_call_logs WHERE user_id = ?`).bind(uid).run();
  await db.prepare(`DELETE FROM usage_quota WHERE user_id = ?`).bind(uid).run();

  // 重置 onboarded 状态，让用户重新走引导
  await db.prepare(`UPDATE users SET onboarded = 0 WHERE id = ?`).bind(uid).run();

  return jsonResp({ ok: true });
}

// ==================== 匹配打分：粗分（Flash）====================
// 6档颜色映射，绿色细分 + 柔和弱化，避免刺眼
// band: 'excellent' | 'great' | 'good' | 'fair' | 'low' | 'poor'
function scoreToBand(score) {
  if (score >= 88) return 'excellent'; // 深绿  极高匹配
  if (score >= 78) return 'great';     // 绿    高匹配
  if (score >= 68) return 'good';      // 浅绿  中高匹配
  if (score >= 55) return 'fair';      // 米黄  中等
  if (score >= 40) return 'low';       // 灰    偏低
  return 'poor';                        // 浅灰  不匹配
}

// 粗分用 Flash，只做关键词级匹配，便宜 + 快
async function computeQuickMatch(env, resume, jd, user) {
  const resumeParsed = resume.parsed_json ? safeParseJson(resume.parsed_json) : null;
  const jdParsed = jd.parsed_json ? safeParseJson(jd.parsed_json) : null;

  const resumeText = resumeParsed
    ? JSON.stringify({
        skills: resumeParsed.skills,
        experiences: resumeParsed.experiences?.map(e => ({ role: e.role, description: e.description })),
        projects: resumeParsed.projects?.map(p => ({ name: p.name, tech_stack: p.tech_stack })),
      }).slice(0, 1500)
    : resume.raw_text.slice(0, 1500);

  const jdText = jdParsed
    ? JSON.stringify({
        requirements: jdParsed.requirements,
        tech_stack: jdParsed.tech_stack,
        preferred: jdParsed.preferred,
      }).slice(0, 1200)
    : jd.raw_text.slice(0, 1200);

  const prompt = `你是一位严苛的招聘评审官。请客观评估候选人简历与JD的契合度，不要讨好候选人。

【评分锚点（必须严格遵守）】
- 95-100：几乎是量身定制，JD核心要求全部命中 + 有亮点加分项
- 85-94：强匹配，核心要求 80%+ 命中，缺1-2个次要能力
- 75-84：较强匹配，核心要求一半以上命中，主干能力达标
- 65-74：中等匹配，有部分重合但缺核心能力
- 50-64：偏弱匹配，只有零星相关，主要能力缺失
- 30-49：基本不匹配，仅表面词汇重合
- 0-29：完全不对口

【评分纪律】
- 学生常见短板（无相关实习、项目规模小、技能只提不证）必须扣分
- 简历里没明确写的能力，不能假设"大概有"
- 校招/实习岗如果JD要求3年经验等，是结构性短板，必须扣到 60 以下
- 技能只是"了解"而非"使用过"，按只写50%能力计算

【简历关键信息】${resumeText}

【JD核心要求】${jdText}

只输出 JSON：
{
  "score": 严格评分（0-100整数）,
  "matched_keywords": ["JD要求里简历确实写过的（最多5个）"],
  "missing_keywords": ["JD要求里简历缺或没证据的（最多5个）"],
  "summary": "一句话客观评价（30字内，不要拍马屁，如果匹配度低就直接说）"
}`;

  const { content } = await runLLMWithQuota(env, user, 'FAST', {
    messages: [
      { role: 'system', content: '你是严苛的招聘评审官，客观评估，不讨好候选人。只输出JSON。' },
      { role: 'user', content: prompt },
    ],
    json: true,
    temperature: 0.2,
    purpose: 'match_quick',
  });

  const parsed = safeParseJson(content);
  if (!parsed) throw new Error('粗匹配解析失败');
  parsed.score = Math.max(0, Math.min(100, Math.round(parsed.score || 0)));
  parsed.band = scoreToBand(parsed.score);
  return parsed;
}

// ==================== 管理员模块 ====================
async function requireAdmin(request, env) {
  // 方案 A：管理员密码 token（不依赖用户账号，跨设备友好）
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  if (token && token.startsWith('admin_')) {
    try {
      const payload = await verifyToken(env, token.slice(6));
      if (payload && payload.role === 'admin' && payload.exp > Math.floor(Date.now() / 1000)) {
        return { user: { id: 'admin', is_admin: 1, name: 'Admin', email: null } };
      }
    } catch (_) {}
    return { error: errResp('admin token invalid or expired', 401) };
  }

  // 方案 B：兼容 user.is_admin（传统路径）
  const { user, error } = await requireAuth(request, env);
  if (error) return { error };
  if (!user.is_admin) return { error: errResp('admin only', 403) };
  return { user };
}

// GET /api/admin/stats —— 全局数据看板
async function handleAdminStats(request, env) {
  const { user, error } = await requireAdmin(request, env);
  if (error) return error;

  const today = todayDate();
  const weekAgo = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  const monthAgo = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString().slice(0, 10);

  const [
    usersTotal, usersActiveToday, usersOnboarded,
    resumesTotal, jdsTotal, positionsTotal, reviewsTotal,
    llmToday, llmWeek, llmMonth,
    quotaToday,
  ] = await Promise.all([
    env.DB.prepare('SELECT COUNT(*) AS c FROM users').first(),
    env.DB.prepare('SELECT COUNT(*) AS c FROM users WHERE substr(last_active_at, 1, 10) = ?').bind(today).first(),
    env.DB.prepare('SELECT COUNT(*) AS c FROM users WHERE onboarded = 1').first(),
    env.DB.prepare('SELECT COUNT(*) AS c FROM resumes').first(),
    env.DB.prepare('SELECT COUNT(*) AS c FROM jds').first(),
    env.DB.prepare('SELECT COUNT(*) AS c FROM positions').first(),
    env.DB.prepare('SELECT COUNT(*) AS c FROM reviews').first(),
    env.DB.prepare(
      "SELECT model, COUNT(*) AS calls, SUM(COALESCE(input_tokens,0)+COALESCE(output_tokens,0)) AS tokens " +
      "FROM llm_call_logs WHERE substr(created_at, 1, 10) = ? GROUP BY model"
    ).bind(today).all(),
    env.DB.prepare(
      "SELECT model, COUNT(*) AS calls, SUM(COALESCE(input_tokens,0)+COALESCE(output_tokens,0)) AS tokens " +
      "FROM llm_call_logs WHERE substr(created_at, 1, 10) >= ? GROUP BY model"
    ).bind(weekAgo).all(),
    env.DB.prepare(
      "SELECT model, COUNT(*) AS calls, SUM(COALESCE(input_tokens,0)+COALESCE(output_tokens,0)) AS tokens " +
      "FROM llm_call_logs WHERE substr(created_at, 1, 10) >= ? GROUP BY model"
    ).bind(monthAgo).all(),
    env.DB.prepare(
      "SELECT SUM(flash_used) AS flash, SUM(pro_used) AS pro, COUNT(*) AS users_with_usage " +
      "FROM usage_quota WHERE date = ?"
    ).bind(today).first(),
  ]);

  return jsonResp({
    users: {
      total: usersTotal?.c || 0,
      active_today: usersActiveToday?.c || 0,
      onboarded: usersOnboarded?.c || 0,
    },
    content: {
      resumes: resumesTotal?.c || 0,
      jds: jdsTotal?.c || 0,
      positions: positionsTotal?.c || 0,
      reviews: reviewsTotal?.c || 0,
    },
    llm: {
      today: llmToday.results || [],
      week: llmWeek.results || [],
      month: llmMonth.results || [],
    },
    quota_today: {
      flash_used_total: quotaToday?.flash || 0,
      pro_used_total: quotaToday?.pro || 0,
      users_with_usage: quotaToday?.users_with_usage || 0,
    },
  });
}

// GET /api/admin/users —— 用户列表
async function handleAdminUsers(request, env) {
  const { user, error } = await requireAdmin(request, env);
  if (error) return error;

  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit')) || 50, 200);

  const { results } = await env.DB.prepare(`
    SELECT
      u.id, u.email, u.name, u.target_track, u.target_stage,
      u.onboarded, u.is_admin, u.created_at, u.last_active_at,
      CASE WHEN u.own_api_key IS NOT NULL AND u.own_api_key != '' THEN 1 ELSE 0 END AS has_own_key,
      (SELECT COUNT(*) FROM resumes WHERE user_id = u.id) AS resumes_count,
      (SELECT COUNT(*) FROM jds WHERE user_id = u.id) AS jds_count,
      (SELECT COUNT(*) FROM positions WHERE user_id = u.id) AS positions_count,
      (SELECT COUNT(*) FROM reviews WHERE user_id = u.id) AS reviews_count,
      COALESCE((SELECT flash_used FROM usage_quota WHERE user_id = u.id AND date = ?), 0) AS flash_today,
      COALESCE((SELECT pro_used FROM usage_quota WHERE user_id = u.id AND date = ?), 0) AS pro_today
    FROM users u
    ORDER BY u.last_active_at DESC NULLS LAST
    LIMIT ?
  `).bind(todayDate(), todayDate(), limit).all();

  return jsonResp({ users: results || [] });
}

// GET /api/admin/users/:id —— 单个用户详情
async function handleAdminUserDetail(request, env, uid) {
  const { user, error } = await requireAdmin(request, env);
  if (error) return error;

  const target = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(uid).first();
  if (!target) return errResp('user not found', 404);

  // 脱敏
  if (target.own_api_key) target.own_api_key_masked = 'sk-***' + target.own_api_key.slice(-4);
  delete target.own_api_key;

  const [resumes, jds, positions, reviews, quotaHistory] = await Promise.all([
    env.DB.prepare('SELECT id, title, is_primary, created_at FROM resumes WHERE user_id = ?').bind(uid).all(),
    env.DB.prepare('SELECT id, company, position_title, match_score, created_at FROM jds WHERE user_id = ? ORDER BY created_at DESC LIMIT 20').bind(uid).all(),
    env.DB.prepare('SELECT id, company, position_title, status, created_at FROM positions WHERE user_id = ? ORDER BY created_at DESC LIMIT 20').bind(uid).all(),
    env.DB.prepare('SELECT id, position_id, created_at FROM reviews WHERE user_id = ? ORDER BY created_at DESC LIMIT 20').bind(uid).all(),
    env.DB.prepare('SELECT date, flash_used, pro_used, using_own_key FROM usage_quota WHERE user_id = ? ORDER BY date DESC LIMIT 14').bind(uid).all(),
  ]);

  return jsonResp({
    user: target,
    resumes: resumes.results || [],
    jds: jds.results || [],
    positions: positions.results || [],
    reviews: reviews.results || [],
    quota_history: quotaHistory.results || [],
  });
}

// GET /api/admin/llm-logs —— LLM 调用日志
async function handleAdminLLMLogs(request, env) {
  const { user, error } = await requireAdmin(request, env);
  if (error) return error;

  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit')) || 100, 500);
  const status = url.searchParams.get('status');      // 'failed' 等
  const purpose = url.searchParams.get('purpose');

  let sql = `
    SELECT l.id, l.user_id, l.model, l.purpose, l.input_tokens, l.output_tokens,
           l.duration_ms, l.status, l.error, l.created_at,
           u.email, u.name
    FROM llm_call_logs l
    LEFT JOIN users u ON l.user_id = u.id
    WHERE 1=1
  `;
  const bindings = [];
  if (status) { sql += ' AND l.status = ?'; bindings.push(status); }
  if (purpose) { sql += ' AND l.purpose = ?'; bindings.push(purpose); }
  sql += ' ORDER BY l.created_at DESC LIMIT ?';
  bindings.push(limit);

  const { results } = await env.DB.prepare(sql).bind(...bindings).all();
  return jsonResp({ logs: results || [] });
}

// GET /api/admin/config —— 读取全局配置
async function handleAdminGetConfig(request, env) {
  const { user, error } = await requireAdmin(request, env);
  if (error) return error;

  return jsonResp({
    quota: DAILY_QUOTA,
    models: LLM_MODELS,
    email_from: env.EMAIL_FROM || 'onboarding@resend.dev',
    version: 'v3.1',
  });
}

// POST /api/admin/config —— 更新配额（运行时生效，重启丢失；持久化改造可后续做）
async function handleAdminSetConfig(request, env) {
  const { user, error } = await requireAdmin(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  if (typeof body.flash_quota === 'number' && body.flash_quota > 0) {
    DAILY_QUOTA.FAST = Math.min(500, Math.max(1, Math.round(body.flash_quota)));
  }
  if (typeof body.pro_quota === 'number' && body.pro_quota > 0) {
    DAILY_QUOTA.PRO = Math.min(100, Math.max(1, Math.round(body.pro_quota)));
  }
  return jsonResp({ ok: true, quota: DAILY_QUOTA });
}

// POST /api/admin/set-admin —— 设定其他账号为管理员（自举用）
// Body: { user_id, is_admin: 0|1 }
async function handleAdminSetAdmin(request, env) {
  const { user, error } = await requireAdmin(request, env);
  if (error) return error;

  const body = await readJson(request) || {};
  if (!body.user_id) return errResp('user_id required');

  await env.DB.prepare('UPDATE users SET is_admin = ? WHERE id = ?')
    .bind(body.is_admin ? 1 : 0, body.user_id).run();

  return jsonResp({ ok: true });
}

// POST /api/admin/login —— 管理员密码登录（不依赖用户账号，跨设备友好）
// Body: { password }
async function handleAdminLogin(request, env) {
  const body = await readJson(request) || {};
  const password = (body.password || '').trim();
  if (!password) return errResp('password required');

  const expected = await getSecret(env.ADMIN_PASSWORD);
  if (!expected) {
    return errResp('ADMIN_PASSWORD not configured on server', 500);
  }
  // 常量时间比较防时序攻击
  if (!constantTimeEqual(password, expected)) {
    return errResp('密码错误', 401);
  }

  // 签发 30 天管理员 token（role=admin），前端以 admin_ 前缀存储
  const exp = Math.floor(Date.now() / 1000) + 30 * 24 * 3600;
  const inner = await signToken(env, { role: 'admin', exp });
  return jsonResp({ ok: true, token: 'admin_' + inner, expires_at: exp });
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// POST /api/admin/bootstrap —— 首个管理员自举（只在没任何管理员时可用）
// Body: { user_id } 或 { fingerprint }
async function handleAdminBootstrap(request, env) {
  const existing = await env.DB.prepare('SELECT COUNT(*) AS c FROM users WHERE is_admin = 1').first();
  if ((existing?.c || 0) > 0) {
    return errResp('已有管理员存在，请通过管理员账号设置其他人', 403);
  }
  const body = await readJson(request) || {};
  let userId = body.user_id;
  if (!userId && body.fingerprint) {
    const u = await env.DB.prepare('SELECT id FROM users WHERE fingerprint = ?').bind(body.fingerprint).first();
    userId = u?.id;
  }
  if (!userId) return errResp('user_id or fingerprint required');

  const res = await env.DB.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').bind(userId).run();
  if (!res.meta?.changes) return errResp('user not found', 404);
  return jsonResp({ ok: true, user_id: userId });
}

// ==================== 路由分发 ====================
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  // --- 健康检查 ---
  if (path === '/' || path === '/api' || path === '/api/health') {
    return jsonResp({
      ok: true,
      version: 'v3.1',
      time: now(),
    });
  }

  // --- 迁移 ---
  if (path === '/api/admin/migrate' && method === 'POST') {
    const result = await runMigration(env);
    return jsonResp(result);
  }
  if (path === '/api/admin/migrate' && method === 'GET') {
    const result = await runMigration(env);
    return jsonResp(result);
  }

  // --- 管理员自举（任何人可调，但只在没管理员时生效）---
  if (path === '/api/admin/bootstrap' && method === 'POST') return handleAdminBootstrap(request, env);

  // --- 管理员密码登录（不依赖用户账号，跨设备友好）---
  if (path === '/api/admin/login' && method === 'POST') return handleAdminLogin(request, env);

  // --- 管理员专用路由 ---
  if (path === '/api/admin/stats' && method === 'GET') return handleAdminStats(request, env);
  if (path === '/api/admin/users' && method === 'GET') return handleAdminUsers(request, env);
  const mAdmUser = path.match(/^\/api\/admin\/users\/([\w-]+)$/);
  if (mAdmUser && method === 'GET') return handleAdminUserDetail(request, env, mAdmUser[1]);
  if (path === '/api/admin/llm-logs' && method === 'GET') return handleAdminLLMLogs(request, env);
  if (path === '/api/admin/config' && method === 'GET') return handleAdminGetConfig(request, env);
  if (path === '/api/admin/config' && method === 'POST') return handleAdminSetConfig(request, env);
  if (path === '/api/admin/set-admin' && method === 'POST') return handleAdminSetAdmin(request, env);
  if (path === '/api/admin/cron/run-daily' && method === 'POST') return handleAdminRunDaily(request, env);

  // --- 账号 ---
  if (path === '/api/auth/anon' && method === 'POST') return handleAnonAuth(request, env);
  if (path === '/api/auth/me' && method === 'GET') return handleMe(request, env);
  if (path === '/api/auth/onboard' && method === 'POST') return handleOnboard(request, env);
  if (path === '/api/auth/bind-email/send' && method === 'POST') return handleSendEmailCode(request, env);
  if (path === '/api/auth/bind-email/verify' && method === 'POST') return handleVerifyEmailCode(request, env);
  if (path === '/api/auth/recover-send' && method === 'POST') return handleRecoverSend(request, env);
  if (path === '/api/auth/recover-by-email' && method === 'POST') return handleRecoverByEmail(request, env);

  // --- 当前用户配额/BYOK ---
  if (path === '/api/me/quota' && method === 'GET') return handleGetQuota(request, env);
  if (path === '/api/me/byok' && method === 'POST') return handleSetBYOK(request, env);
  if (path === '/api/me/reset' && method === 'POST') return handleResetMe(request, env);

  // --- 简历 ---
  if (path === '/api/resumes' && method === 'GET') return handleListResumes(request, env);
  if (path === '/api/resumes' && method === 'POST') return handleCreateResume(request, env);

  const mResume = path.match(/^\/api\/resumes\/([\w-]+)$/);
  if (mResume) {
    const id = mResume[1];
    if (method === 'GET') return handleGetResume(request, env, id);
    if (method === 'PUT') return handleUpdateResume(request, env, id);
    if (method === 'DELETE') return handleDeleteResume(request, env, id);
  }

  // --- JD ---
  if (path === '/api/jds' && method === 'GET') return handleListJDs(request, env);
  if (path === '/api/jds' && method === 'POST') return handleCreateJD(request, env);

  const mJdMatch = path.match(/^\/api\/jds\/([\w-]+)\/match$/);
  if (mJdMatch && method === 'POST') return handleMatchJD(request, env, mJdMatch[1]);

  const mJdQuick = path.match(/^\/api\/jds\/([\w-]+)\/quick-match$/);
  if (mJdQuick && method === 'POST') return handleQuickMatchJD(request, env, mJdQuick[1]);

  const mJd = path.match(/^\/api\/jds\/([\w-]+)$/);
  if (mJd) {
    const id = mJd[1];
    if (method === 'GET') return handleGetJD(request, env, id);
    if (method === 'PUT') return handleUpdateJD(request, env, id);
    if (method === 'DELETE') return handleDeleteJD(request, env, id);
  }

  // --- 岗位 ---
  if (path === '/api/positions' && method === 'GET') return handleListPositions(request, env);
  if (path === '/api/positions' && method === 'POST') return handleCreatePosition(request, env);

  const mPosRounds = path.match(/^\/api\/positions\/([\w-]+)\/rounds$/);
  if (mPosRounds) {
    const pid = mPosRounds[1];
    if (method === 'GET') return handleListRounds(request, env, pid);
    if (method === 'POST') return handleCreateRound(request, env, pid);
  }

  const mPos = path.match(/^\/api\/positions\/([\w-]+)$/);
  if (mPos) {
    const id = mPos[1];
    if (method === 'GET') return handleGetPosition(request, env, id);
    if (method === 'PUT') return handleUpdatePosition(request, env, id);
    if (method === 'DELETE') return handleDeletePosition(request, env, id);
  }

  // --- 面试轮次（直接按 round id 操作）---
  const mRnd = path.match(/^\/api\/rounds\/([\w-]+)$/);
  if (mRnd) {
    const id = mRnd[1];
    if (method === 'PUT') return handleUpdateRound(request, env, id);
    if (method === 'DELETE') return handleDeleteRound(request, env, id);
  }

  // --- 复盘 ---
  if (path === '/api/reviews' && method === 'GET') return handleListReviews(request, env);
  if (path === '/api/reviews' && method === 'POST') return handleCreateReview(request, env);

  const mRv = path.match(/^\/api\/reviews\/([\w-]+)$/);
  if (mRv) {
    const id = mRv[1];
    if (method === 'GET') return handleGetReview(request, env, id);
    if (method === 'DELETE') return handleDeleteReview(request, env, id);
  }

  // --- 画像池 ---
  if (path === '/api/profile' && method === 'GET') return handleGetProfile(request, env);
  if (path === '/api/profile/audit' && method === 'POST') return handleProfileAudit(request, env);

  const mTag = path.match(/^\/api\/profile\/tags\/([\w-]+)$/);
  if (mTag) {
    const id = mTag[1];
    if (method === 'PUT') return handleUpdateTag(request, env, id);
    if (method === 'DELETE') return handleRejectTag(request, env, id);
  }

  // --- 陪练题 ---
  if (path === '/api/practice' && method === 'GET') return handleListPractice(request, env);
  if (path === '/api/practice/generate' && method === 'POST') return handleGeneratePractice(request, env);
  if (path === '/api/practice/user-paste' && method === 'POST') return handlePastePractice(request, env);

  const mPq = path.match(/^\/api\/practice\/([\w-]+)$/);
  if (mPq) {
    const id = mPq[1];
    if (method === 'PUT') return handleUpdatePractice(request, env, id);
    if (method === 'DELETE') return handleDeletePractice(request, env, id);
  }

  // --- 岗位建议 ---
  if (path === '/api/suggestions' && method === 'GET') return handleListSuggestions(request, env);
  if (path === '/api/suggestions/generate' && method === 'POST') return handleGenerateSuggestions(request, env);

  const mSg = path.match(/^\/api\/suggestions\/([\w-]+)$/);
  if (mSg && method === 'PUT') return handleUpdateSuggestion(request, env, mSg[1]);

  // --- 通知 ---
  if (path === '/api/notifications' && method === 'GET') return handleListNotifications(request, env);
  if (path === '/api/notifications/read-all' && method === 'POST') return handleMarkAllNotifRead(request, env);
  if (path === '/api/notifications/preferences' && method === 'GET') return handleGetNotifPref(request, env);
  if (path === '/api/notifications/preferences' && method === 'POST') return handleSetNotifPref(request, env);

  const mNtfRead = path.match(/^\/api\/notifications\/([\w-]+)\/read$/);
  if (mNtfRead && method === 'POST') return handleMarkNotifRead(request, env, mNtfRead[1]);

  const mNtf = path.match(/^\/api\/notifications\/([\w-]+)$/);
  if (mNtf && method === 'DELETE') return handleDeleteNotif(request, env, mNtf[1]);

  return errResp('not_found', 404, { path });
}

// ==================== 入口 ====================
export default {
  async fetch(request, env, ctx) {
    try {
      // 把 ctx 挂到 env 上，业务层用 env.__ctx.waitUntil() 包裹异步任务
      // （Cloudflare Worker 要求异步后台任务必须用 waitUntil，否则响应返回后任务会被立即终止）
      env.__ctx = ctx;
      return await handleRequest(request, env, ctx);
    } catch (e) {
      console.error('fatal:', e?.stack || e);
      return errResp(`internal: ${e.message || e}`, 500);
    }
  },

  async scheduled(event, env, ctx) {
    console.log('Scheduled triggered:', event.cron, 'at', new Date().toISOString());
    env.__ctx = ctx;
    try {
      await dailyCronTasks(env);
    } catch (e) {
      console.error('scheduled error:', e?.stack || e);
    }
  },
};

// ==================== Cron 定时任务 ====================

// 每日综合任务：画像池自审 + 面试未复盘提醒
async function dailyCronTasks(env) {
  const summary = {
    started_at: now(),
    profile_audit: { processed: 0, failed: 0 },
    review_reminder: { reminded_users: 0, pending_reviews: 0 },
  };

  // ---------- 任务 1：面试未复盘提醒 ----------
  // 找所有"距今 24-96 小时前发生的面试轮次，还没写对应复盘"
  // 96 小时上限是为了避免把古老面试反复提醒
  const h24ago = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const h96ago = new Date(Date.now() - 96 * 3600 * 1000).toISOString();

  // 查所有合格的面试轮次
  const { results: pendingRounds } = await env.DB.prepare(`
    SELECT
      r.id AS round_id, r.position_id, r.round_number, r.scheduled_at,
      p.user_id, p.company, p.position_title
    FROM interview_rounds r
    JOIN positions p ON r.position_id = p.id
    WHERE r.scheduled_at IS NOT NULL
      AND r.scheduled_at > ?
      AND r.scheduled_at <= ?
      AND NOT EXISTS (
        SELECT 1 FROM reviews rv WHERE rv.round_id = r.id AND rv.parse_status != 'failed'
      )
  `).bind(h96ago, h24ago).all();

  summary.review_reminder.pending_reviews = (pendingRounds || []).length;

  // 按用户聚合：同一用户的多场面试合并成一条通知
  const byUser = {};
  for (const row of pendingRounds || []) {
    if (!byUser[row.user_id]) byUser[row.user_id] = [];
    byUser[row.user_id].push(row);
  }

  for (const [uid, rounds] of Object.entries(byUser)) {
    // 去重：如果今天已经推过一条 review_missing 通知，就不重复推
    const today = todayDate();
    const existed = await env.DB.prepare(`
      SELECT id FROM notifications
      WHERE user_id = ? AND type = 'review_missing'
        AND substr(created_at, 1, 10) = ?
    `).bind(uid, today).first();
    if (existed) continue;

    const title = rounds.length === 1
      ? `面试已结束，别忘了复盘：${rounds[0].company} · ${rounds[0].position_title}`
      : `你有 ${rounds.length} 场面试还没复盘`;
    const content = rounds.length === 1
      ? `第 ${rounds[0].round_number} 轮面试已结束 24h+，粘贴回忆文本让 AI 帮你分析`
      : rounds.map(r => `· ${r.company} · ${r.position_title} 第 ${r.round_number} 轮`).join('\n');

    await createNotification(env, uid, {
      type: 'review_missing',
      title,
      content,
      link: rounds.length === 1 ? `/position/${rounds[0].position_id}` : '/positions',
    });
    summary.review_reminder.reminded_users++;
  }

  // ---------- 任务 2：画像池自审（按用户分批）----------
  // 只对"画像标签数 >= 6 且上次自审 >= 7 天前"的用户跑，避免日日重复
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();

  const { results: candidates } = await env.DB.prepare(`
    SELECT
      u.id AS user_id,
      COUNT(pt.id) AS tag_count,
      (SELECT MAX(created_at) FROM profile_audits WHERE user_id = u.id) AS last_audit_at
    FROM users u
    LEFT JOIN profile_tags pt ON pt.user_id = u.id AND pt.status = 'active'
    GROUP BY u.id
    HAVING tag_count >= 6
      AND (last_audit_at IS NULL OR last_audit_at < ?)
  `).bind(sevenDaysAgo).all();

  // 每次 Cron 最多处理 20 个用户（避免单次 Cron 超时 / 配额一次炸太多）
  const BATCH_LIMIT = 20;
  const toProcess = (candidates || []).slice(0, BATCH_LIMIT);

  for (const c of toProcess) {
    try {
      // 取用户对象（Cron 里没有 request，手动构造"user 像"）
      const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(c.user_id).first();
      if (!user) continue;
      await runProfileAudit(env, user);
      summary.profile_audit.processed++;
    } catch (e) {
      console.error('audit user failed:', c.user_id, e.message);
      summary.profile_audit.failed++;
    }
  }

  summary.finished_at = now();
  console.log('dailyCronTasks summary:', JSON.stringify(summary));
  return summary;
}

// ---------- 管理员手动触发 Cron 的接口（排查用）----------
// POST /api/admin/cron/run-daily
async function handleAdminRunDaily(request, env) {
  const { user, error } = await requireAdmin(request, env);
  if (error) return error;

  const summary = await dailyCronTasks(env);
  return jsonResp({ ok: true, summary });
}
