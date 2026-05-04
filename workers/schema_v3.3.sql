-- ============================================================
-- 求职小助 v3.2 → v3.3 增量迁移
-- Cloudflare D1 (SQLite 语法)
-- 新增：面经墙 UGC 生态
-- ============================================================

-- 1. 面经卡片表
CREATE TABLE IF NOT EXISTS experience_cards (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  review_id TEXT,
  company TEXT NOT NULL,
  position_title TEXT NOT NULL,
  round_number INTEGER,
  round_type TEXT,
  score INTEGER,
  card_mode TEXT NOT NULL DEFAULT 'qa',        -- 'qa' 完整问答 | 'q_only' 仅问题
  card_title TEXT,
  card_body TEXT NOT NULL,                      -- 富文本/Markdown 正文
  ai_tags TEXT,                                  -- JSON ["产品","数据分析","一面"]
  like_count INTEGER DEFAULT 0,
  question_count INTEGER DEFAULT 0,
  is_draft INTEGER DEFAULT 1,                   -- 0=发布 1=草稿
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cards_user ON experience_cards(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cards_company ON experience_cards(company);
CREATE INDEX IF NOT EXISTS idx_cards_tags ON experience_cards(ai_tags);

-- 2. 卡片问答表（AI生成 + 自定义提问）
CREATE TABLE IF NOT EXISTS card_questions (
  id TEXT PRIMARY KEY,
  card_id TEXT NOT NULL,
  asker_id TEXT NOT NULL,
  question_text TEXT NOT NULL,
  is_ai_generated INTEGER DEFAULT 0,            -- 0=自定义 1=AI模板
  reply_text TEXT,
  replied_at TEXT,
  like_count INTEGER DEFAULT 0,
  is_hidden INTEGER DEFAULT 0,                   -- 自定义提问未回复时折叠
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cq_card ON card_questions(card_id, created_at);
CREATE INDEX IF NOT EXISTS idx_cq_asker ON card_questions(asker_id);

-- 3. 点赞表（卡片 / 问题 通用）
CREATE TABLE IF NOT EXISTS card_likes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  target_type TEXT NOT NULL,                     -- 'card' | 'question'
  target_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_likes_unique ON card_likes(user_id, target_type, target_id);

-- 4. AI 问题缓存（每张卡生成一次，所有访客看到相同问题）
CREATE TABLE IF NOT EXISTS card_ai_questions (
  card_id TEXT PRIMARY KEY,
  questions TEXT NOT NULL,                       -- JSON ["问题1","问题2",...]
  generated_at TEXT NOT NULL
);

-- 5. 用户表扩展：用于面经墙展示（不存在则添加，幂等）
-- ALTER TABLE users ADD COLUMN display_name TEXT;
-- ALTER TABLE users ADD COLUMN bio TEXT;
-- (D1 不支持 ALTER TABLE IF NOT EXISTS，由 /api/admin/migrate 运行时检测后执行)
