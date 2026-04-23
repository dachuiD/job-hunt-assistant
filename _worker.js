// ============================================================
// Cloudflare Pages Functions - 反向代理
// 作用：把 job-hunt-assistant.pages.dev/api/* 的请求
//       内部转发到 workers.dev 后端，绕过国内 DNS 污染
//
// 部署方式：把本文件放在 GitHub 仓库根目录（跟 index.html 同级）
//           Cloudflare Pages 会自动识别并启用
// ============================================================

// 你的 Worker 后端地址（Service Binding 在边缘节点内部走，不经过公网 DNS）
const WORKER_HOST = 'https://job-hunt-api.dxhapi.workers.dev';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 只代理 /api/* 路径到 Worker，其他路径走 Pages 静态资源
    if (url.pathname.startsWith('/api/')) {
      // 构造转发 URL：保留 path 和 query
      const targetUrl = WORKER_HOST + url.pathname + url.search;

      // 克隆请求头，去掉 host（让 fetch 自己填）
      const headers = new Headers(request.headers);
      headers.delete('host');

      const forwarded = new Request(targetUrl, {
        method: request.method,
        headers,
        body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
        redirect: 'follow',
      });

      try {
        const resp = await fetch(forwarded);

        // 复制响应，追加 CORS 头（冗余保险）
        const newHeaders = new Headers(resp.headers);
        newHeaders.set('Access-Control-Allow-Origin', '*');
        newHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        newHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');

        return new Response(resp.body, {
          status: resp.status,
          statusText: resp.statusText,
          headers: newHeaders,
        });
      } catch (err) {
        return new Response(
          JSON.stringify({ error: 'proxy_error', message: err.message }),
          {
            status: 502,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*',
            },
          }
        );
      }
    }

    // 非 /api/* 路径：交给 Pages 静态资源处理（index.html 等）
    return env.ASSETS.fetch(request);
  },
};
