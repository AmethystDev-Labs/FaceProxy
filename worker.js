let jwtToken = null;
let jwtExpiration = 0;

/**
 * 获取或刷新 Hugging Face JWT Token
 */
async function getJwtToken(HF_SPACE_NAME, HF_TOKEN, HF_SPACE_USER) {
  const now = Date.now() / 1000;
  if (jwtToken && jwtExpiration > now + 60) {
    return jwtToken;
  }

  if (!HF_TOKEN || !HF_SPACE_NAME || !HF_SPACE_USER) {
    throw new Error('Environment variables HF_TOKEN, HF_SPACE_NAME, or HF_SPACE_USER are missing.');
  }

  const HF_API_URL = `https://huggingface.co/api/spaces/${HF_SPACE_USER}/${HF_SPACE_NAME}/jwt`;
  const response = await fetch(HF_API_URL, {
    headers: { "Authorization": `Bearer ${HF_TOKEN}` },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch JWT token: ${response.statusText}`);
  }

  const result = await response.json();
  jwtToken = result.token;

  try {
    const jwtPayload = JSON.parse(atob(jwtToken.split('.')[1]));
    jwtExpiration = jwtPayload.exp;
  } catch (e) {
    jwtExpiration = now + 3600; 
  }
  return jwtToken;
}

export default {
  async fetch(request, env) {
    const { HF_TOKEN, HF_SPACE_NAME, HF_SPACE_USER } = env;
    const targetHost = `${HF_SPACE_USER}-${HF_SPACE_NAME}.hf.space`;

    try {
      const token = await getJwtToken(HF_SPACE_NAME, HF_TOKEN, HF_SPACE_USER);
      const url = new URL(request.url);
      const originalHost = url.host; // 记录 Worker 的域名
      url.host = targetHost;

      // 1. 深度克隆并处理 Headers
      const newHeaders = new Headers(request.headers);
      
      // 合并 Cookie，而不是覆盖！
      const existingCookie = request.headers.get('Cookie') || '';
      const spaceJwtCookie = `spaces-jwt=${token}`;
      newHeaders.set('Cookie', existingCookie ? `${existingCookie}; ${spaceJwtCookie}` : spaceJwtCookie);
      
      // 设置 Host 头部，这对于后端路由非常重要
      newHeaders.set('Host', targetHost);
      
      // 传递真实客户端 IP，缓解 Turnstile 验证
      const clientIP = request.headers.get("CF-Connecting-IP");
      if (clientIP) {
        newHeaders.set('X-Forwarded-For', clientIP);
        newHeaders.set('X-Real-IP', clientIP);
      }

      // 2. 发起转发请求（禁止自动重定向，以便我们手动改写 Location）
      const modifiedRequest = new Request(url, {
        method: request.method,
        headers: newHeaders,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : null,
        redirect: 'manual' 
      });

      const response = await fetch(modifiedRequest);

      // 3. 处理重定向 (OAuth 关键步骤)
      // 如果后端要求重定向到 HF 域名，我们需要将其改回 Worker 域名
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get('Location');
        if (location) {
          const newResponseHeaders = new Headers(response.headers);
          const rewrittenLocation = location.replace(targetHost, originalHost);
          newResponseHeaders.set('Location', rewrittenLocation);
          
          return new Response(response.body, {
            status: response.status,
            headers: newResponseHeaders
          });
        }
      }

      return response;

    } catch (error) {
      return new Response(`Proxy Error: ${error.message}`, { status: 500 });
    }
  }
};