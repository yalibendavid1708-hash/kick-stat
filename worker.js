const API = "https://api.kick.com/public/v1";
const ID = "https://id.kick.com";

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    try {
      if (url.pathname === "/api/stats") return json(await stats(env));
      if (url.pathname === "/auth/login") return login(url, env);
      if (url.pathname === "/auth/callback") return callback(url, env);
      return new Response("Not found", { status: 404 });
    } catch (e) {
      return json({ error: String(e.message || e) }, 500);
    }
  },
};

const json = (d, s = 200) =>
  new Response(JSON.stringify(d), {
    status: s,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      "cache-control": "public, max-age=30",
    },
  });

const b64url = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const rand = (n) => b64url(crypto.getRandomValues(new Uint8Array(n)));

async function stats(env) {
  const cached = await env.KV.get("stats", "json");
  if (cached) return cached;
  const token = await appToken(env);
  const ch = await kick(`/channels?slug=${encodeURIComponent(env.CHANNEL)}`, token);
  const c = ch.data?.[0] || {};
  const out = {
    channel: env.CHANNEL,
    live: !!c.stream?.is_live,
    viewers: c.stream?.viewer_count ?? 0,
    title: c.stream_title ?? "",
    followers: await followers(env.CHANNEL),
    leaderboard: await leaderboard(env),
    updated: Date.now(),
  };
  await env.KV.put("stats", JSON.stringify(out), { expirationTtl: 60 });
  return out;
}

async function kick(path, token) {
  const r = await fetch(API + path, { headers: { authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`kick ${path} -> ${r.status}`);
  return r.json();
}

async function tokenReq(env, params) {
  const r = await fetch(`${ID}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.KICK_CLIENT_ID,
      client_secret: env.KICK_CLIENT_SECRET,
      ...params,
    }),
  });
  const d = await r.json();
  if (!d.access_token) throw new Error("token request failed");
  return d;
}

async function appToken(env) {
  const c = await env.KV.get("app_token");
  if (c) return c;
  const d = await tokenReq(env, { grant_type: "client_credentials" });
  await env.KV.put("app_token", d.access_token, {
    expirationTtl: Math.max(60, (d.expires_in || 3600) - 120),
  });
  return d.access_token;
}

// Unofficial endpoint: Kick's official API has no follower count.
// It may be blocked or change; the site simply hides followers if null.
async function followers(slug) {
  try {
    const r = await fetch(`https://kick.com/api/v2/channels/${slug}`, {
      headers: {
        accept: "application/json",
        "user-agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36",
      },
    });
    if (!r.ok) return null;
    const d = await r.json();
    return d.followers_count ?? d.followersCount ?? null;
  } catch {
    return null;
  }
}

// Top donors (KICKs leaderboard) needs the channel owner's one-time authorization.
async function leaderboard(env) {
  try {
    const t = await userToken(env);
    if (!t) return null;
    const d = await kick("/kicks/leaderboard?top=5", t);
    return d.data ?? null;
  } catch {
    return null;
  }
}

async function saveUser(env, d) {
  await env.KV.put(
    "user_tokens",
    JSON.stringify({
      access_token: d.access_token,
      refresh_token: d.refresh_token,
      expires_at: Date.now() + (d.expires_in || 3600) * 1000,
    })
  );
}

async function userToken(env) {
  const s = await env.KV.get("user_tokens", "json");
  if (!s) return null;
  if (Date.now() < s.expires_at - 60000) return s.access_token;
  const d = await tokenReq(env, { grant_type: "refresh_token", refresh_token: s.refresh_token });
  await saveUser(env, d);
  return d.access_token;
}

async function login(url, env) {
  if (url.searchParams.get("key") !== env.ADMIN_KEY) return new Response("Forbidden", { status: 403 });
  const state = rand(16);
  const verifier = rand(48);
  const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  await env.KV.put(`pkce:${state}`, verifier, { expirationTtl: 600 });
  const u = new URL(`${ID}/oauth/authorize`);
  u.search = new URLSearchParams({
    response_type: "code",
    client_id: env.KICK_CLIENT_ID,
    redirect_uri: env.REDIRECT_URI,
    scope: "user:read channel:read kicks:read",
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
  }).toString();
  return Response.redirect(u.toString(), 302);
}

async function callback(url, env) {
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");
  const verifier = state ? await env.KV.get(`pkce:${state}`) : null;
  if (!code || !verifier) return new Response("Invalid or expired link", { status: 400 });
  await env.KV.delete(`pkce:${state}`);
  const d = await tokenReq(env, {
    grant_type: "authorization_code",
    code,
    redirect_uri: env.REDIRECT_URI,
    code_verifier: verifier,
  });
  await saveUser(env, d);
  return new Response("Connected. You can close this tab.");
}
