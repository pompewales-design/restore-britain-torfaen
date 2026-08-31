const COOKIE = "rb_torfaen_member";
const SESSION_SECONDS = 60 * 60 * 24 * 90; // 90 days; changing the password invalidates old sessions

function b64url(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

async function sign(secret, text) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(text)
  ));
}

async function makeSession(secret) {
  const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  const payload = String(expires);
  const signature = b64url(await sign(secret, payload));
  return `${b64url(new TextEncoder().encode(payload))}.${signature}`;
}

async function validSession(secret, value) {
  try {
    if (!secret || !value) return false;
    const [encodedPayload, encodedSignature] = value.split(".");
    if (!encodedPayload || !encodedSignature) return false;

    const payload = new TextDecoder().decode(fromB64url(encodedPayload));
    if (Number(payload) < Math.floor(Date.now() / 1000)) return false;

    const expected = await sign(secret, payload);
    const actual = fromB64url(encodedSignature);
    if (expected.length !== actual.length) return false;

    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ actual[i];
    return diff === 0;
  } catch {
    return false;
  }
}

function loginPage(message = "") {
  return `<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Members Login | Restore Britain Torfaen</title>
<style>
body{margin:0;min-height:100vh;font-family:Arial,Helvetica,sans-serif;background:#f5f7fa;color:#172033;display:grid;place-items:center}
.box{width:min(430px,calc(100% - 36px));background:#fff;border-radius:18px;padding:34px;box-shadow:0 10px 30px #06224a18;text-align:center;border-top:7px solid #c9151e}
h1{font-family:Georgia,serif;color:#06224a}
p{color:#5f6878;line-height:1.6}
input{width:100%;padding:13px;border:1px solid #ccd3dd;border-radius:8px;font-size:1rem;box-sizing:border-box;margin:10px 0 14px}
button{width:100%;padding:13px;border:0;border-radius:8px;background:#06224a;color:#fff;font-weight:700;font-size:1rem;cursor:pointer}
.err{color:#c9151e;font-weight:700}
</style>
</head>
<body>
<main class="box">
<h1>Members Area</h1>
<p>Enter the current Restore Britain Torfaen members' password.</p>
${message ? `<p class="err">${message}</p>` : ""}
<form method="post">
<input name="password" type="password" autocomplete="current-password" required aria-label="Members password">
<button type="submit">Continue</button>
</form>
</main>
</body>
</html>`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const isMembers = url.pathname === "/members" || url.pathname.startsWith("/members/");

    // Everything except /members is completely public.
    if (!isMembers) return env.ASSETS.fetch(request);

    const cookie = request.headers.get("Cookie") || "";
    const match = cookie.match(new RegExp(`${COOKIE}=([^;]+)`));

    if (await validSession(env.MEMBERS_PASSWORD, match?.[1])) {
      const response = await env.ASSETS.fetch(request);
      const headers = new Headers(response.headers);
      headers.set("Cache-Control", "private, no-store");
      return new Response(response.body, { status: response.status, headers });
    }

    if (request.method === "POST") {
      const form = await request.formData();
      const supplied = String(form.get("password") || "");

      if (supplied && supplied === env.MEMBERS_PASSWORD) {
        const token = await makeSession(env.MEMBERS_PASSWORD);
        return new Response(null, {
          status: 302,
          headers: {
            Location: url.pathname + url.search,
            "Set-Cookie": `${COOKIE}=${token}; Max-Age=${SESSION_SECONDS}; Path=/members; Secure; HttpOnly; SameSite=Lax`
          }
        });
      }

      return new Response(loginPage("That password is not correct."), {
        status: 401,
        headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store" }
      });
    }

    return new Response(loginPage(), {
      status: 200,
      headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store" }
    });
  }
};
