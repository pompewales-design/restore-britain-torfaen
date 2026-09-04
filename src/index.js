const COOKIE = "rb_torfaen_member";
const SESSION_SECONDS = 60 * 60 * 24 * 90;
const CALENDAR_API = "/members/api/calendar";

function b64url(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
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
    "HMAC",
    key,
    new TextEncoder().encode(text)
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

function getCookie(request) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp(`${COOKIE}=([^;]+)`));
  return match?.[1] || "";
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "Cache-Control": "private, no-store"
    }
  });
}

function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  return origin === new URL(request.url).origin;
}

function validateEvent(input) {
  const title = String(input?.title ?? "").trim();
  const eventDate = String(input?.event_date ?? "").trim();
  const start = String(input?.start_time ?? "").trim();
  const end = String(input?.end_time ?? "").trim();
  const location = String(input?.location ?? "").trim();
  const description = String(input?.description ?? "").trim();
  const category = String(input?.category ?? "Other").trim() || "Other";

  if (!title) return { ok: false, error: "Title is required." };
  if (title.length > 120) return { ok: false, error: "Title is too long." };
  if (!/^\d{4}-\d{2}-\d{2}$/.test(eventDate)) {
    return { ok: false, error: "A valid event date is required." };
  }

  const [y, m, d] = eventDate.split("-").map(Number);
  const check = new Date(Date.UTC(y, m - 1, d));
  if (
    check.getUTCFullYear() !== y ||
    check.getUTCMonth() !== m - 1 ||
    check.getUTCDate() !== d
  ) {
    return { ok: false, error: "A valid event date is required." };
  }

  if (start && !/^\d{2}:\d{2}$/.test(start)) {
    return { ok: false, error: "Start time is invalid." };
  }
  if (end && !/^\d{2}:\d{2}$/.test(end)) {
    return { ok: false, error: "End time is invalid." };
  }
  if (start && end && start > end) {
    return { ok: false, error: "End time must be after start time." };
  }
  if (location.length > 200) return { ok: false, error: "Location is too long." };
  if (description.length > 4000) return { ok: false, error: "Description is too long." };

  const categories = ["Meeting", "Campaign", "Branch Activity", "Other"];
  if (!categories.includes(category)) {
    return { ok: false, error: "Category is invalid." };
  }

  return {
    ok: true,
    value: {
      title,
      event_date: eventDate,
      start_time: start,
      end_time: end,
      location,
      description,
      category
    }
  };
}

async function calendarApi(request, env) {
  if (!env.DB) return json({ error: "Calendar database is not connected." }, 500);

  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean);
  const idPart = parts.length === 4 ? parts[3] : null;

  if (request.method === "GET") {
    const month = url.searchParams.get("month") || "";
    if (!/^\d{4}-\d{2}$/.test(month)) {
      return json({ error: "Month must be YYYY-MM." }, 400);
    }

    const [year, monthNumber] = month.split("-").map(Number);
    if (monthNumber < 1 || monthNumber > 12) {
      return json({ error: "Invalid month." }, 400);
    }

    const start = `${year}-${String(monthNumber).padStart(2, "0")}-01`;
    const nextDate = new Date(Date.UTC(year, monthNumber, 1));
    const next = `${nextDate.getUTCFullYear()}-${String(nextDate.getUTCMonth() + 1).padStart(2, "0")}-01`;

    const result = await env.DB.prepare(`
      SELECT id, title, event_date, start_time, end_time, location, description, category
      FROM events
      WHERE event_date >= ? AND event_date < ?
      ORDER BY event_date ASC, start_time ASC, title ASC
    `).bind(start, next).all();

    return json({ events: result.results || [] });
  }

  if (!sameOrigin(request)) return json({ error: "Invalid request origin." }, 403);

  if (request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "Invalid JSON." }, 400);
    }

    const checked = validateEvent(body);
    if (!checked.ok) return json({ error: checked.error }, 400);

    const e = checked.value;
    const result = await env.DB.prepare(`
      INSERT INTO events
        (title, event_date, start_time, end_time, location, description, category)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      e.title, e.event_date, e.start_time, e.end_time,
      e.location, e.description, e.category
    ).run();

    return json({ id: result.meta?.last_row_id, event: e }, 201);
  }

  if (!idPart || !/^\d+$/.test(idPart)) {
    return json({ error: "Event ID is required." }, 400);
  }

  const id = Number(idPart);

  if (request.method === "PUT") {
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "Invalid JSON." }, 400);
    }

    const checked = validateEvent(body);
    if (!checked.ok) return json({ error: checked.error }, 400);

    const e = checked.value;
    const result = await env.DB.prepare(`
      UPDATE events
      SET title = ?, event_date = ?, start_time = ?, end_time = ?,
          location = ?, description = ?, category = ?,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(
      e.title, e.event_date, e.start_time, e.end_time,
      e.location, e.description, e.category, id
    ).run();

    if (!result.meta?.changes) return json({ error: "Event not found." }, 404);
    return json({ id, event: e });
  }

  if (request.method === "DELETE") {
    const result = await env.DB.prepare(
      "DELETE FROM events WHERE id = ?"
    ).bind(id).run();

    if (!result.meta?.changes) return json({ error: "Event not found." }, 404);
    return json({ ok: true });
  }

  return json({ error: "Method not allowed." }, 405);
}

function loginPage(message = "") {
  return `<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Members Login | Restore Britain Torfaen</title>
<style>
body{margin:0;min-height:100vh;font-family:Arial,Helvetica,sans-serif;background:#090909;color:#eee;display:grid;place-items:center}
.box{width:min(430px,calc(100% - 36px));background:#151515;border-radius:12px;padding:34px;box-shadow:0 10px 30px #000;text-align:center;border-top:6px solid #ed1c24}
h1{font-family:Georgia,serif;color:#fff}
p{color:#bdbdbd;line-height:1.6}
input{width:100%;padding:13px;border:1px solid #444;background:#222;color:#fff;border-radius:7px;font-size:1rem;box-sizing:border-box;margin:10px 0 14px}
button{width:100%;padding:13px;border:0;border-radius:7px;background:#ed1c24;color:#fff;font-weight:700;font-size:1rem;cursor:pointer}
.err{color:#ff6b70;font-weight:700}
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

    if (!isMembers) {
      if (!env.ASSETS) {
        return new Response("Preview environment: ASSETS binding is not available.", {
          status: 503,
          headers: { "Content-Type": "text/plain; charset=UTF-8" }
        });
      }
      return env.ASSETS.fetch(request);
    }

    const cookie = getCookie(request);
    const authenticated = await validSession(env.MEMBERS_PASSWORD, cookie);

    if (authenticated && url.pathname.startsWith(CALENDAR_API)) {
      return calendarApi(request, env);
    }

    if (authenticated) {
      if (!env.ASSETS) {
        return new Response("Preview environment: ASSETS binding is not available.", {
          status: 503,
          headers: { "Content-Type": "text/plain; charset=UTF-8" }
        });
      }
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
        headers: {
          "Content-Type": "text/html; charset=UTF-8",
          "Cache-Control": "no-store"
        }
      });
    }

    return new Response(loginPage(), {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=UTF-8",
        "Cache-Control": "no-store"
      }
    });
  }
};
