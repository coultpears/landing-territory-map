// Single-password gate for the Landing Territory Map.
// Serves a custom login page (password-only, no username) instead of the
// browser's Basic-Auth dialog. The password is read from the MAP_PASSWORD
// site env var, so it is never stored in this (public) repo. On success we
// set an auth cookie whose value is the password itself — forging it requires
// knowing the password, so the threat model matches Basic Auth.
const COOKIE = "ltm_auth";

function loginPage(error) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Landing Territory Map</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap');
*{box-sizing:border-box}body{margin:0;font-family:'DM Sans',system-ui,sans-serif;background:#15192D;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}
.card{background:#fff;border-radius:14px;padding:36px 40px;max-width:340px;width:100%;box-shadow:0 8px 40px rgba(0,0,0,.3);text-align:center}
h1{font-size:18px;color:#15192D;margin:0 0 4px;font-weight:700;letter-spacing:-.3px}
p{font-size:13px;color:#5A6478;margin:0 0 22px}
input{width:100%;padding:11px 14px;border:1px solid #D8DBE2;border-radius:8px;font-size:14px;margin-bottom:12px;font-family:inherit}
input:focus{outline:none;border-color:#1A61D9}
button{width:100%;padding:11px;background:#1A61D9;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit}
button:hover{background:#134EAE}
.err{color:#D84A3D;font-size:12px;margin-bottom:10px;font-weight:500}
</style></head><body>
<form class="card" method="POST" action="/">
<h1>Landing Territory Map</h1>
<p>Enter the password to continue</p>
${error ? '<div class="err">Incorrect password</div>' : ''}
<input type="password" name="password" placeholder="Password" autofocus required>
<button type="submit">Enter</button>
</form></body></html>`;
}

export default async (request, context) => {
  const expected = Netlify.env.get("MAP_PASSWORD");

  // Already authenticated?
  const cookie = request.headers.get("cookie") || "";
  const m = cookie.match(/(?:^|;\s*)ltm_auth=([^;]+)/);
  if (expected && m && decodeURIComponent(m[1]) === expected) {
    return context.next();
  }

  // Login submission
  if (request.method === "POST") {
    let pw = "";
    try { pw = (await request.formData()).get("password") || ""; } catch { pw = ""; }
    if (expected && pw === expected) {
      const headers = new Headers();
      headers.set("Location", "/");
      headers.set("Set-Cookie", `${COOKIE}=${encodeURIComponent(expected)}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax`);
      return new Response("", { status: 303, headers });
    }
    return new Response(loginPage(true), { status: 401, headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  // Unauthenticated GET -> show the password form (200 so no browser auth dialog)
  return new Response(loginPage(false), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
};

export const config = { path: "/*" };
