// Territory config store — GET is open (already behind the site password via
// the edge auth gate); writes require the admin token (ADMIN_PASSWORD env var).
// Persisted in Netlify Blobs so an admin edit is live for every viewer with no
// redeploy. Returns { config: null } when nothing has been saved yet, in which
// case the page falls back to its baked-in DEFAULT_CONFIG.
import { getStore } from "@netlify/blobs";

const STORE_NAME = "territory";
const KEY = "config";

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });

export default async (req) => {
  const store = getStore(STORE_NAME);

  if (req.method === "GET") {
    // Admin password check (no write) — lets the editor verify the password
    // before entering edit mode without persisting anything.
    const url = new URL(req.url);
    if (url.searchParams.get("verify") === "1") {
      const expected = Netlify.env.get("ADMIN_PASSWORD") || "";
      const token = req.headers.get("x-admin-token") || "";
      return json({ valid: !!expected && token === expected });
    }
    const config = await store.get(KEY, { type: "json" });
    return json({ config: config || null });
  }

  if (req.method === "POST" || req.method === "PUT") {
    const expected = Netlify.env.get("ADMIN_PASSWORD") || "";
    const token = req.headers.get("x-admin-token") || "";
    if (!expected || token !== expected) return json({ error: "unauthorized" }, 401);

    let body;
    try { body = await req.json(); } catch { return json({ error: "invalid json" }, 400); }
    // Shape guard — never persist something the map can't render.
    if (!body || !Array.isArray(body.pods) || typeof body.stateAssignments !== "object") {
      return json({ error: "invalid config" }, 400);
    }
    await store.setJSON(KEY, body);
    return json({ ok: true, savedAt: Date.now() });
  }

  return json({ error: "method not allowed" }, 405);
};

// Functions API v2 path routing — served directly at /api/territory (no redirect).
export const config = { path: "/api/territory" };
