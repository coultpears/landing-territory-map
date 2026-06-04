// HTTP Basic Auth gate for the Landing Territory Map.
// The password is read from the MAP_PASSWORD site env var, so it is never
// committed to this (public) repo. Username is ignored — any username works,
// only the password is checked.
export default async (request, context) => {
  const expected = Netlify.env.get("MAP_PASSWORD");
  // If the password var is somehow unset, fail closed (deny) rather than
  // silently exposing the map.
  const header = request.headers.get("authorization") || "";
  if (expected && header.startsWith("Basic ")) {
    let decoded = "";
    try { decoded = atob(header.slice(6)); } catch { decoded = ""; }
    const pass = decoded.slice(decoded.indexOf(":") + 1);
    if (pass === expected) return context.next();
  }
  return new Response("Authentication required.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Landing Territory Map", charset="UTF-8"',
      "Content-Type": "text/plain",
    },
  });
};

export const config = { path: "/*" };
