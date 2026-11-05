import { guard, json, publicSection, readSettings } from "../../server/access.js";

// Tells the app who is signed in, which sections they may open, and the ministry name.
export async function onRequest(context) {
  const { request, env } = context;
  if (request.method !== "GET") return json({ error: "Method not allowed" }, 405);

  const g = await guard(request, env);
  if (g.error) return g.error;

  const settings = await readSettings(env);
  return json({
    email: g.user.email,
    isAdmin: g.user.isAdmin,
    sections: g.user.sections.map(publicSection),
    settings,
    setupNeeded: !settings && g.user.isAdmin,
  });
}
