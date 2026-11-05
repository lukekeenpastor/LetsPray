import { guard, json, cleanEmailList, loadAccess, adminEmails, SECTION_IDS } from "../../server/access.js";

// Admin-only. Lists which email addresses may open each section.
export async function onRequest(context) {
  const { request, env } = context;
  const g = await guard(request, env, { admin: true });
  if (g.error) return g.error;

  if (request.method === "GET") {
    return json({ access: await loadAccess(env), admins: adminEmails(env) });
  }

  if (request.method === "POST") {
    const body = await request.text();
    if (body.length > 100_000) return json({ error: "Too large" }, 413);
    try {
      const p = JSON.parse(body);
      const next = {};
      for (const id of SECTION_IDS) next[id] = cleanEmailList(p && p[id]);
      await env.INTERCEDE_KV.put("access", JSON.stringify(next));
      return json({ ok: true, access: next });
    } catch (_e) {
      return json({ error: "Invalid JSON" }, 400);
    }
  }

  return json({ error: "Method not allowed" }, 405);
}
