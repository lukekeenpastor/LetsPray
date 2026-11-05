import { guard, json, kvKeys } from "../../server/access.js";

const FIELDS = ["weekStart", "prevWeekStart", "prevWeekDateStr", "count", "total"];

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === "OPTIONS") return new Response(null, { status: 204 });

  const url = new URL(request.url);
  const section = url.searchParams.get("section") || "students";
  const g = await guard(request, env, { section });
  if (g.error) return g.error;
  const key = kvKeys(section).history;

  if (request.method === "GET") {
    let list = [];
    try { list = JSON.parse((await env.INTERCEDE_KV.get(key)) || "[]"); } catch (_e) { list = []; }
    return json(Array.isArray(list) ? list : []);
  }

  if (request.method === "POST") {
    const body = await request.text();
    if (body.length > 200_000) return json({ error: "Too large" }, 413);
    try {
      const parsed = JSON.parse(body);
      if (!Array.isArray(parsed)) throw new Error("not array");
      // Keep up to 52 weeks for streak tracking, and only the fields the app uses.
      const clean = parsed.slice(0, 52).filter(e => e && typeof e === "object").map(e => {
        const o = {};
        for (const f of FIELDS) if (e[f] !== undefined) o[f] = e[f];
        return o;
      });
      await env.INTERCEDE_KV.put(key, JSON.stringify(clean));
      return json({ ok: true });
    } catch (_e) {
      return json({ error: "Invalid JSON" }, 400);
    }
  }

  return json({ error: "Method not allowed" }, 405);
}
