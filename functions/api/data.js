import { guard, json, kvKeys, scrubPeople, readSettings } from "../../server/access.js";

const MAX_BODY = 1_000_000;
const MAX_PEOPLE = 2000;

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === "OPTIONS") return new Response(null, { status: 204 });

  const url = new URL(request.url);
  const key = url.searchParams.get("key") || "people";

  /* Ministry name + subtitle. Anyone signed in may read; only admins may change. */
  if (key === "settings") {
    if (request.method === "GET") {
      const g = await guard(request, env);
      if (g.error) return g.error;
      const s = await readSettings(env);
      return json(s);
    }
    if (request.method === "POST") {
      const g = await guard(request, env, { admin: true });
      if (g.error) return g.error;
      const body = await request.text();
      if (body.length > 5000) return json({ error: "Too large" }, 413);
      try {
        const p = JSON.parse(body);
        const name = String(p.name || "").trim().slice(0, 80);
        if (!name) return json({ error: "Name required" }, 400);
        const sub = String(p.sub || "").trim().slice(0, 80);
        await env.INTERCEDE_KV.put("settings", JSON.stringify({ name, sub }));
        return json({ ok: true });
      } catch (_e) {
        return json({ error: "Invalid JSON" }, 400);
      }
    }
    return json({ error: "Method not allowed" }, 405);
  }

  /* People for one section. */
  const section = url.searchParams.get("section") || "students";
  const g = await guard(request, env, { section });
  if (g.error) return g.error;
  const keys = kvKeys(section);

  if (request.method === "GET") {
    let list = [];
    try { list = JSON.parse((await env.INTERCEDE_KV.get(keys.people)) || "[]"); } catch (_e) { list = []; }
    return json(scrubPeople(list, section));
  }

  if (request.method === "POST") {
    const body = await request.text();
    if (body.length > MAX_BODY) return json({ error: "Too large" }, 413);
    let incoming, force;
    try {
      const parsed = JSON.parse(body);
      if (Array.isArray(parsed)) { incoming = parsed; force = false; }
      else { incoming = parsed.data; force = parsed.force === true; }
      if (!Array.isArray(incoming)) throw new Error("not array");
    } catch (_e) {
      return json({ error: "Invalid JSON" }, 400);
    }

    incoming = scrubPeople(incoming, section);
    if (incoming.length === 0) return json({ error: "Refusing to store empty data" }, 400);
    if (incoming.length > MAX_PEOPLE) return json({ error: "Too many people" }, 413);

    if (force) {
      if (!g.user.isAdmin) return json({ error: "admin_only" }, 403);
      await env.INTERCEDE_KV.put(keys.people, JSON.stringify(incoming));
      return json({ ok: true, count: incoming.length, forced: true });
    }

    let stored = [];
    try { stored = scrubPeople(JSON.parse((await env.INTERCEDE_KV.get(keys.people)) || "[]"), section); } catch (_e) { stored = []; }

    const storedMap = Object.fromEntries(stored.map(p => [p.id, p]));
    const incomingIds = new Set(incoming.map(p => p.id));
    const merged = incoming.map(p => {
      const s = storedMap[p.id];
      if (!s) return p;
      return (p.updatedAt || 0) >= (s.updatedAt || 0) ? p : s;
    });
    for (const s of stored) if (!incomingIds.has(s.id)) merged.push(s);

    await env.INTERCEDE_KV.put(keys.people, JSON.stringify(merged.slice(0, MAX_PEOPLE)));
    return json({ ok: true, count: merged.length });
  }

  return json({ error: "Method not allowed" }, 405);
}
