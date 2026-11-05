// Shared server helpers: verified sign-in (Cloudflare Access), sections, access lists, privacy rules.
// Nothing here trusts the browser. Every API route calls guard() before touching data.

export const SECTIONS = {
  students: {
    label: "Students", minors: true,
    features: { birthdays: true, grades: true, requests: true, groups: true },
  },
  kids: {
    label: "Kids", minors: true,
    features: { birthdays: false, grades: false, requests: false, groups: false },
  },
  board: {
    label: "Board", minors: false,
    features: { birthdays: false, grades: false, requests: false, groups: false },
  },
  staff: {
    label: "Staff", minors: false,
    features: { birthdays: false, grades: false, requests: false, groups: false },
  },
};
export const SECTION_IDS = Object.keys(SECTIONS);

// The original single list lives under the old keys, so existing Students data keeps working untouched.
export function kvKeys(section) {
  return section === "students"
    ? { people: "people", history: "week_history" }
    : { people: `people:${section}`, history: `week_history:${section}` };
}

export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

/* ── Email lists ───────────────────────────────────────── */

const EMAIL_RE = /^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/;

export function cleanEmailList(list) {
  const seen = new Set();
  for (const raw of Array.isArray(list) ? list : []) {
    const e = String(raw || "").trim().toLowerCase();
    if (e.length <= 254 && EMAIL_RE.test(e)) seen.add(e);
  }
  return Array.from(seen).slice(0, 200);
}

export function adminEmails(env) {
  return cleanEmailList(String(env.ADMIN_EMAILS || "").split(/[\s,;]+/));
}

export async function loadAccess(env) {
  let raw = null;
  try { raw = JSON.parse((await env.INTERCEDE_KV.get("access")) || "null"); } catch (_e) { raw = null; }
  const out = {};
  for (const id of SECTION_IDS) out[id] = cleanEmailList(raw && raw[id]);
  return out;
}

export function sectionsFor(email, admins, access) {
  if (admins.includes(email)) return SECTION_IDS.slice();
  return SECTION_IDS.filter(id => (access[id] || []).includes(email));
}

export function publicSection(id) {
  const s = SECTIONS[id];
  return { id, label: s.label, minors: s.minors, features: s.features };
}

/* ── Cloudflare Access sign-in check ───────────────────── */

const TEAM_RE = /^[a-z0-9-]+\.cloudflareaccess\.com$/;

export function normalizeTeam(v) {
  const t = String(v || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  return TEAM_RE.test(t) ? t : "";
}

export function configProblem(env) {
  const missing = [];
  if (!normalizeTeam(env.ACCESS_TEAM_DOMAIN)) missing.push("ACCESS_TEAM_DOMAIN");
  if (!String(env.ACCESS_AUD || "").trim()) missing.push("ACCESS_AUD");
  if (adminEmails(env).length === 0) missing.push("ADMIN_EMAILS");
  if (!env.INTERCEDE_KV) missing.push("INTERCEDE_KV");
  return missing.length ? missing : null;
}

function b64urlToBytes(s) {
  const b = atob(String(s).replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(String(s).length / 4) * 4, "="));
  return Uint8Array.from(b, c => c.charCodeAt(0));
}

const jwksCache = { team: "", at: 0, keys: null };

async function fetchJwks(team, fetchFn, force) {
  const fresh = jwksCache.team === team && jwksCache.keys && Date.now() - jwksCache.at < 3600_000;
  if (fresh && !force) return jwksCache.keys;
  const res = await fetchFn(`https://${team}/cdn-cgi/access/certs`);
  if (!res.ok) throw new Error("certs fetch failed");
  const body = await res.json();
  jwksCache.team = team; jwksCache.at = Date.now(); jwksCache.keys = Array.isArray(body.keys) ? body.keys : [];
  return jwksCache.keys;
}

export function resetJwksCache() { jwksCache.team = ""; jwksCache.at = 0; jwksCache.keys = null; }

// Returns the signed-in email, or null if the token is missing, forged, expired or meant for another app.
export async function verifyAccessJwt(token, env, fetchFn = fetch, nowMs = Date.now()) {
  try {
    const team = normalizeTeam(env.ACCESS_TEAM_DOMAIN);
    const aud = String(env.ACCESS_AUD || "").trim();
    if (!token || !team || !aud) return null;
    const parts = String(token).split(".");
    if (parts.length !== 3) return null;
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
    if (header.alg !== "RS256" || !header.kid) return null;

    let key = (await fetchJwks(team, fetchFn, false)).find(k => k.kid === header.kid);
    if (!key) key = (await fetchJwks(team, fetchFn, true)).find(k => k.kid === header.kid);
    if (!key) return null;

    const cryptoKey = await crypto.subtle.importKey(
      "jwk", key, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
    );
    const ok = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5", cryptoKey, b64urlToBytes(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
    );
    if (!ok) return null;

    const p = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1])));
    const now = Math.floor(nowMs / 1000);
    if (p.iss !== `https://${team}`) return null;
    const auds = Array.isArray(p.aud) ? p.aud : [p.aud];
    if (!auds.includes(aud)) return null;
    if (typeof p.exp !== "number" || p.exp <= now) return null;
    if (typeof p.nbf === "number" && p.nbf > now + 60) return null;
    const email = String(p.email || "").trim().toLowerCase();
    return EMAIL_RE.test(email) ? email : null;
  } catch (_e) {
    return null;
  }
}

function tokenFrom(request) {
  const h = request.headers.get("Cf-Access-Jwt-Assertion");
  if (h) return h;
  const m = (request.headers.get("Cookie") || "").match(/(?:^|;\s*)CF_Authorization=([^;]+)/);
  return m ? m[1] : "";
}

// Single entry point for every API route. Returns { user } on success or { error: Response }.
export async function guard(request, env, { section = null, admin = false, fetchFn = fetch } = {}) {
  const problem = configProblem(env);
  if (problem) return { error: json({ error: "login_not_configured", missing: problem }, 503) };

  const email = await verifyAccessJwt(tokenFrom(request), env, fetchFn);
  if (!email) return { error: json({ error: "not_signed_in" }, 401) };

  const admins = adminEmails(env);
  const access = await loadAccess(env);
  const isAdmin = admins.includes(email);
  const sections = sectionsFor(email, admins, access);

  if (admin && !isAdmin) return { error: json({ error: "admin_only" }, 403) };
  if (section !== null) {
    if (!SECTIONS[section]) return { error: json({ error: "unknown_section" }, 400) };
    if (!sections.includes(section)) return { error: json({ error: "no_access" }, 403) };
  }
  return { user: { email, isAdmin, sections, access } };
}

export async function readSettings(env) {
  try {
    const s = JSON.parse((await env.INTERCEDE_KV.get("settings")) || "null");
    if (!s || !String(s.name || "").trim()) return null;
    return { name: String(s.name), sub: String(s.sub || "") }; // never includes the old admin password
  } catch (_e) { return null; }
}

/* ── Privacy rules ─────────────────────────────────────── */

const SUFFIXES = new Set(["jr", "sr", "ii", "iii", "iv", "v"]);

// "Delaney Roberts" -> "Delaney R."   "Roberts, Delaney" -> "Delaney R."   safe to apply twice.
export function maskMinorName(name) {
  let s = String(name || "").replace(/\s+/g, " ").trim();
  if (!s) return "";
  let first, last;
  if (s.includes(",")) {
    const [l, ...rest] = s.split(",");
    last = l.trim();
    first = rest.join(" ").trim().split(" ")[0] || "";
  } else {
    const parts = s.split(" ").filter(Boolean);
    while (parts.length > 2 && SUFFIXES.has(parts[parts.length - 1].replace(/\./g, "").toLowerCase())) parts.pop();
    if (parts.length === 1) return parts[0];
    first = parts[0];
    last = parts[parts.length - 1];
  }
  const initial = (last.match(/\p{L}/u) || [""])[0].toUpperCase();
  return initial ? `${first} ${initial}.` : first;
}

export function scrubPerson(p, sectionId) {
  if (!p || typeof p !== "object") return null;
  const s = SECTIONS[sectionId];
  const out = { ...p };
  delete out.photo; delete out.phone; delete out.email;
  if (s.minors) out.name = maskMinorName(out.name);
  if (!s.features.birthdays) delete out.birthday;
  if (!s.features.grades) delete out.grade;
  if (!s.features.requests) delete out.prayerRequests;
  return out;
}

export function scrubPeople(list, sectionId) {
  return (Array.isArray(list) ? list : []).map(p => scrubPerson(p, sectionId)).filter(p => p && p.id && p.name);
}
