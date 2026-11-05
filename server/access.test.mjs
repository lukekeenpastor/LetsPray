// Run with:  node server/access.test.mjs
// Exercises sign-in verification, section isolation, access lists and privacy rules with no network.
import { onRequest as dataRoute } from "../functions/api/data.js";
import { onRequest as historyRoute } from "../functions/api/history.js";
import { onRequest as meRoute } from "../functions/api/me.js";
import { onRequest as accessRoute } from "../functions/api/access.js";
import { maskMinorName, resetJwksCache } from "./access.js";

let failed = 0;
const ok = (cond, msg) => { if (!cond) { failed++; console.log("FAIL", msg); } else console.log("ok  ", msg); };

const TEAM = "testchurch.cloudflareaccess.com";
const AUD = "app-aud-123";
const b64u = (buf) => Buffer.from(buf).toString("base64url");

async function makeKey(kid) {
  const kp = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  return { kid, priv: kp.privateKey, jwk: { ...jwk, kid, alg: "RS256", use: "sig" } };
}
async function mint(key, claims = {}, headerOver = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", kid: key.kid, typ: "JWT", ...headerOver };
  const payload = { iss: `https://${TEAM}`, aud: [AUD], exp: now + 600, iat: now, email: "x@example.org", ...claims };
  const data = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key.priv, new TextEncoder().encode(data));
  return `${data}.${b64u(sig)}`;
}

const good = await makeKey("kid-good");
const evil = await makeKey("kid-good"); // attacker key claiming the same kid
globalThis.fetch = async (url) => {
  if (String(url) === `https://${TEAM}/cdn-cgi/access/certs`) return new Response(JSON.stringify({ keys: [good.jwk] }));
  return new Response("nope", { status: 404 });
};

function makeKV(seed = {}) {
  const m = new Map(Object.entries(seed));
  return { get: async (k) => (m.has(k) ? m.get(k) : null), put: async (k, v) => { m.set(k, v); }, _m: m };
}
const baseEnv = (kv) => ({ ACCESS_TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD, ADMIN_EMAILS: "pastor@church.org", INTERCEDE_KV: kv });

async function call(route, env, { path, method = "GET", token, body, headers = {} }) {
  const h = new Headers(headers);
  if (token) h.set("Cf-Access-Jwt-Assertion", token);
  const req = new Request(`https://site.example${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  const res = await route({ request: req, env });
  let data = null; try { data = await res.json(); } catch (_e) {}
  return { status: res.status, data };
}

const admin = await mint(good, { email: "Pastor@Church.org" });   // mixed case on purpose
const leaderKids = await mint(good, { email: "kidsleader@gmail.com" });
const stranger = await mint(good, { email: "random@gmail.com" });

/* --- configuration --- */
{
  const r = await call(meRoute, { INTERCEDE_KV: makeKV() }, { path: "/api/me", token: admin });
  ok(r.status === 503 && r.data.error === "login_not_configured", "fails closed when Cloudflare Access variables are missing");
}

const kv = makeKV({
  settings: JSON.stringify({ name: "Faith Youth", sub: "Let's Pray", password: "hunter22" }),
  people: JSON.stringify([
    { id: "s1", name: "Delaney Roberts", type: "student", grade: 9, birthday: "3-14", prayerRequests: [{ text: "exam" }], updatedAt: 1 },
  ]),
});
const env = baseEnv(kv);

/* --- sign-in verification --- */
{
  resetJwksCache();
  ok((await call(meRoute, env, { path: "/api/me" })).status === 401, "no token is rejected");
  ok((await call(meRoute, env, { path: "/api/me", headers: { "Cf-Access-Authenticated-User-Email": "pastor@church.org" } })).status === 401, "spoofed email header alone is rejected");
  const forged = await mint(evil, { email: "pastor@church.org" });
  ok((await call(meRoute, env, { path: "/api/me", token: forged })).status === 401, "token signed with a different key is rejected");
  ok((await call(meRoute, env, { path: "/api/me", token: await mint(good, { email: "pastor@church.org", aud: ["other"] }) })).status === 401, "wrong audience is rejected");
  ok((await call(meRoute, env, { path: "/api/me", token: await mint(good, { email: "pastor@church.org", iss: "https://evil.cloudflareaccess.com" }) })).status === 401, "wrong issuer is rejected");
  ok((await call(meRoute, env, { path: "/api/me", token: await mint(good, { email: "pastor@church.org", exp: Math.floor(Date.now() / 1000) - 5 }) })).status === 401, "expired token is rejected");
  ok((await call(meRoute, env, { path: "/api/me", token: await mint(good, { email: "pastor@church.org" }, { alg: "none" }) })).status === 401, "alg none is rejected");
  const tampered = (await mint(good, { email: "random@gmail.com" })).split(".");
  tampered[1] = b64u(JSON.stringify({ iss: `https://${TEAM}`, aud: [AUD], exp: Math.floor(Date.now() / 1000) + 600, email: "pastor@church.org" }));
  ok((await call(meRoute, env, { path: "/api/me", token: tampered.join(".") })).status === 401, "edited payload with the old signature is rejected");
  ok((await call(meRoute, env, { path: "/api/me", token: "garbage" })).status === 401, "garbage token is rejected");
}

/* --- admin and strangers --- */
{
  const me = await call(meRoute, env, { path: "/api/me", token: admin });
  ok(me.status === 200 && me.data.isAdmin && me.data.sections.length === 4, "admin (any email case) sees all four sections");
  ok(JSON.stringify(me.data).indexOf("hunter22") === -1, "old admin password is never sent to the browser");
  ok(me.data.settings && me.data.settings.name === "Faith Youth", "settings come back without password");

  const s = await call(meRoute, env, { path: "/api/me", token: stranger });
  ok(s.status === 200 && s.data.sections.length === 0 && !s.data.isAdmin, "unlisted person gets zero sections");
  ok((await call(dataRoute, env, { path: "/api/data?section=students", token: stranger })).status === 403, "unlisted person cannot read students");
  ok((await call(dataRoute, env, { path: "/api/data", token: stranger })).status === 403, "default section is still protected");
  ok((await call(historyRoute, env, { path: "/api/history?section=students", token: stranger })).status === 403, "unlisted person cannot read history");
  ok((await call(accessRoute, env, { path: "/api/access", token: stranger })).status === 403, "unlisted person cannot read access lists");
  ok((await call(dataRoute, env, { path: "/api/data?key=settings", method: "POST", token: stranger, body: { name: "Hacked" } })).status === 403, "unlisted person cannot change settings");
}

/* --- access lists --- */
{
  const save = await call(accessRoute, env, { path: "/api/access", method: "POST", token: admin, body: { kids: ["KidsLeader@gmail.com", "bad-email", "kidsleader@gmail.com"], staff: ["a@b.org"], unknown: ["z@z.org"] } });
  ok(save.status === 200 && save.data.access.kids.length === 1 && save.data.access.kids[0] === "kidsleader@gmail.com", "access lists are cleaned and de-duplicated");
  ok(!("unknown" in save.data.access), "unknown sections are ignored");
  ok((await call(accessRoute, env, { path: "/api/access", method: "POST", token: leaderKids, body: { kids: ["x@y.org"] } })).status === 403, "a leader cannot edit access lists");

  const me = await call(meRoute, env, { path: "/api/me", token: leaderKids });
  ok(me.data.sections.length === 1 && me.data.sections[0].id === "kids" && !me.data.isAdmin, "kids leader sees only Kids");
}

/* --- section isolation and privacy rules --- */
{
  const g1 = await call(dataRoute, env, { path: "/api/data?section=students", token: leaderKids });
  const g2 = await call(dataRoute, env, { path: "/api/data?section=board", token: leaderKids });
  ok(g1.status === 403 && g2.status === 403, "kids leader is blocked from students and board");
  ok((await call(dataRoute, env, { path: "/api/data?section=bogus", token: admin })).status === 400, "unknown section is rejected");

  const post = await call(dataRoute, env, {
    path: "/api/data?section=kids", method: "POST", token: leaderKids,
    body: [{ id: "k1", name: "Maya Thompson", type: "member", birthday: "5-5", grade: 2, prayerRequests: [{ text: "x" }], phone: "555", updatedAt: 5 }],
  });
  ok(post.status === 200, "kids leader can save to Kids");
  const stored = JSON.parse(kv._m.get("people:kids"));
  ok(stored[0].name === "Maya T.", "minor name stored as first name + last initial");
  ok(!("birthday" in stored[0]) && !("grade" in stored[0]) && !("prayerRequests" in stored[0]) && !("phone" in stored[0]), "birthday, grade, requests and phone are stripped from Kids");
  ok(kv._m.get("people:board") === undefined && kv._m.get("people:staff") === undefined, "Kids data did not land in other sections");

  const force = await call(dataRoute, env, { path: "/api/data?section=kids", method: "POST", token: leaderKids, body: { force: true, data: [{ id: "k2", name: "Solo Kid", updatedAt: 1 }] } });
  ok(force.status === 403, "a leader cannot force-overwrite a roster");
  const forceAdmin = await call(dataRoute, env, { path: "/api/data?section=kids", method: "POST", token: admin, body: { force: true, data: [{ id: "k2", name: "Solo Kid", updatedAt: 1 }] } });
  ok(forceAdmin.status === 200, "admin can force-overwrite a roster");

  const board = await call(dataRoute, env, { path: "/api/data?section=board", method: "POST", token: admin, body: [{ id: "b1", name: "Robert Alan Jones", updatedAt: 1 }] });
  ok(board.status === 200 && JSON.parse(kv._m.get("people:board"))[0].name === "Robert Alan Jones", "adult sections keep full names");

  const students = await call(dataRoute, env, { path: "/api/data?section=students", token: admin });
  ok(students.data[0].name === "Delaney R.", "old stored full names are masked before leaving the server (Students)");
  ok(students.data[0].birthday === "3-14" && students.data[0].grade === 9 && students.data[0].prayerRequests.length === 1, "Students keeps birthdays, grades and requests");
  ok(JSON.parse(kv._m.get("people"))[0].name === "Delaney Roberts", "reading does not rewrite stored data");

  const hist = await call(historyRoute, env, { path: "/api/history?section=kids", method: "POST", token: leaderKids, body: [{ weekStart: 1, prevWeekStart: 0, prevWeekDateStr: "1/1/2026", count: 3, total: 5, evil: "<script>" }] });
  ok(hist.status === 200 && !("evil" in JSON.parse(kv._m.get("week_history:kids"))[0]), "history keeps only known fields, per section");
  ok(kv._m.get("week_history") === undefined, "Kids history did not touch Students history");

  const setName = await call(dataRoute, env, { path: "/api/data?key=settings", method: "POST", token: admin, body: { name: "Quincy Faith", sub: "Pray", password: "ignored" } });
  ok(setName.status === 200 && !("password" in JSON.parse(kv._m.get("settings"))), "saving settings drops the old password");
}

/* --- name masking --- */
{
  const cases = [
    ["Delaney Roberts", "Delaney R."], ["Delaney R.", "Delaney R."], ["roberts, delaney", "delaney R."],
    ["Mary Ann Smith", "Mary S."], ["Alex Rivera Jr.", "Alex R."], ["Cher", "Cher"], ["  Sam   Okafor ", "Sam O."],
    ["Zoë Émile", "Zoë É."], ["", ""],
  ];
  for (const [i, o] of cases) ok(maskMinorName(i) === o, `mask "${i}" -> "${o}" (got "${maskMinorName(i)}")`);
  ok(maskMinorName(maskMinorName("Mary Ann Smith")) === "Mary S.", "masking twice changes nothing");
}

console.log(failed ? `\n${failed} FAILED` : "\nALL PASSED");
process.exit(failed ? 1 : 0);
