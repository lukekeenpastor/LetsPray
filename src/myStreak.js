// Personal prayer streak.
// Counts consecutive days on which this device marked at least one person as prayed for.
// Stored only on the leader's own phone (localStorage), so no login is needed.
// Clearing browser data or switching phones starts the streak over.

const KEY = "letspray-my-prayer-days";
const MAX_DAYS = 730;

function pad(n) { return String(n).padStart(2, "0"); }

export function dayKey(date = new Date()) {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

function shiftDays(date, delta) {
  const d = new Date(date.getFullYear(), date.getMonth(), date.getDate(), 12);
  d.setDate(d.getDate() + delta);
  return d;
}

function parseKey(k) {
  const [y, m, d] = k.split("-").map(Number);
  return new Date(y, m - 1, d, 12);
}

export function loadMyDays() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.filter(k => typeof k === "string" && /^\d{4}-\d{2}-\d{2}$/.test(k)) : [];
  } catch (_e) { return []; }
}

export function saveMyDays(days) {
  try { localStorage.setItem(KEY, JSON.stringify(days)); } catch (_e) {}
}

// Returns a new sorted array that includes today's date.
export function addPrayerDay(days, now = new Date()) {
  const set = new Set(days);
  set.add(dayKey(now));
  return Array.from(set).sort().slice(-MAX_DAYS);
}

// current: days in a row, still alive if the leader prayed today or yesterday.
// best: longest run ever recorded on this device.
// today: whether the leader has already prayed today.
export function computeMyStreak(days, now = new Date()) {
  const set = new Set(days);
  const todayKey = dayKey(now);
  const today = set.has(todayKey);
  let cursor = null;
  if (today) cursor = shiftDays(now, 0);
  else if (set.has(dayKey(shiftDays(now, -1)))) cursor = shiftDays(now, -1);

  let current = 0;
  while (cursor && set.has(dayKey(cursor))) {
    current++;
    cursor = shiftDays(cursor, -1);
  }

  let best = 0, run = 0, prev = null;
  for (const k of Array.from(set).sort()) {
    const d = parseKey(k);
    run = prev && Math.round((d - prev) / 86400000) === 1 ? run + 1 : 1;
    if (run > best) best = run;
    prev = d;
  }
  return { current, best, today };
}
