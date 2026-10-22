// clock — the whole API of the NFC attendance clock as one Supabase Edge Function.
// Deployed with --no-verify-jwt (the project signs ES256 JWTs the gateway cannot verify, same as
// every mb-* function); nothing here uses Supabase Auth. Three secrets authenticate everything:
//   x-admin-key   : the manager's dashboard link  (clock.orgs.admin_key)
//   x-worker-token: the phone's binding, minted by POST /bind from a personal install link
//                   (stored as sha256 in clock.workers.device_token_hash)
//   install_key   : the personal install link itself (clock.workers.install_key)
// CORS is "*": the API never relies on cookies, so cross-origin reads carry no ambient authority.
//
// Routes (all JSON unless noted):
//   POST /signup                 {org_name}                      → {admin_key, org}
//   POST /bind                   {install_key}                   → {token, worker, org}
//   GET  /me                     worker                          → {worker, org, today}
//   POST /tap                    worker {code, lat?, lng?, accuracy?} → {event, today, dup}
//   POST /out                    worker                          → {event, today}
//   GET  /admin/overview         admin                           → {org, workers, tags}
//   POST /admin/workers          admin {name, phone?}            → {worker}
//   PATCH /admin/workers/:id     admin {name?, phone?, active?, unbind?} → {worker}
//   POST /admin/tags             admin {location, lat?, lng?, radius_m?} → {tag}
//   PATCH /admin/tags/:id        admin {location?, lat?, lng?, radius_m?} → {tag}
//   DELETE /admin/tags/:id       admin                           → {ok}
//   GET  /admin/events?from&to[&format=csv]  admin               → {events} | text/csv
//   POST /admin/events           admin {worker_id, kind, ts?, note?} → {event}   (manual fix)
//   DELETE /admin/events/:id     admin                           → {ok}
import { createClient } from "npm:@supabase/supabase-js@2.116.0";

const sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  db: { schema: "clock" },
  auth: { persistSession: false, autoRefreshToken: false },
});

const CORS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "content-type, x-admin-key, x-worker-token, authorization, apikey, x-client-info",
  "Access-Control-Max-Age": "86400",
};
const BODY_CAP = 8192;
const KEY_RE = /^[A-Za-z0-9_-]{40,48}$/;
const CODE_RE = /^[A-Z2-9]{6,12}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DUP_WINDOW_MS = 2 * 60 * 1000;
const DEFAULT_TZ = "Asia/Jerusalem";

type Json = Record<string, unknown>;
type Org = { id: string; name: string; admin_key?: string; tz: string; created_at: string };
type Worker = {
  id: string; org_id: string; name: string; phone: string | null; install_key?: string;
  device_token_hash?: string | null; bound_at: string | null; link_opened_at: string | null; active: boolean; created_at: string;
};
type Tag = { id: string; org_id: string; code: string; location: string; lat: number | null; lng: number | null; radius_m: number; created_at: string };

class HttpError extends Error {
  constructor(public status: number, public code: string, public detail?: string) { super(code); }
}

function json(status: number, body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra },
  });
}
const fail = (status: number, code: string, detail?: string) => new HttpError(status, code, detail);

async function sha256(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function randKey(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function clientIp(req: Request): string {
  const xf = req.headers.get("x-forwarded-for") ?? "";
  return xf.split(",")[0].trim() || "unknown";
}

// ---- rate limit (per isolate; good enough to blunt abuse, not a security boundary) ----
const buckets = new Map<string, { n: number; reset: number }>();
function rateLimit(key: string, max: number, windowMs: number) {
  const now = Date.now();
  const b = buckets.get(key);
  if (!b || b.reset < now) { buckets.set(key, { n: 1, reset: now + windowMs }); return; }
  if (++b.n > max) throw fail(429, "rate_limited");
  if (buckets.size > 5000) for (const [k, v] of buckets) if (v.reset < now) buckets.delete(k);
}

async function readBody(req: Request): Promise<Json> {
  const len = Number(req.headers.get("content-length") ?? "0");
  if (len > BODY_CAP) throw fail(413, "body_too_large");
  const text = await req.text();
  if (text.length > BODY_CAP) throw fail(413, "body_too_large");
  if (!text.trim()) return {};
  try { const v = JSON.parse(text); return v && typeof v === "object" && !Array.isArray(v) ? v : {}; } catch { throw fail(400, "bad_json"); }
}
function str(v: unknown, max: number, field: string, required = false): string | null {
  if (v == null || v === "") { if (required) throw fail(400, "missing_" + field); return null; }
  if (typeof v !== "string") throw fail(400, "bad_" + field);
  const s = v.replace(/[\u0000-\u001f\u007f]/g, "").trim();
  if (!s && required) throw fail(400, "missing_" + field);
  if (s.length > max) throw fail(400, "too_long_" + field);
  return s || null;
}
function num(v: unknown, min: number, max: number, field: string): number | null {
  if (v == null || v === "") return null;
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n) || n < min || n > max) throw fail(400, "bad_" + field);
  return n;
}

// ---- time zone helpers (org day boundaries) ----
function tzParts(d: Date, tz: string) {
  const p = new Intl.DateTimeFormat("en-CA", { timeZone: tz, hour12: false, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" })
    .formatToParts(d).reduce((o, x) => (o[x.type] = x.value, o), {} as Record<string, string>);
  return { y: +p.year, m: +p.month, d: +p.day, hh: +p.hour % 24, mm: +p.minute, ss: +p.second };
}
function localDate(d: Date, tz: string): string {
  const p = tzParts(d, tz);
  return `${p.y}-${String(p.m).padStart(2, "0")}-${String(p.d).padStart(2, "0")}`;
}
/** UTC instant of local midnight of YYYY-MM-DD in tz. */
function zonedMidnight(date: string, tz: string): Date {
  const [y, m, d] = date.split("-").map(Number);
  let guess = Date.UTC(y, m - 1, d, 0, 0, 0);
  for (let i = 0; i < 3; i++) {
    const p = tzParts(new Date(guess), tz);
    const asUtc = Date.UTC(p.y, p.m - 1, p.d, p.hh, p.mm, p.ss);
    const diff = asUtc - guess; // tz offset in ms at the guess
    const target = Date.UTC(y, m - 1, d, 0, 0, 0);
    const next = target - diff;
    if (next === guess) break;
    guess = next;
  }
  return new Date(guess);
}
function validDate(s: unknown): string | null {
  if (typeof s !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  return isNaN(Date.parse(s + "T00:00:00Z")) ? null : s;
}
function haversineM(lat1: number, lng1: number, lat2: number, lng2: number): number {
  const R = 6371000, toR = (x: number) => (x * Math.PI) / 180;
  const dLat = toR(lat2 - lat1), dLng = toR(lng2 - lng1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toR(lat1)) * Math.cos(toR(lat2)) * Math.sin(dLng / 2) ** 2;
  return Math.round(2 * R * Math.asin(Math.sqrt(a)));
}

// ---- auth ----
async function requireAdmin(req: Request): Promise<Org> {
  const key = req.headers.get("x-admin-key") ?? "";
  if (!KEY_RE.test(key)) throw fail(401, "admin_key_required");
  const { data, error } = await sb.from("orgs").select("id,name,tz,created_at").eq("admin_key", key).maybeSingle();
  if (error) throw fail(500, "db", error.message);
  if (!data) throw fail(401, "admin_key_invalid");
  return data as Org;
}
async function requireWorker(req: Request): Promise<{ worker: Worker; org: Org }> {
  const tok = req.headers.get("x-worker-token") ?? "";
  if (!KEY_RE.test(tok)) throw fail(401, "not_bound");
  const h = await sha256(tok);
  const { data, error } = await sb.from("workers").select("id,org_id,name,phone,bound_at,link_opened_at,active,created_at, orgs(id,name,tz,created_at)")
    .eq("device_token_hash", h).maybeSingle();
  if (error) throw fail(500, "db", error.message);
  if (!data) throw fail(401, "not_bound");
  const { orgs, ...worker } = data as unknown as Worker & { orgs: Org };
  if (!worker.active) throw fail(403, "worker_inactive");
  return { worker, org: orgs };
}

// ---- event shaping ----
type EventRow = {
  id: number; worker_id: string; tag_id: string | null; kind: string; ts: string; lat: number | null; lng: number | null;
  accuracy_m: number | null; distance_m: number | null; flags: string[]; source: string; note: string | null;
  workers?: { name: string } | null; tags?: { location: string; code: string } | null;
};
const EVENT_SEL = "id,worker_id,tag_id,kind,ts,lat,lng,accuracy_m,distance_m,flags,source,note,workers(name),tags(location,code)";
function shapeEvent(e: EventRow, tz: string) {
  const d = new Date(e.ts);
  const p = tzParts(d, tz);
  return {
    id: e.id, worker_id: e.worker_id, worker: e.workers?.name ?? null, tag_id: e.tag_id,
    location: e.kind === "out" ? null : (e.tags?.location ?? null), kind: e.kind, ts: e.ts,
    date: localDate(d, tz), time: `${String(p.hh).padStart(2, "0")}:${String(p.mm).padStart(2, "0")}`,
    lat: e.lat, lng: e.lng, accuracy_m: e.accuracy_m, distance_m: e.distance_m, flags: e.flags ?? [], source: e.source, note: e.note,
  };
}
async function todayFor(workerId: string, tz: string) {
  const start = zonedMidnight(localDate(new Date(), tz), tz).toISOString();
  const { data, error } = await sb.from("events").select(EVENT_SEL).eq("worker_id", workerId).gte("ts", start).order("ts", { ascending: true }).limit(200);
  if (error) throw fail(500, "db", error.message);
  return (data as unknown as EventRow[]).map((e) => shapeEvent(e, tz));
}

// ---- handlers ----
async function signup(req: Request) {
  rateLimit("signup:" + clientIp(req), 5, 60 * 60 * 1000);
  const b = await readBody(req);
  const name = str(b.org_name, 80, "org_name", true)!;
  const { data, error } = await sb.from("orgs").insert({ name }).select("id,name,admin_key,tz,created_at").single();
  if (error) throw fail(500, "db", error.message);
  return json(201, { admin_key: data.admin_key, org: { id: data.id, name: data.name, tz: data.tz } });
}

async function bind(req: Request) {
  rateLimit("bind:" + clientIp(req), 30, 10 * 60 * 1000);
  const b = await readBody(req);
  const key = str(b.install_key, 64, "install_key", true)!;
  if (!KEY_RE.test(key)) throw fail(404, "install_key_invalid");
  const { data: w, error } = await sb.from("workers").select("id,org_id,name,active,bound_at, orgs(id,name,tz)").eq("install_key", key).maybeSingle();
  if (error) throw fail(500, "db", error.message);
  if (!w) throw fail(404, "install_key_invalid");
  if (!w.active) throw fail(403, "worker_inactive");
  const token = randKey();
  const now = new Date().toISOString();
  const { error: e2 } = await sb.from("workers").update({ device_token_hash: await sha256(token), bound_at: now, link_opened_at: now }).eq("id", w.id);
  if (e2) throw fail(500, "db", e2.message);
  const org = (w as unknown as { orgs: Org }).orgs;
  return json(200, { token, worker: { id: w.id, name: w.name, rebound: !!w.bound_at }, org: { id: org.id, name: org.name, tz: org.tz } });
}

async function me(req: Request) {
  const { worker, org } = await requireWorker(req);
  return json(200, { worker: { id: worker.id, name: worker.name }, org: { id: org.id, name: org.name, tz: org.tz }, today: await todayFor(worker.id, org.tz) });
}

async function tap(req: Request) {
  rateLimit("tap:" + clientIp(req), 60, 60 * 1000);
  const { worker, org } = await requireWorker(req);
  const b = await readBody(req);
  const code = (str(b.code, 16, "code", true) ?? "").toUpperCase();
  if (!CODE_RE.test(code)) throw fail(404, "tag_unknown");
  const { data: tag, error } = await sb.from("tags").select("id,org_id,code,location,lat,lng,radius_m").eq("code", code).maybeSingle();
  if (error) throw fail(500, "db", error.message);
  if (!tag || tag.org_id !== org.id) throw fail(404, "tag_unknown");
  const lat = num(b.lat, -90, 90, "lat"), lng = num(b.lng, -180, 180, "lng"), acc = num(b.accuracy, 0, 100000, "accuracy");
  const flags: string[] = [];
  let distance: number | null = null;
  if (lat == null || lng == null) flags.push("no_gps");
  else if (tag.lat != null && tag.lng != null) {
    distance = haversineM(lat, lng, tag.lat, tag.lng);
    if (distance > tag.radius_m + Math.min(acc ?? 0, 500)) flags.push("far");
  }
  // the same sticker twice within 2 minutes is one arrival (double tap, page reload)
  const since = new Date(Date.now() - DUP_WINDOW_MS).toISOString();
  const { data: last } = await sb.from("events").select(EVENT_SEL).eq("worker_id", worker.id).eq("tag_id", tag.id).eq("kind", "in").gte("ts", since).order("ts", { ascending: false }).limit(1);
  if (last && last.length) {
    return json(200, { dup: true, event: shapeEvent(last[0] as unknown as EventRow, org.tz), worker: { name: worker.name }, today: await todayFor(worker.id, org.tz) });
  }
  const { data: ev, error: e2 } = await sb.from("events").insert({
    org_id: org.id, worker_id: worker.id, tag_id: tag.id, kind: "in", lat, lng,
    accuracy_m: acc == null ? null : Math.round(acc), distance_m: distance, flags, source: "tap",
  }).select(EVENT_SEL).single();
  if (e2) throw fail(500, "db", e2.message);
  return json(201, { dup: false, event: shapeEvent(ev as unknown as EventRow, org.tz), worker: { name: worker.name }, today: await todayFor(worker.id, org.tz) });
}

async function out(req: Request) {
  rateLimit("out:" + clientIp(req), 60, 60 * 1000);
  const { worker, org } = await requireWorker(req);
  const b = await readBody(req);
  const lat = num(b.lat, -90, 90, "lat"), lng = num(b.lng, -180, 180, "lng"), acc = num(b.accuracy, 0, 100000, "accuracy");
  const since = new Date(Date.now() - DUP_WINDOW_MS).toISOString();
  const { data: last } = await sb.from("events").select(EVENT_SEL).eq("worker_id", worker.id).eq("kind", "out").gte("ts", since).order("ts", { ascending: false }).limit(1);
  if (last && last.length) return json(200, { dup: true, event: shapeEvent(last[0] as unknown as EventRow, org.tz), today: await todayFor(worker.id, org.tz) });
  const { data: ev, error } = await sb.from("events").insert({
    org_id: org.id, worker_id: worker.id, kind: "out", lat, lng, accuracy_m: acc == null ? null : Math.round(acc), flags: lat == null ? ["no_gps"] : [], source: "button",
  }).select(EVENT_SEL).single();
  if (error) throw fail(500, "db", error.message);
  return json(201, { dup: false, event: shapeEvent(ev as unknown as EventRow, org.tz), today: await todayFor(worker.id, org.tz) });
}

async function adminOverview(req: Request) {
  const org = await requireAdmin(req);
  const [w, t, last] = await Promise.all([
    sb.from("workers").select("id,name,phone,install_key,bound_at,link_opened_at,active,created_at").eq("org_id", org.id).order("created_at", { ascending: true }),
    sb.from("tags").select("id,code,location,lat,lng,radius_m,created_at").eq("org_id", org.id).order("created_at", { ascending: true }),
    sb.from("events").select(EVENT_SEL).eq("org_id", org.id).gte("ts", zonedMidnight(localDate(new Date(), org.tz), org.tz).toISOString()).order("ts", { ascending: false }).limit(500),
  ]);
  for (const r of [w, t, last]) if (r.error) throw fail(500, "db", r.error.message);
  // each worker's latest event today → "who is in now"
  const lastBy = new Map<string, ReturnType<typeof shapeEvent>>();
  for (const e of (last.data as unknown as EventRow[])) if (!lastBy.has(e.worker_id)) lastBy.set(e.worker_id, shapeEvent(e, org.tz));
  const workers = (w.data as Worker[]).map((x) => ({ ...x, last: lastBy.get(x.id) ?? null, bound: !!x.bound_at }));
  return json(200, { org, workers, tags: t.data });
}

async function adminWorkerCreate(req: Request) {
  const org = await requireAdmin(req);
  const b = await readBody(req);
  const name = str(b.name, 60, "name", true)!, phone = str(b.phone, 24, "phone");
  const { count } = await sb.from("workers").select("id", { count: "exact", head: true }).eq("org_id", org.id);
  if ((count ?? 0) >= 500) throw fail(400, "too_many_workers");
  const { data, error } = await sb.from("workers").insert({ org_id: org.id, name, phone }).select("id,name,phone,install_key,bound_at,active,created_at").single();
  if (error) throw fail(500, "db", error.message);
  return json(201, { worker: { ...data, bound: false, last: null } });
}

async function adminWorkerPatch(req: Request, id: string) {
  const org = await requireAdmin(req);
  if (!UUID_RE.test(id)) throw fail(404, "not_found");
  const b = await readBody(req);
  const patch: Json = {};
  if (b.name !== undefined) patch.name = str(b.name, 60, "name", true);
  if (b.phone !== undefined) patch.phone = str(b.phone, 24, "phone");
  if (b.active !== undefined) patch.active = !!b.active;
  if (b.unbind === true) { patch.device_token_hash = null; patch.bound_at = null; }
  if (!Object.keys(patch).length) throw fail(400, "nothing_to_change");
  const { data, error } = await sb.from("workers").update(patch).eq("id", id).eq("org_id", org.id).select("id,name,phone,install_key,bound_at,active,created_at").maybeSingle();
  if (error) throw fail(500, "db", error.message);
  if (!data) throw fail(404, "not_found");
  return json(200, { worker: { ...data, bound: !!data.bound_at } });
}

async function adminTagCreate(req: Request) {
  const org = await requireAdmin(req);
  const b = await readBody(req);
  const location = str(b.location, 80, "location", true)!;
  const lat = num(b.lat, -90, 90, "lat"), lng = num(b.lng, -180, 180, "lng"), radius = num(b.radius_m, 20, 5000, "radius_m") ?? 150;
  const { count } = await sb.from("tags").select("id", { count: "exact", head: true }).eq("org_id", org.id);
  if ((count ?? 0) >= 500) throw fail(400, "too_many_tags");
  const { data, error } = await sb.from("tags").insert({ org_id: org.id, location, lat, lng, radius_m: Math.round(radius) }).select("id,code,location,lat,lng,radius_m,created_at").single();
  if (error) throw fail(500, "db", error.message);
  return json(201, { tag: data });
}

async function adminTagPatch(req: Request, id: string) {
  const org = await requireAdmin(req);
  if (!UUID_RE.test(id)) throw fail(404, "not_found");
  const b = await readBody(req);
  const patch: Json = {};
  if (b.location !== undefined) patch.location = str(b.location, 80, "location", true);
  if (b.lat !== undefined) patch.lat = num(b.lat, -90, 90, "lat");
  if (b.lng !== undefined) patch.lng = num(b.lng, -180, 180, "lng");
  if (b.radius_m !== undefined) patch.radius_m = Math.round(num(b.radius_m, 20, 5000, "radius_m") ?? 150);
  if (!Object.keys(patch).length) throw fail(400, "nothing_to_change");
  const { data, error } = await sb.from("tags").update(patch).eq("id", id).eq("org_id", org.id).select("id,code,location,lat,lng,radius_m,created_at").maybeSingle();
  if (error) throw fail(500, "db", error.message);
  if (!data) throw fail(404, "not_found");
  return json(200, { tag: data });
}

async function adminTagDelete(req: Request, id: string) {
  const org = await requireAdmin(req);
  if (!UUID_RE.test(id)) throw fail(404, "not_found");
  const { error } = await sb.from("tags").delete().eq("id", id).eq("org_id", org.id);
  if (error) throw fail(500, "db", error.message);
  return json(200, { ok: true });
}

function csvCell(v: unknown): string {
  const s = v == null ? "" : String(v);
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

async function adminEvents(req: Request, url: URL) {
  const org = await requireAdmin(req);
  const today = localDate(new Date(), org.tz);
  const from = validDate(url.searchParams.get("from")) ?? today;
  const to = validDate(url.searchParams.get("to")) ?? from;
  const start = zonedMidnight(from, org.tz), endExcl = new Date(zonedMidnight(to, org.tz).getTime() + 24 * 3600 * 1000 + 3600 * 1000);
  if (endExcl.getTime() - start.getTime() > 93 * 24 * 3600 * 1000) throw fail(400, "range_too_long");
  // the +1h above only guards DST; filter the exact local day boundary below
  const { data, error } = await sb.from("events").select(EVENT_SEL).eq("org_id", org.id).gte("ts", start.toISOString()).lt("ts", endExcl.toISOString()).order("ts", { ascending: true }).limit(5000);
  if (error) throw fail(500, "db", error.message);
  const rows = (data as unknown as EventRow[]).map((e) => shapeEvent(e, org.tz)).filter((e) => e.date >= from && e.date <= to);
  if (url.searchParams.get("format") === "csv") {
    const head = ["תאריך", "שעה", "שם", "מיקום", "סוג", "מרחק (מ')", "דגלים", "מקור", "הערה"];
    const lines = [head.join(",")];
    for (const r of rows) {
      lines.push([r.date, r.time, r.worker, r.kind === "out" ? "סיום עבודה" : r.location, r.kind === "out" ? "יציאה" : "כניסה", r.distance_m, r.flags.join(" "), r.source, r.note].map(csvCell).join(","));
    }
    return new Response("﻿" + lines.join("\r\n") + "\r\n", {
      status: 200,
      headers: { ...CORS, "Content-Type": "text/csv; charset=utf-8", "Cache-Control": "no-store", "Content-Disposition": `attachment; filename="attendance-${from}-${to}.csv"` },
    });
  }
  return json(200, { from, to, tz: org.tz, events: rows });
}

async function adminEventCreate(req: Request) {
  const org = await requireAdmin(req);
  const b = await readBody(req);
  const workerId = str(b.worker_id, 40, "worker_id", true)!;
  if (!UUID_RE.test(workerId)) throw fail(404, "worker_not_found");
  const kind = b.kind === "out" ? "out" : b.kind === "in" ? "in" : null;
  if (!kind) throw fail(400, "bad_kind");
  const { data: w } = await sb.from("workers").select("id").eq("id", workerId).eq("org_id", org.id).maybeSingle();
  if (!w) throw fail(404, "worker_not_found");
  let tagId: string | null = null;
  if (kind === "in") {
    const t = str(b.tag_id, 40, "tag_id");
    if (t) {
      if (!UUID_RE.test(t)) throw fail(404, "tag_unknown");
      const { data: tg } = await sb.from("tags").select("id").eq("id", t).eq("org_id", org.id).maybeSingle();
      if (!tg) throw fail(404, "tag_unknown");
      tagId = t;
    }
  }
  let ts = new Date();
  if (b.ts != null) { ts = new Date(String(b.ts)); if (isNaN(ts.getTime())) throw fail(400, "bad_ts"); }
  const { data, error } = await sb.from("events").insert({ org_id: org.id, worker_id: workerId, tag_id: tagId, kind, ts: ts.toISOString(), source: "manual", note: str(b.note, 200, "note") })
    .select(EVENT_SEL).single();
  if (error) throw fail(500, "db", error.message);
  return json(201, { event: shapeEvent(data as unknown as EventRow, org.tz) });
}

async function adminEventDelete(req: Request, id: string) {
  const org = await requireAdmin(req);
  if (!/^\d{1,18}$/.test(id)) throw fail(404, "not_found");
  const { error } = await sb.from("events").delete().eq("id", Number(id)).eq("org_id", org.id);
  if (error) throw fail(500, "db", error.message);
  return json(200, { ok: true });
}

// ---- router ----
Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/clock/, "").replace(/\/+$/, "") || "/";
  const m = req.method;
  try {
    if (m === "GET" && path === "/") return json(200, { ok: true, service: "clock", version: "0.1.0" });
    if (m === "POST" && path === "/signup") return await signup(req);
    if (m === "POST" && path === "/bind") return await bind(req);
    if (m === "GET" && path === "/me") return await me(req);
    if (m === "POST" && path === "/tap") return await tap(req);
    if (m === "POST" && path === "/out") return await out(req);
    if (m === "GET" && path === "/admin/overview") return await adminOverview(req);
    if (m === "POST" && path === "/admin/workers") return await adminWorkerCreate(req);
    let mm = path.match(/^\/admin\/workers\/([^/]+)$/);
    if (mm && m === "PATCH") return await adminWorkerPatch(req, mm[1]);
    if (m === "POST" && path === "/admin/tags") return await adminTagCreate(req);
    mm = path.match(/^\/admin\/tags\/([^/]+)$/);
    if (mm && m === "PATCH") return await adminTagPatch(req, mm[1]);
    if (mm && m === "DELETE") return await adminTagDelete(req, mm[1]);
    if (m === "GET" && path === "/admin/events") return await adminEvents(req, url);
    if (m === "POST" && path === "/admin/events") return await adminEventCreate(req);
    mm = path.match(/^\/admin\/events\/([^/]+)$/);
    if (mm && m === "DELETE") return await adminEventDelete(req, mm[1]);
    return json(404, { error: "not_found" });
  } catch (e) {
    if (e instanceof HttpError) return json(e.status, { error: e.code, detail: e.detail });
    console.error("clock unhandled", (e as Error)?.message);
    return json(500, { error: "internal" });
  }
});
