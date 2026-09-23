use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use wasm_bindgen::JsValue;
use worker::*;

const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_EVENTS_PER_BATCH: usize = 50;
const KEEP_EVENTS: u32 = 500;
const MAX_CLOCK_SKEW_SECS: f64 = 300.0;
const MAX_EVENT_AGE_SECS: f64 = 24.0 * 60.0 * 60.0;
const PUBLIC_CACHE_SECS: u32 = 30;
const RECENT_DEFAULT: u32 = 50;
const RECENT_MAX: u32 = 100;
const MAX_TOP: usize = 10;
const MAX_POINTS: usize = 500;

#[derive(Deserialize)]
struct IngestBatch {
    sent_at: f64,
    events: Vec<IncomingEvent>,
    stats: Option<Stats>,
}

#[derive(Deserialize)]
struct IncomingEvent {
    ts: f64,
    service: String,
    ip: String,
    country: Option<String>,
    city: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    username: Option<String>,
    password: Option<String>,
    method: Option<String>,
    path: Option<String>,
    ua: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct EventRow {
    ts: f64,
    service: String,
    ip_masked: String,
    country: Option<String>,
    city: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    username: Option<String>,
    password: Option<String>,
    method: Option<String>,
    path: Option<String>,
    ua: Option<String>,
}

#[derive(Deserialize, Serialize, Default)]
struct TopRow {
    k: Option<String>,
    n: u64,
}

#[derive(Deserialize, Serialize, Default)]
struct PointRow {
    lat: f64,
    lon: f64,
    n: u64,
}

#[derive(Deserialize, Serialize, Default)]
struct Stats {
    generated_at: f64,
    total_24h: u64,
    total_7d: u64,
    unique_sources_24h: u64,
    by_service_24h: Vec<TopRow>,
    top_usernames: Vec<TopRow>,
    top_passwords: Vec<TopRow>,
    top_paths: Vec<TopRow>,
    top_countries: Vec<TopRow>,
    top_user_agents: Vec<TopRow>,
    points_24h: Vec<PointRow>,
}

#[derive(Deserialize)]
struct SnapshotRow {
    body: String,
}

fn clean_top(rows: Vec<TopRow>) -> Vec<TopRow> {
    rows.into_iter()
        .take(MAX_TOP)
        .map(|r| TopRow { k: clip(r.k, 256), n: r.n })
        .collect()
}

impl Stats {
    fn sanitized(self) -> Stats {
        Stats {
            generated_at: self.generated_at,
            total_24h: self.total_24h,
            total_7d: self.total_7d,
            unique_sources_24h: self.unique_sources_24h,
            by_service_24h: clean_top(self.by_service_24h),
            top_usernames: clean_top(self.top_usernames),
            top_passwords: clean_top(self.top_passwords),
            top_paths: clean_top(self.top_paths),
            top_countries: clean_top(self.top_countries),
            top_user_agents: clean_top(self.top_user_agents),
            points_24h: self
                .points_24h
                .into_iter()
                .filter(|p| (-90.0..=90.0).contains(&p.lat) && (-180.0..=180.0).contains(&p.lon))
                .take(MAX_POINTS)
                .collect(),
        }
    }
}

fn now_secs() -> f64 {
    Date::now().as_millis() as f64 / 1000.0
}

fn mask_ip(ip: &str) -> String {
    let ip = ip.trim();
    if ip.contains(':') {
        let head: Vec<&str> = ip.split(':').filter(|p| !p.is_empty()).take(3).collect();
        format!("{}::x", head.join(":"))
    } else {
        let head: Vec<&str> = ip.split('.').take(3).collect();
        format!("{}.x", head.join("."))
    }
}

fn clip(s: Option<String>, max_chars: usize) -> Option<String> {
    s.map(|v| v.chars().filter(|c| !c.is_control()).take(max_chars).collect::<String>())
        .filter(|v| !v.is_empty())
}

fn opt_str(v: Option<String>) -> JsValue {
    v.map(JsValue::from).unwrap_or(JsValue::NULL)
}

fn opt_f64(v: Option<f64>) -> JsValue {
    v.filter(|n| n.is_finite()).map(JsValue::from).unwrap_or(JsValue::NULL)
}

fn verify_signature(secret: &str, body: &[u8], signature_hex: &str) -> bool {
    let Ok(sig) = hex::decode(signature_hex.trim()) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&sig).is_ok()
}

fn allowed_origin(req: &Request, env: &Env) -> Option<String> {
    let origin = req.headers().get("Origin").ok().flatten()?;
    let allowed = env.var("ALLOWED_ORIGINS").ok()?.to_string();
    allowed
        .split(',')
        .map(str::trim)
        .any(|o| o == origin)
        .then_some(origin)
}

fn with_cors(mut res: Response, origin: &Option<String>) -> Result<Response> {
    if let Some(o) = origin {
        let h = res.headers_mut();
        h.set("Access-Control-Allow-Origin", o)?;
        h.set("Access-Control-Allow-Methods", "GET, OPTIONS")?;
        h.set("Vary", "Origin")?;
    }
    Ok(res)
}

async fn ingest(mut req: Request, env: &Env) -> Result<Response> {
    let signature = match req.headers().get("X-Hive-Signature")? {
        Some(s) => s,
        None => return Response::error("Unauthorized", 401),
    };
    let body = req.bytes().await?;
    if body.len() > MAX_BODY_BYTES {
        return Response::error("Batch too large", 413);
    }
    let secret = env.secret("HIVE_SECRET")?.to_string();
    if !verify_signature(&secret, &body, &signature) {
        return Response::error("Unauthorized", 401);
    }

    let batch: IngestBatch = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => return Response::error("Invalid JSON payload", 400),
    };
    let now = now_secs();
    if (now - batch.sent_at).abs() > MAX_CLOCK_SKEW_SECS {
        return Response::error("Stale or future batch", 401);
    }
    if batch.events.len() > MAX_EVENTS_PER_BATCH {
        return Response::error("Too many events in batch", 413);
    }

    let db = env.d1("hive_db")?;
    let mut statements = Vec::with_capacity(batch.events.len());
    for e in batch.events.into_iter() {
        if e.service != "ssh" && e.service != "http" {
            continue;
        }
        if e.ts < now - MAX_EVENT_AGE_SECS || e.ts > now + MAX_CLOCK_SKEW_SECS {
            continue;
        }
        let stmt = db
            .prepare(
                "INSERT INTO events (ts, service, ip_masked, country, city, lat, lon, \
                 username, password, method, path, ua) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )
            .bind(&[
                JsValue::from(e.ts.floor()),
                JsValue::from(e.service),
                JsValue::from(mask_ip(&e.ip)),
                opt_str(clip(e.country, 2)),
                opt_str(clip(e.city, 64)),
                opt_f64(e.lat),
                opt_f64(e.lon),
                opt_str(clip(e.username, 64)),
                opt_str(clip(e.password, 64)),
                opt_str(clip(e.method, 16)),
                opt_str(clip(e.path, 256)),
                opt_str(clip(e.ua, 256)),
            ])?;
        statements.push(stmt);
    }

    let accepted = statements.len();
    if accepted > 0 {
        statements.push(
            db.prepare("DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?1")
                .bind(&[JsValue::from(KEEP_EVENTS)])?,
        );
    }
    let has_stats = batch.stats.is_some();
    if let Some(stats) = batch.stats {
        statements.push(
            db.prepare(
                "INSERT INTO snapshot (id, body, updated_at) VALUES (1, ?1, ?2) \
                 ON CONFLICT(id) DO UPDATE SET body = excluded.body, updated_at = excluded.updated_at",
            )
            .bind(&[
                JsValue::from(serde_json::to_string(&stats.sanitized())?),
                JsValue::from(now.floor()),
            ])?,
        );
    }
    if !statements.is_empty() {
        db.batch(statements).await?;
    }
    Response::from_json(&serde_json::json!({ "accepted": accepted, "stats": has_stats }))
}

async fn build_stats(env: &Env) -> Result<String> {
    let row = env
        .d1("hive_db")?
        .prepare("SELECT body FROM snapshot WHERE id = 1")
        .first::<SnapshotRow>(None)
        .await?;
    match row {
        Some(r) => Ok(r.body),
        None => Ok(serde_json::to_string(&Stats::default())?),
    }
}

async fn build_recent(env: &Env, limit: u32) -> Result<String> {
    let rows = env
        .d1("hive_db")?
        .prepare(
            "SELECT ts, service, ip_masked, country, city, lat, lon, username, password, \
             method, path, ua FROM events ORDER BY id DESC LIMIT ?1",
        )
        .bind(&[JsValue::from(limit)])?
        .all()
        .await?
        .results::<EventRow>()?;
    Ok(serde_json::to_string(&rows)?)
}

async fn cached_json(cache_key: &str, origin: &Option<String>, build: impl std::future::Future<Output = Result<String>>) -> Result<Response> {
    let cache = Cache::default();
    let body = match cache.get(cache_key, false).await? {
        Some(mut hit) => hit.text().await?,
        None => {
            let body = build.await?;
            let mut stored = Response::ok(body.clone())?;
            stored
                .headers_mut()
                .set("Cache-Control", &format!("public, max-age={PUBLIC_CACHE_SECS}"))?;
            cache.put(cache_key, stored).await?;
            body
        }
    };
    let mut res = Response::ok(body)?;
    let h = res.headers_mut();
    h.set("Content-Type", "application/json")?;
    h.set("Cache-Control", &format!("public, max-age={PUBLIC_CACHE_SECS}"))?;
    with_cors(res, origin)
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let origin = allowed_origin(&req, &env);
    let path = req.path();

    match (req.method(), path.as_str()) {
        (Method::Options, _) => with_cors(Response::empty()?, &origin),
        (Method::Post, "/ingest") => ingest(req, &env).await,
        (Method::Get, "/stats") => {
            cached_json("https://hive.internal/stats", &origin, build_stats(&env)).await
        }
        (Method::Get, "/recent") => {
            let limit = req
                .url()?
                .query_pairs()
                .find(|(k, _)| k == "limit")
                .and_then(|(_, v)| v.parse::<u32>().ok())
                .unwrap_or(RECENT_DEFAULT)
                .clamp(1, RECENT_MAX);
            let key = format!("https://hive.internal/recent?limit={limit}");
            cached_json(&key, &origin, build_recent(&env, limit)).await
        }
        _ => Response::error("Not found", 404),
    }
}
