use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use wasm_bindgen::JsValue;
use worker::*;

const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_EVENTS_PER_BATCH: usize = 500;
const MAX_CLOCK_SKEW_SECS: f64 = 300.0;
const MAX_EVENT_AGE_SECS: f64 = 24.0 * 60.0 * 60.0;
const RETENTION_SECS: f64 = 30.0 * 24.0 * 60.0 * 60.0;
const PUBLIC_CACHE_SECS: u32 = 30;
const RECENT_DEFAULT: u32 = 50;
const RECENT_MAX: u32 = 100;
const TOP_N: u32 = 5;

#[derive(Deserialize)]
struct IngestBatch {
    sent_at: f64,
    events: Vec<IncomingEvent>,
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

#[derive(Deserialize, Serialize)]
struct TopRow {
    k: Option<String>,
    n: u64,
}

#[derive(Deserialize, Serialize)]
struct CountRow {
    n: u64,
}

#[derive(Deserialize, Serialize)]
struct PointRow {
    lat: f64,
    lon: f64,
    n: u64,
}

#[derive(Serialize)]
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

fn now_secs() -> f64 {
    Date::now().as_millis() as f64 / 1000.0
}

/// Keep the network, drop the host: 203.0.113.57 -> 203.0.113.x, 2001:db8:1:2::5 -> 2001:db8:1::x.
/// Applied again here even though the sensor already masks, so a full IP can never be stored.
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
    for e in batch.events {
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
        db.batch(statements).await?;
    }
    Response::from_json(&serde_json::json!({ "accepted": accepted }))
}

async fn top(db: &D1Database, sql: &str, since: f64) -> Result<Vec<TopRow>> {
    db.prepare(sql)
        .bind(&[JsValue::from(since), JsValue::from(TOP_N)])?
        .all()
        .await?
        .results::<TopRow>()
}

async fn count(db: &D1Database, sql: &str, since: f64) -> Result<u64> {
    let row = db
        .prepare(sql)
        .bind(&[JsValue::from(since)])?
        .first::<CountRow>(None)
        .await?;
    Ok(row.map(|r| r.n).unwrap_or(0))
}

async fn build_stats(env: &Env) -> Result<String> {
    let db = env.d1("hive_db")?;
    let now = now_secs();
    let day = now - 86_400.0;
    let week = now - 7.0 * 86_400.0;

    let stats = Stats {
        generated_at: now.floor(),
        total_24h: count(&db, "SELECT COUNT(*) AS n FROM events WHERE ts >= ?1", day).await?,
        total_7d: count(&db, "SELECT COUNT(*) AS n FROM events WHERE ts >= ?1", week).await?,
        unique_sources_24h: count(
            &db,
            "SELECT COUNT(DISTINCT ip_masked) AS n FROM events WHERE ts >= ?1",
            day,
        )
        .await?,
        by_service_24h: top(
            &db,
            "SELECT service AS k, COUNT(*) AS n FROM events WHERE ts >= ?1 \
             GROUP BY service ORDER BY n DESC LIMIT ?2",
            day,
        )
        .await?,
        top_usernames: top(
            &db,
            "SELECT username AS k, COUNT(*) AS n FROM events \
             WHERE service = 'ssh' AND ts >= ?1 AND username IS NOT NULL \
             GROUP BY username ORDER BY n DESC LIMIT ?2",
            week,
        )
        .await?,
        top_passwords: top(
            &db,
            "SELECT password AS k, COUNT(*) AS n FROM events \
             WHERE service = 'ssh' AND ts >= ?1 AND password IS NOT NULL \
             GROUP BY password ORDER BY n DESC LIMIT ?2",
            week,
        )
        .await?,
        top_paths: top(
            &db,
            "SELECT path AS k, COUNT(*) AS n FROM events \
             WHERE service = 'http' AND ts >= ?1 AND path IS NOT NULL AND path != '/' \
             GROUP BY path ORDER BY n DESC LIMIT ?2",
            week,
        )
        .await?,
        top_countries: top(
            &db,
            "SELECT country AS k, COUNT(*) AS n FROM events \
             WHERE ts >= ?1 AND country IS NOT NULL \
             GROUP BY country ORDER BY n DESC LIMIT ?2",
            week,
        )
        .await?,
        top_user_agents: top(
            &db,
            "SELECT ua AS k, COUNT(*) AS n FROM events \
             WHERE service = 'http' AND ts >= ?1 AND ua IS NOT NULL \
             GROUP BY ua ORDER BY n DESC LIMIT ?2",
            week,
        )
        .await?,
        points_24h: db
            .prepare(
                "SELECT ROUND(lat, 1) AS lat, ROUND(lon, 1) AS lon, COUNT(*) AS n FROM events \
                 WHERE ts >= ?1 AND lat IS NOT NULL AND lon IS NOT NULL \
                 GROUP BY 1, 2 ORDER BY n DESC LIMIT 500",
            )
            .bind(&[JsValue::from(day)])?
            .all()
            .await?
            .results::<PointRow>()?,
    };
    Ok(serde_json::to_string(&stats)?)
}

async fn build_recent(env: &Env, limit: u32) -> Result<String> {
    let rows = env
        .d1("hive_db")?
        .prepare(
            "SELECT ts, service, ip_masked, country, city, lat, lon, username, password, \
             method, path, ua FROM events ORDER BY ts DESC, id DESC LIMIT ?1",
        )
        .bind(&[JsValue::from(limit)])?
        .all()
        .await?
        .results::<EventRow>()?;
    Ok(serde_json::to_string(&rows)?)
}

/// Serve a public JSON endpoint through the edge cache, so a busy page costs one D1 query per 30s.
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

#[event(scheduled)]
pub async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let cutoff = now_secs() - RETENTION_SECS;
    let result = async {
        env.d1("hive_db")?
            .prepare("DELETE FROM events WHERE ts < ?1")
            .bind(&[JsValue::from(cutoff)])?
            .run()
            .await
    }
    .await;
    if let Err(e) = result {
        console_error!("retention cleanup failed: {e}");
    }
}
