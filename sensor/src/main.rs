mod blocklist;
mod event;
mod geo;
mod http;
mod limiter;
mod shipper;
mod ssh;
mod stats;

use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;

pub struct Shared {
    pub geo: geo::Geo,
    pub shipper: shipper::Shipper,
    pub limiter: Arc<limiter::Limiter>,
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        eprintln!("missing required environment variable {name}");
        std::process::exit(2);
    })
}

#[tokio::main]
async fn main() {
    let ingest_url = required("HIVE_INGEST_URL");
    let secret = required("HIVE_SECRET");
    let ssh_addr = env_or("HIVE_SSH_ADDR", "0.0.0.0:22");
    let http_addr = env_or("HIVE_HTTP_ADDR", "0.0.0.0:80");
    let state_dir = PathBuf::from(env_or("HIVE_STATE_DIR", "/var/lib/hive"));
    let geoip = std::env::var("HIVE_GEOIP_DB").ok().map(PathBuf::from);
    let policy = blocklist::Policy {
        min_hits: env_or("HIVE_BLOCKLIST_MIN", "3").parse().unwrap_or_else(|_| {
            eprintln!("HIVE_BLOCKLIST_MIN must be a whole number");
            std::process::exit(2);
        }),
        ignore: blocklist::parse_ignore(&env_or("HIVE_IGNORE_IPS", "")),
    };

    let host_key = ssh::load_or_create_host_key(&state_dir.join("ssh_host_ed25519_key"))
        .unwrap_or_else(|e| {
            eprintln!("ssh: cannot load or create host key in {}: {e}", state_dir.display());
            std::process::exit(1);
        });
    let bind = |addr: String| async move {
        TcpListener::bind(&addr).await.unwrap_or_else(|e| {
            eprintln!("cannot listen on {addr}: {e}");
            std::process::exit(1);
        })
    };
    let ssh_listener = bind(ssh_addr.clone()).await;
    let http_listener = bind(http_addr.clone()).await;

    let shared = Arc::new(Shared {
        geo: geo::Geo::open(geoip.as_deref()),
        shipper: shipper::Shipper::new(state_dir.join("stats.json")),
        limiter: limiter::Limiter::new(256, 10),
    });
    eprintln!("hive-sensor: ssh on {ssh_addr}, http on {http_addr}, shipping to {ingest_url}");

    let s = shared.clone();
    tokio::spawn(async move { s.shipper.run(ingest_url, secret, policy).await });
    tokio::spawn(ssh::serve(ssh_listener, host_key, shared.clone()));
    tokio::spawn(http::serve(http_listener, shared.clone()));

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    eprintln!("hive-sensor: shutting down");
    shared.shipper.save();
}
