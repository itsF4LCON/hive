use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use crate::event::{clip, Event};
use crate::Shared;

const CONNECTION_LIMIT: Duration = Duration::from_secs(30);

const PAGE: &str = "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n<style>\nhtml { color-scheme: light dark; }\nbody { width: 35em; margin: 0 auto;\nfont-family: Tahoma, Verdana, Arial, sans-serif; }\n</style>\n</head>\n<body>\n<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully installed and\nworking. Further configuration is required.</p>\n\n<p>For online documentation and support please refer to\n<a href=\"http://nginx.org/\">nginx.org</a>.<br/>\nCommercial support is available at\n<a href=\"http://nginx.com/\">nginx.com</a>.</p>\n\n<p><em>Thank you for using nginx.</em></p>\n</body>\n</html>\n";

fn record(req: &Request<Incoming>, ip: IpAddr, shared: &Shared) {
    let mut e = Event::new("http", ip, shared.geo.lookup(ip));
    e.method = clip(req.method().as_str(), 16);
    e.path = req.uri().path_and_query().and_then(|pq| clip(pq.as_str(), 256));
    e.ua = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| clip(v, 256));
    eprintln!("http {:<16} {} {}", e.ip, e.method.as_deref().unwrap_or("?"), e.path.as_deref().unwrap_or("?"));
    shared.shipper.push(e);
}

pub async fn serve(listener: TcpListener, shared: Arc<Shared>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("http: accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let ip = peer.ip().to_canonical();
        let Some(permit) = shared.limiter.try_acquire(ip) else {
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(move |req: Request<Incoming>| {
                record(&req, ip, &shared);
                async {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("Server", "nginx/1.24.0 (Ubuntu)")
                            .header("Content-Type", "text/html")
                            .body(Full::new(Bytes::from_static(PAGE.as_bytes())))
                            .unwrap(),
                    )
                }
            });
            let conn = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .max_buf_size(16 * 1024)
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service);
            let _ = tokio::time::timeout(CONNECTION_LIMIT, conn).await;
        });
    }
}
