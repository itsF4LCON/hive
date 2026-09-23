use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, Config, Handler};
use russh::{MethodKind, MethodSet, SshId};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use crate::event::{clip, Event};
use crate::Shared;

const SESSION_LIMIT: Duration = Duration::from_secs(60);

struct Trap {
    ip: IpAddr,
    shared: Arc<Shared>,
}

impl Handler for Trap {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let mut e = Event::new("ssh", self.ip, self.shared.geo.lookup(self.ip));
        e.username = clip(user, 64);
        e.password = clip(password, 64);
        eprintln!("ssh  {:<16} {:?} / {:?}", e.ip, e.username, e.password);
        self.shared.shipper.push(e);
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
            partial_success: false,
        })
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::reject())
    }
}

pub fn load_or_create_host_key(path: &Path) -> std::io::Result<PrivateKey> {
    if path.exists() {
        return PrivateKey::read_openssh_file(path).map_err(std::io::Error::other);
    }
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).map_err(std::io::Error::other)?;
    key.write_openssh_file(path, russh::keys::ssh_key::LineEnding::LF)
        .map_err(std::io::Error::other)?;
    eprintln!("ssh: generated new host key at {}", path.display());
    Ok(key)
}

pub async fn serve(listener: TcpListener, host_key: PrivateKey, shared: Arc<Shared>) {
    let config = Arc::new(Config {
        server_id: SshId::Standard("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5".into()),
        methods: MethodSet::from(&[MethodKind::Password, MethodKind::PublicKey][..]),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        max_auth_attempts: 6,
        inactivity_timeout: Some(Duration::from_secs(30)),
        keys: vec![host_key],
        ..Default::default()
    });

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("ssh: accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let ip = peer.ip().to_canonical();
        let Some(permit) = shared.limiter.try_acquire(ip) else {
            continue;
        };
        let config = config.clone();
        let shared = shared.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = stream.set_nodelay(true);
            let session = async {
                if let Ok(running) = russh::server::run_stream(config, stream, Trap { ip, shared }).await {
                    let _ = running.await;
                }
            };
            let _ = tokio::time::timeout(SESSION_LIMIT, session).await;
        });
    }
}
