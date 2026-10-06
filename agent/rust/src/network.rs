//! Stagger full TCP/TLS/Upgrade attempts while keeping the canonical URI.
use crate::client::Ws;
use anyhow::{anyhow, Context, Result};
use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    task::JoinSet,
    time::{sleep, timeout, Instant},
};
use tokio_rustls::{
    rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};
use tokio_tungstenite::{
    client_async,
    tungstenite::{handshake::client::Request, Error},
    MaybeTlsStream,
};

pub const ATTEMPT_DELAY: Duration = Duration::from_millis(250);
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(15);

pub fn interleave(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut unique = Vec::new();
    for address in addresses {
        if !unique.contains(&address) {
            unique.push(address);
        }
    }
    let Some(first) = unique.first() else {
        return unique;
    };
    let preferred_v6 = first.is_ipv6();
    let (preferred, alternate): (Vec<_>, Vec<_>) = unique
        .into_iter()
        .partition(|a| a.is_ipv6() == preferred_v6);
    let mut preferred = preferred.into_iter();
    let mut alternate = alternate.into_iter();
    let mut ordered = Vec::new();
    loop {
        let a = preferred.next();
        let b = alternate.next();
        if a.is_none() && b.is_none() {
            break;
        }
        ordered.extend(a);
        ordered.extend(b);
    }
    ordered
}

// Dropping/aborting an attempt drops its owned socket/TLS transport. Only the
// first complete Upgrade is returned. No Agent hello is sent by the losers.
pub async fn race<T, F, Fut>(addresses: Vec<SocketAddr>, attempt: F, delay: Duration) -> Result<T>
where
    T: Send + 'static,
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T>> + Send + 'static,
{
    let mut addresses = addresses.into_iter();
    let mut tasks = JoinSet::new();
    let first = addresses.next().context("stage=dns: no viable addresses")?;
    tasks.spawn(attempt(first));
    let mut next = Instant::now() + delay;
    let mut last_error = None;
    let mut exhausted = false;
    loop {
        tokio::select! {
            result = tasks.join_next(), if !tasks.is_empty() => {
                match result.context("stage=tcp: no attempts")?.context("connection task failed")? {
                    Ok(winner) => { tasks.abort_all(); while tasks.join_next().await.is_some() {} return Ok(winner); }
                    Err(error) => {
                        eprintln!("Agent opening attempt failed: {error}");
                        last_error = Some(error);
                        // Fail fast to the next candidate, without waiting 250ms.
                        next = Instant::now();
                    }
                }
            }
            _ = sleep(next.saturating_duration_since(Instant::now())), if !exhausted => {
                if let Some(address) = addresses.next() { tasks.spawn(attempt(address)); next = Instant::now() + delay; }
                else { exhausted = true; }
            }
        }
        if exhausted && tasks.is_empty() {
            return Err(last_error.unwrap_or_else(|| anyhow!("stage=tcp: all attempts failed")));
        }
    }
}

async fn attempt(
    address: SocketAddr,
    request: Request,
    host: String,
    secure: bool,
    tls: Arc<ClientConfig>,
) -> Result<Ws> {
    let tcp = timeout(Duration::from_secs(5), TcpStream::connect(address))
        .await
        .context("stage=tcp: connect timeout")?
        .context("stage=tcp: connect failed")?;
    let stream = if secure {
        let name = ServerName::try_from(host).context("stage=tls: invalid server name")?;
        let tls = timeout(
            Duration::from_secs(5),
            TlsConnector::from(tls).connect(name, tcp),
        )
        .await
        .context("stage=tls: handshake timeout")?
        .context("stage=tls: handshake/certificate failure")?;
        MaybeTlsStream::Rustls(tls)
    } else {
        MaybeTlsStream::Plain(tcp)
    };
    let opening = timeout(Duration::from_secs(5), client_async(request, stream))
        .await
        .context("stage=upgrade: WebSocket opening timeout")?;
    let (ws, _) = opening.map_err(|error| {
        let denied =
            matches!(&error, Error::Http(response) if matches!(response.status().as_u16(),401|403));
        anyhow::Error::new(error).context(if denied {
            "stage=authentication: WebSocket rejected"
        } else {
            "stage=upgrade: WebSocket opening failed"
        })
    })?;
    Ok(ws)
}

pub async fn connect(request: Request) -> Result<Ws> {
    let uri = request.uri();
    let host = uri
        .host()
        .context("stage=dns: missing hostname")?
        .trim_matches(['[', ']'])
        .to_owned();
    let secure = match uri.scheme_str() {
        Some("wss") => true,
        Some("ws") => false,
        _ => return Err(anyhow!("stage=dns: invalid WebSocket scheme")),
    };
    let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
    let start = Instant::now();
    let resolved = timeout(OPEN_TIMEOUT, tokio::net::lookup_host((host.as_str(), port)))
        .await
        .context("stage=dns: resolution timeout")?
        .context("stage=dns: resolution failed")?;
    let addresses = interleave(resolved.collect());
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let remaining = OPEN_TIMEOUT.saturating_sub(start.elapsed());
    let ws = timeout(
        remaining,
        race(
            addresses,
            move |address| attempt(address, request.clone(), host.clone(), secure, tls.clone()),
            ATTEMPT_DELAY,
        ),
    )
    .await
    .context("stage=opening: overall 15s deadline")??;
    // The returned transport exclusively belongs to the authentication caller.
    Ok(ws)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn resolver_order_and_family_interleaving() {
        let a = "[::1]:443".parse().unwrap();
        let b = "[::2]:443".parse().unwrap();
        let c = "127.0.0.1:443".parse().unwrap();
        assert_eq!(interleave(vec![a, b, c, a]), vec![a, c, b]);
        assert_eq!(interleave(vec![c, b, a]), vec![c, b, a]);
    }

    #[tokio::test]
    async fn reachable_both_or_blackholed_first_family() {
        for blackholed in [None, Some(true), Some(false)] {
            let v6: SocketAddr = "[::1]:443".parse().unwrap();
            let v4: SocketAddr = "127.0.0.1:443".parse().unwrap();
            let ordered = if blackholed == Some(false) {
                vec![v4, v6]
            } else {
                vec![v6, v4]
            };
            let alive = Arc::new(AtomicUsize::new(0));
            let tracked = alive.clone();
            let start = Instant::now();
            let result = race(
                ordered,
                move |address| {
                    let alive = tracked.clone();
                    async move {
                        alive.fetch_add(1, Ordering::SeqCst);
                        let _guard = Active(alive);
                        if Some(address.is_ipv6()) == blackholed {
                            std::future::pending::<()>().await;
                        }
                        Ok(address)
                    }
                },
                Duration::from_millis(10),
            )
            .await
            .unwrap();
            assert_ne!(Some(result.is_ipv6()), blackholed);
            assert!(start.elapsed() < Duration::from_millis(200));
            assert_eq!(alive.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn all_blackholed_cancel_on_overall_deadline() {
        let alive = Arc::new(AtomicUsize::new(0));
        let tracked = alive.clone();
        let result = timeout(
            Duration::from_millis(40),
            race(
                vec![
                    "[::1]:443".parse().unwrap(),
                    "127.0.0.1:443".parse().unwrap(),
                ],
                move |_| {
                    let alive = tracked.clone();
                    async move {
                        alive.fetch_add(1, Ordering::SeqCst);
                        let _guard = Active(alive);
                        std::future::pending::<Result<()>>().await
                    }
                },
                Duration::from_millis(10),
            ),
        )
        .await;
        assert!(result.is_err());
        tokio::task::yield_now().await;
        assert_eq!(alive.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn failure_accelerates_alternate_and_keeps_tls_rejection() {
        let start = Instant::now();
        let result = race(
            vec![
                "[::1]:443".parse().unwrap(),
                "127.0.0.1:443".parse().unwrap(),
            ],
            |_| async { Err::<(), _>(anyhow!("stage=tls: certificate failure")) },
            Duration::from_secs(1),
        )
        .await;
        assert!(result.unwrap_err().to_string().starts_with("stage=tls"));
        assert!(start.elapsed() < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn tls_rejected_candidate_can_fall_back_without_changing_trust() {
        let result = race(
            vec![
                "[::1]:443".parse().unwrap(),
                "127.0.0.1:443".parse().unwrap(),
            ],
            |address| async move {
                if address.is_ipv6() {
                    Err(anyhow!("stage=tls: certificate failure"))
                } else {
                    Ok(address)
                }
            },
            Duration::from_millis(250),
        )
        .await
        .unwrap();
        assert!(result.is_ipv4());
    }

    #[tokio::test]
    async fn actual_tls_failure_never_sends_plaintext_upgrade() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = [0; 2048];
            let n = stream.read(&mut data).await.unwrap();
            assert!(!data[..n].starts_with(b"GET"));
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        });
        let tls = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        );
        let request = format!("wss://localhost:{}/agent", address.port())
            .into_client_request()
            .unwrap();
        let error = attempt(address, request, "localhost".into(), true, tls)
            .await
            .unwrap_err();
        assert!(error.to_string().starts_with("stage=tls"));
        peer.await.unwrap();
    }
}
