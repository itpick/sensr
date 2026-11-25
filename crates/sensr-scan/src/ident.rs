//! Service identification on open TCP ports.
//!
//! The result types live in [`crate::types`] so they build without features
//! (the store, API and UI read them). The parsers here are pure and always
//! built; [`identify`], which talks to the network, needs the `daemon`
//! feature.
//!
//! The probes and match rules are our own (nmap's service probe database is
//! under the NPSL and is not used).
//!
//! Everything a service sends is untrusted: reads are capped, every call has a
//! hard time budget, the parsers accept any bytes without panicking, and all
//! text goes through [`sanitize`].

pub use crate::types::{Ident, TlsInfo, sanitize};

/// Most bytes of an HTTP response [`parse_http`] looks at.
pub const HTTP_MAX: usize = 64 * 1024;
/// Most bytes of a greeting [`parse_greeting`] looks at.
pub const GREETING_MAX: usize = 4 * 1024;

/// Products recognised by name in FTP/SMTP/POP3/IMAP greetings; the version
/// is the next word when it starts with a digit.
const GREETING_PRODUCTS: &[&str] = &[
    "vsFTPd",
    "ProFTPD",
    "Pure-FTPd",
    "FileZilla",
    "Postfix",
    "Exim",
    "Sendmail",
    "OpenSMTPD",
    "Dovecot",
    "Cyrus",
    "Courier",
];

/// Identify a service from the first bytes it sends unprompted: an SSH
/// version line, an FTP/SMTP `220`, a POP3 `+OK` or an IMAP `* OK` greeting.
/// Other text becomes the banner.
#[must_use]
pub fn parse_greeting(b: &[u8]) -> Ident {
    let b = &b[..b.len().min(GREETING_MAX)];
    let line = b.split(|&c| c == b'\n').next().unwrap_or_default();
    let mut id = Ident::default();
    let banner = sanitize(line);
    if banner.is_empty() {
        return id;
    }
    if let Some(rest) = banner.strip_prefix("SSH-") {
        // SSH-protoversion-softwareversion SP comments (RFC 4253 §4.2).
        let software = rest
            .split_once('-')
            .map_or("", |(_, s)| s)
            .split(' ')
            .next()
            .unwrap_or_default();
        let (product, version) = software.split_once('_').unwrap_or((software, ""));
        id.product = non_empty(product);
        id.version = non_empty(version);
    } else if ["220", "+OK", "* OK"].iter().any(|p| banner.starts_with(p)) {
        let words: Vec<&str> = banner
            .split([' ', '(', ')', '[', ']'])
            .filter(|w| !w.is_empty())
            .collect();
        if let Some(i) = words
            .iter()
            .position(|w| GREETING_PRODUCTS.iter().any(|p| w.eq_ignore_ascii_case(p)))
        {
            id.product = non_empty(words[i]);
            id.version = words
                .get(i + 1)
                .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
                .and_then(|v| non_empty(v.trim_end_matches([',', ';', '.'])));
        }
    }
    id.banner = Some(banner);
    id
}

/// Identify a web server from its response: the `Server:` header gives the
/// product and version, the page `<title>` the title, the status line the
/// banner. Only the first [`HTTP_MAX`] bytes are read. RTSP responses have
/// the same shape and parse here too.
#[must_use]
pub fn parse_http(b: &[u8]) -> Ident {
    let b = &b[..b.len().min(HTTP_MAX)];
    let (head, body) = match find(b, b"\r\n\r\n") {
        Some(i) => (&b[..i], &b[i + 4..]),
        None => match find(b, b"\n\n") {
            Some(i) => (&b[..i], &b[i + 2..]),
            None => (b, &b[b.len()..]),
        },
    };
    let mut lines = head.split(|&c| c == b'\n');
    let mut id = Ident {
        banner: lines.next().map(sanitize).filter(|s| !s.is_empty()),
        ..Ident::default()
    };
    for line in lines {
        let Some(colon) = line.iter().position(|&c| c == b':') else {
            continue;
        };
        if !line[..colon].trim_ascii().eq_ignore_ascii_case(b"server") {
            continue;
        }
        let value = sanitize(&line[colon + 1..]);
        let first = value.split(' ').next().unwrap_or_default();
        let (product, version) = first.split_once('/').unwrap_or((first, ""));
        id.product = non_empty(product);
        id.version = non_empty(version);
        break;
    }
    id.title = title(body);
    id
}

/// The text of the first `<title>` element of an HTML body.
fn title(body: &[u8]) -> Option<String> {
    let mut from = 0;
    while let Some(i) = find_ci(&body[from..], b"<title") {
        let after = from + i + b"<title".len();
        match body.get(after) {
            Some(b'>') | Some(b' ' | b'\t' | b'\r' | b'\n') => {
                let open_end = after + body[after..].iter().position(|&c| c == b'>')? + 1;
                let len = find_ci(&body[open_end..], b"</title").unwrap_or(body.len() - open_end);
                let text = sanitize(&body[open_end..open_end + len]);
                return non_empty(&unescape(&text));
            }
            _ => from = after,
        }
    }
    None
}

/// Decode the few HTML entities common in titles.
fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
}

fn non_empty(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

#[cfg(feature = "daemon")]
pub use net::{BUDGET, identify, parse_cert};

#[cfg(feature = "daemon")]
mod net {
    use std::net::{IpAddr, SocketAddr};
    use std::sync::{Arc, LazyLock};
    use std::time::Duration;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::WebPkiSupportedAlgorithms;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{Instant, timeout, timeout_at};
    use tokio_rustls::TlsConnector;
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::{FromDer, X509Certificate};

    use super::{
        GREETING_MAX, HTTP_MAX, Ident, TlsInfo, find, find_ci, parse_greeting, parse_http, sanitize,
    };

    /// Hard limit on one [`identify`] call.
    pub const BUDGET: Duration = Duration::from_secs(5);
    /// How long to wait for a service to speak first.
    const GREETING_WAIT: Duration = Duration::from_millis(1500);
    /// Connect timeout, and read timeout for each probe's answer.
    const PROBE_WAIT: Duration = Duration::from_millis(1500);
    /// Most subject alternative names kept from a certificate.
    const SANS_MAX: usize = 32;

    /// A probe sent when a port stays silent.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Probe {
        Http,
        Redis,
        Rtsp,
        Mqtt,
    }

    /// The probes worth sending for a service name hint or a port.
    fn probes_for(hint: Option<&str>, port: u16) -> Vec<Probe> {
        let by_hint = match hint.map(str::to_ascii_lowercase).as_deref() {
            Some("http" | "http-alt" | "http-proxy" | "www") => Some(Probe::Http),
            Some("redis") => Some(Probe::Redis),
            Some("rtsp") => Some(Probe::Rtsp),
            Some("mqtt") => Some(Probe::Mqtt),
            _ => None,
        };
        let by_port = match port {
            80 | 81 | 591 | 8000 | 8008 | 8080 | 8081 | 8888 | 5000 => Some(Probe::Http),
            6379 => Some(Probe::Redis),
            554 | 8554 => Some(Probe::Rtsp),
            1883 => Some(Probe::Mqtt),
            _ => None,
        };
        let mut v: Vec<Probe> = by_hint.into_iter().collect();
        if let Some(p) = by_port.filter(|p| !v.contains(p)) {
            v.push(p);
        }
        v
    }

    /// Find out what is listening on `ip:port`. Tries, in order and within
    /// [`BUDGET`] overall:
    /// 1. a greeting the service sends unprompted;
    /// 2. the probes for `hint` / `port` (HTTP, Redis, RTSP, MQTT);
    /// 3. a plain HTTP request;
    /// 4. a TLS handshake (certificate not verified), recording the
    ///    certificate, then HTTP over TLS for the page title.
    ///
    /// `None` when nothing was learned (closed, silent or unknown).
    pub async fn identify(ip: IpAddr, port: u16, hint: Option<&str>) -> Option<Ident> {
        let mut best = None;
        // On timeout the future, and its borrow of `best`, is dropped, so
        // whatever was learned so far is still returned.
        let _ = timeout(BUDGET, run(SocketAddr::new(ip, port), hint, &mut best)).await;
        best.filter(|i| *i != Ident::default())
    }

    async fn run(addr: SocketAddr, hint: Option<&str>, best: &mut Option<Ident>) {
        // 1. Greeting.
        let Ok(mut s) = connect(addr).await else {
            return;
        };
        let greeting =
            read_until(&mut s, GREETING_MAX, GREETING_WAIT, |b| b.contains(&b'\n')).await;
        drop(s);
        if !greeting.is_empty() {
            let id = parse_greeting(&greeting);
            if id != Ident::default() {
                *best = Some(id);
                return;
            }
        }

        // 2. Probes for the hint / port, then 3. generic HTTP.
        let mut probes = probes_for(hint, addr.port());
        if !probes.contains(&Probe::Http) {
            probes.push(Probe::Http);
        }
        for probe in probes {
            let Some(id) = send_probe(addr, probe).await else {
                continue;
            };
            // A plain HTTP 400 is often a TLS port refusing clear text
            // ("The plain HTTP request was sent to HTTPS port"): keep it
            // but go on to TLS.
            let tls_hint = id.banner.as_deref().is_some_and(|b| b.contains(" 400"));
            *best = Some(id);
            if !tls_hint {
                return;
            }
            break;
        }

        // 4. TLS.
        if let Some(mut id) = tls(addr).await {
            if let Some(prev) = best.take() {
                id.product = id.product.or(prev.product);
                id.version = id.version.or(prev.version);
            }
            *best = Some(id);
        }
    }

    async fn send_probe(addr: SocketAddr, probe: Probe) -> Option<Ident> {
        let mut s = connect(addr).await.ok()?;
        match probe {
            Probe::Http => {
                s.write_all(&http_request(addr)).await.ok()?;
                let r = read_until(&mut s, HTTP_MAX, PROBE_WAIT, http_done).await;
                r.starts_with(b"HTTP/").then(|| parse_http(&r))
            }
            Probe::Redis => {
                s.write_all(b"PING\r\n").await.ok()?;
                let r = read_until(&mut s, 512, PROBE_WAIT, |b| find(b, b"\r\n").is_some()).await;
                // +PONG, or an error when auth or protected mode is on.
                let ok = r.starts_with(b"+PONG")
                    || r.starts_with(b"-NOAUTH")
                    || r.starts_with(b"-DENIED")
                    || r.starts_with(b"-ERR");
                ok.then(|| Ident {
                    product: Some("Redis".into()),
                    banner: Some(sanitize(
                        r.split(|&c| c == b'\r').next().unwrap_or_default(),
                    ))
                    .filter(|b| !b.is_empty()),
                    ..Ident::default()
                })
            }
            Probe::Rtsp => {
                let req = format!("OPTIONS rtsp://{addr}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n");
                s.write_all(req.as_bytes()).await.ok()?;
                let r = read_until(&mut s, GREETING_MAX, PROBE_WAIT, |b| {
                    find(b, b"\r\n\r\n").is_some()
                })
                .await;
                r.starts_with(b"RTSP/").then(|| {
                    let mut id = parse_http(&r);
                    id.product = id.product.or_else(|| Some("RTSP".into()));
                    id
                })
            }
            Probe::Mqtt => {
                s.write_all(MQTT_CONNECT).await.ok()?;
                let r = read_until(&mut s, 64, PROBE_WAIT, |b| b.len() >= 4).await;
                // CONNACK: type 2, remaining length 2, flags, return code.
                (r.len() >= 4 && r[0] == 0x20 && r[1] == 0x02).then(|| Ident {
                    product: Some("MQTT".into()),
                    banner: Some(
                        match r[3] {
                            0 => "connection accepted",
                            4 | 5 => "authentication required",
                            _ => "connection refused",
                        }
                        .into(),
                    ),
                    ..Ident::default()
                })
            }
        }
    }

    /// MQTT 3.1.1 CONNECT: clean session, 60 s keep-alive, client id
    /// `sensr-scan`.
    const MQTT_CONNECT: &[u8] = &[
        0x10, 22, // CONNECT, remaining length
        0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, // variable header
        0x00, 10, b's', b'e', b'n', b's', b'r', b'-', b's', b'c', b'a', b'n',
    ];

    fn http_request(addr: SocketAddr) -> Vec<u8> {
        let host = match addr.ip() {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        format!(
            "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: sensr-scan\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    }

    /// Enough of an HTTP response read: the title is complete, or the body
    /// reached its `Content-Length`.
    fn http_done(b: &[u8]) -> bool {
        if find_ci(b, b"</title").is_some() {
            return true;
        }
        let Some(end) = find(b, b"\r\n\r\n") else {
            return false;
        };
        let len = b[..end].split(|&c| c == b'\n').find_map(|l| {
            let (k, v) = l.split_at(l.iter().position(|&c| c == b':')?);
            k.trim_ascii()
                .eq_ignore_ascii_case(b"content-length")
                .then(|| {
                    std::str::from_utf8(&v[1..])
                        .ok()?
                        .trim()
                        .parse::<usize>()
                        .ok()
                })?
        });
        len.is_some_and(|n| b.len() >= end + 4 + n)
    }

    async fn connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
        timeout(PROBE_WAIT, TcpStream::connect(addr))
            .await
            .map_err(|_| std::io::ErrorKind::TimedOut)?
    }

    /// Read until EOF, `cap` bytes, `wait` elapsed or `done` says enough.
    async fn read_until<S: AsyncRead + Unpin>(
        s: &mut S,
        cap: usize,
        wait: Duration,
        done: impl Fn(&[u8]) -> bool,
    ) -> Vec<u8> {
        let deadline = Instant::now() + wait;
        let mut out = Vec::new();
        let mut buf = vec![0u8; 8 * 1024];
        while out.len() < cap {
            let want = buf.len().min(cap - out.len());
            match timeout_at(deadline, s.read(&mut buf[..want])).await {
                Ok(Ok(n)) if n > 0 => {
                    out.extend_from_slice(&buf[..n]);
                    if done(&out) {
                        break;
                    }
                }
                _ => break,
            }
        }
        out
    }

    async fn tls(addr: SocketAddr) -> Option<Ident> {
        let tcp = connect(addr).await.ok()?;
        // We do not know the host name; an IP server name sends no SNI.
        let name = ServerName::IpAddress(addr.ip().into());
        let mut s = timeout(
            PROBE_WAIT,
            TlsConnector::from(Arc::clone(&CLIENT)).connect(name, tcp),
        )
        .await
        .ok()?
        .ok()?;
        let cert = s.get_ref().1.peer_certificates()?.first()?;
        let info = parse_cert(cert.as_ref());
        let mut id = Ident::default();
        if s.write_all(&http_request(addr)).await.is_ok() {
            let r = read_until(&mut s, HTTP_MAX, PROBE_WAIT, http_done).await;
            if r.starts_with(b"HTTP/") {
                id = parse_http(&r);
            }
        }
        id.tls = info;
        Some(id)
    }

    /// The parts of a DER certificate worth showing; `None` if it does not
    /// parse.
    #[must_use]
    pub fn parse_cert(der: &[u8]) -> Option<TlsInfo> {
        let (_, c) = X509Certificate::from_der(der).ok()?;
        let sans = c
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|e| {
                e.value
                    .general_names
                    .iter()
                    .filter_map(|n| match n {
                        GeneralName::DNSName(d) => Some(sanitize(d.as_bytes())),
                        GeneralName::IPAddress(b) => match b.len() {
                            4 => <[u8; 4]>::try_from(*b)
                                .ok()
                                .map(|a| IpAddr::from(a).to_string()),
                            16 => <[u8; 16]>::try_from(*b)
                                .ok()
                                .map(|a| IpAddr::from(a).to_string()),
                            _ => None,
                        },
                        _ => None,
                    })
                    .filter(|s| !s.is_empty())
                    .take(SANS_MAX)
                    .collect()
            })
            .unwrap_or_default();
        Some(TlsInfo {
            subject: sanitize(c.subject().to_string().as_bytes()),
            sans,
            issuer: sanitize(c.issuer().to_string().as_bytes()),
            not_after: c.validity().not_after.timestamp(),
        })
    }

    /// Client config that accepts any certificate: we record what a service
    /// presents, we never trust it. Handshake signatures are still checked,
    /// so the certificate shown is the one the server holds the key for.
    static CLIENT: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(AcceptAny(provider.signature_verification_algorithms));
        let cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Arc::new(cfg)
    });

    #[derive(Debug)]
    struct AcceptAny(WebPkiSupportedAlgorithms);

    impl ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.supported_schemes()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn ident_probes_for_hint_and_port() {
            assert_eq!(probes_for(Some("redis"), 1234), vec![Probe::Redis]);
            assert_eq!(probes_for(Some("HTTP"), 80), vec![Probe::Http]);
            assert_eq!(probes_for(Some("rtsp"), 80), vec![Probe::Rtsp, Probe::Http]);
            assert_eq!(probes_for(None, 1883), vec![Probe::Mqtt]);
            assert_eq!(probes_for(None, 554), vec![Probe::Rtsp]);
            assert_eq!(probes_for(Some("ssh"), 22), vec![]);
        }

        #[test]
        fn ident_http_done_rules() {
            assert!(!http_done(b"HTTP/1.0 200 OK\r\n"));
            assert!(http_done(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nab"));
            assert!(!http_done(
                b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nab"
            ));
            assert!(http_done(b"HTTP/1.0 200 OK\r\n\r\n<title>x</TITLE"));
            assert!(!http_done(
                b"HTTP/1.0 200 OK\r\nContent-Length: zz\r\n\r\nab"
            ));
            assert!(!http_done(b"HTTP/1.0 200 OK\r\nContent-Length\r\n\r\nab"));
        }

        #[test]
        fn ident_mqtt_connect_length_matches() {
            assert_eq!(MQTT_CONNECT[1] as usize, MQTT_CONNECT.len() - 2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ident_greeting_ssh() {
        let i = parse_greeting(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n");
        assert_eq!(i.product.as_deref(), Some("OpenSSH"));
        assert_eq!(i.version.as_deref(), Some("9.6p1"));
        let i = parse_greeting(b"SSH-2.0-OpenSSH_9.6");
        assert_eq!(i.product.as_deref(), Some("OpenSSH"));
        assert_eq!(i.version.as_deref(), Some("9.6"));
        let i = parse_greeting(b"SSH-2.0-dropbear_2022.83\r\n");
        assert_eq!(i.product.as_deref(), Some("dropbear"));
        assert_eq!(i.version.as_deref(), Some("2022.83"));
        let i = parse_greeting(b"SSH-2.0-Cisco\r\n");
        assert_eq!(i.product.as_deref(), Some("Cisco"));
        assert_eq!(i.version, None);
    }

    #[test]
    fn ident_greeting_mail_and_ftp_banners() {
        let i = parse_greeting(b"220 (vsFTPd 3.0.5)\r\n");
        assert_eq!(i.banner.as_deref(), Some("220 (vsFTPd 3.0.5)"));
        assert_eq!(i.product.as_deref(), Some("vsFTPd"));
        assert_eq!(i.version.as_deref(), Some("3.0.5"));
        let i = parse_greeting(b"220 mx.example.org ESMTP Postfix (Debian)\r\n");
        assert_eq!(i.product.as_deref(), Some("Postfix"));
        assert_eq!(i.version, None);
        let i = parse_greeting(b"220 mail ESMTP Exim 4.96 Mon, 1 Jan 2024\r\n");
        assert_eq!(i.product.as_deref(), Some("Exim"));
        assert_eq!(i.version.as_deref(), Some("4.96"));
        let i = parse_greeting(b"+OK Dovecot ready.\r\n");
        assert_eq!(i.banner.as_deref(), Some("+OK Dovecot ready."));
        assert_eq!(i.product.as_deref(), Some("Dovecot"));
        let i = parse_greeting(b"* OK [CAPABILITY IMAP4rev1] ready\r\nmore\r\n");
        assert_eq!(
            i.banner.as_deref(),
            Some("* OK [CAPABILITY IMAP4rev1] ready")
        );
        assert_eq!(i.product, None);
    }

    #[test]
    fn ident_greeting_other_text_is_banner() {
        let i = parse_greeting(b"hello there\nsecond");
        assert_eq!(i.banner.as_deref(), Some("hello there"));
        assert_eq!(parse_greeting(b""), Ident::default());
        assert_eq!(parse_greeting(b"\r\n\x00\x01"), Ident::default());
    }

    #[test]
    fn ident_greeting_garbage_and_truncation_do_not_panic() {
        for b in [
            &b"SSH-"[..],
            b"SSH-2.0-",
            b"SSH-2.0-_",
            b"SSH-2.0-_\xff\xfe",
            b"SSH-\xff\xff\xff",
            b"220",
            b"\xff\xfe\xfd\x00\x1b[2J",
            b"* OK",
        ] {
            let i = parse_greeting(b);
            for s in [&i.product, &i.version, &i.banner].into_iter().flatten() {
                assert!(s.len() <= crate::types::TEXT_MAX);
                assert!(!s.chars().any(char::is_control), "{s:?}");
            }
        }
        let long = [b"SSH-2.0-".as_slice(), &[b'A'; 100_000]].concat();
        let i = parse_greeting(&long);
        assert!(i.product.unwrap().len() <= crate::types::TEXT_MAX);
    }

    #[test]
    fn ident_http_server_and_title() {
        let r = b"HTTP/1.1 200 OK\r\nServer: nginx/1.27\r\nContent-Type: text/html\r\n\r\n\
                  <html><head><title>Synology DiskStation</title></head></html>";
        let i = parse_http(r);
        assert_eq!(i.product.as_deref(), Some("nginx"));
        assert_eq!(i.version.as_deref(), Some("1.27"));
        assert_eq!(i.title.as_deref(), Some("Synology DiskStation"));
        assert_eq!(i.banner.as_deref(), Some("HTTP/1.1 200 OK"));
    }

    #[test]
    fn ident_http_variants() {
        let i = parse_http(b"HTTP/1.0 200 OK\nserver: Apache/2.4.58 (Ubuntu)\n\n<TITLE lang=en>\n  A &amp; B </TITLE>");
        assert_eq!(i.product.as_deref(), Some("Apache"));
        assert_eq!(i.version.as_deref(), Some("2.4.58"));
        assert_eq!(i.title.as_deref(), Some("A & B"));
        let i = parse_http(b"HTTP/1.1 401 Unauthorized\r\nServer: lighttpd\r\n\r\n<titlebar>x</titlebar><title></title>");
        assert_eq!(i.product.as_deref(), Some("lighttpd"));
        assert_eq!(i.version, None);
        assert_eq!(i.title, None);
        // A header named like a title is not the page title.
        let i = parse_http(b"HTTP/1.1 200 OK\r\nX-Note: <title>no</title>\r\n\r\nbody");
        assert_eq!(i.title, None);
    }

    #[test]
    fn ident_http_only_reads_first_64k() {
        let mut r = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        r.resize(70 * 1024, b'a');
        r.extend_from_slice(b"<title>late</title>");
        assert_eq!(parse_http(&r).title, None);
    }

    #[test]
    fn ident_http_big_body_without_title_is_fast() {
        let mut r = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n".to_vec();
        r.resize(1024 * 1024, b'<');
        let t = std::time::Instant::now();
        let i = parse_http(&r);
        assert_eq!(i.title, None);
        assert!(
            t.elapsed() < std::time::Duration::from_millis(200),
            "{:?}",
            t.elapsed()
        );
    }

    #[test]
    fn ident_http_garbage_and_truncation_do_not_panic() {
        let full = b"HTTP/1.1 200 OK\r\nServer: nginx/1.27\r\n\r\n<title>T\xc3\xa9st</title>";
        for n in 0..=full.len() {
            let _ = parse_http(&full[..n]);
        }
        for b in [
            &b"\xff\xff\xff"[..],
            b"Server:",
            b"\r\n\r\n<title",
            b"\r\n\r\n<title>",
            b"HTTP/1.1\r\nServer: /\r\n\r\n<title>\x1b\x00</title>",
        ] {
            let i = parse_http(b);
            for s in [&i.product, &i.version, &i.title, &i.banner]
                .into_iter()
                .flatten()
            {
                assert!(!s.is_empty());
                assert!(!s.chars().any(char::is_control), "{s:?}");
            }
        }
    }

    #[test]
    fn ident_sanitize_hostile_bytes() {
        let s = sanitize(b"<script>\x1b[31mx\x00\xff");
        assert!(!s.contains('\x1b'));
        assert!(!s.contains('\0'));
        assert!(!s.contains("\u{fffd}\u{fffd}"));
        assert!(s.len() <= 256);
        let s = sanitize(b"a\xff\xfe\xfd\xfcb");
        assert_eq!(s, "a\u{fffd}b");
    }

    #[cfg(feature = "daemon")]
    #[test]
    fn ident_cert_parse() {
        let mut p = rcgen::CertificateParams::new(vec!["nas.local".to_string()]).unwrap();
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "nas.local");
        let kp = rcgen::KeyPair::generate().unwrap();
        let der = p.self_signed(&kp).unwrap().der().to_vec();
        let t = parse_cert(&der).expect("parsed");
        assert!(t.subject.contains("nas.local"), "{t:?}");
        assert_eq!(t.sans, vec!["nas.local".to_string()]);
        assert!(t.issuer.contains("nas.local"));
        assert!(t.not_after > 1_700_000_000);
    }

    #[cfg(feature = "daemon")]
    #[test]
    fn ident_cert_garbage_and_truncation_do_not_panic() {
        let p = rcgen::CertificateParams::new(vec!["a.b".to_string()]).unwrap();
        let kp = rcgen::KeyPair::generate().unwrap();
        let der = p.self_signed(&kp).unwrap().der().to_vec();
        for n in 0..der.len() {
            assert_eq!(parse_cert(&der[..n]), None, "len {n}");
        }
        assert_eq!(parse_cert(b"\x30\x82\xff\xff garbage"), None);
    }
}
