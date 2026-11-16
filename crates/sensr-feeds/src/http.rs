//! Fetching: a [`Fetcher`] trait (so refresh logic is tested without a
//! network) and [`HttpFetcher`] on `ureq` with rustls.

use std::time::Duration;

use sensr_rules::alias::Auth;

/// Validators from a previous fetch, sent so an unchanged list costs a 304.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Conditional {
    /// `ETag` of the cached body
    pub etag: Option<String>,
    /// `Last-Modified` of the cached body
    pub last_modified: Option<String>,
}

/// Outcome of a successful request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetched {
    /// 200 with a body.
    Body {
        /// raw bytes (gzip/zip are left as they are; callers detect them)
        bytes: Vec<u8>,
        /// validators for the next request
        conditional: Conditional,
    },
    /// 304: the cached body is still current.
    NotModified,
}

/// Why a fetch failed. The caller keeps the last good contents.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct HttpError(pub String);

/// Something that GETs URLs.
pub trait Fetcher: Send + Sync {
    /// GET `url`; 200 and 304 are successes, anything else an error.
    fn get(&self, url: &str, auth: &Auth, cond: &Conditional) -> Result<Fetched, HttpError>;
}

/// Limits for [`HttpFetcher`].
#[derive(Clone, Debug)]
pub struct HttpOptions {
    /// whole-request timeout (upstream uses 120 s)
    pub timeout: Duration,
    /// largest body accepted
    pub max_bytes: u64,
}

impl Default for HttpOptions {
    fn default() -> Self {
        HttpOptions {
            timeout: Duration::from_secs(120),
            max_bytes: 256 * 1024 * 1024,
        }
    }
}

/// HTTPS client with the webpki root store.
pub struct HttpFetcher {
    agent: ureq::Agent,
    max_bytes: u64,
}

impl HttpFetcher {
    /// A client with `opts`.
    pub fn new(opts: HttpOptions) -> HttpFetcher {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(opts.timeout))
            .http_status_as_error(false)
            .user_agent(concat!("sensr/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        HttpFetcher {
            agent,
            max_bytes: opts.max_bytes,
        }
    }
}

impl Default for HttpFetcher {
    fn default() -> Self {
        HttpFetcher::new(HttpOptions::default())
    }
}

fn header(r: &ureq::http::Response<ureq::Body>, name: &str) -> Option<String> {
    r.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

impl Fetcher for HttpFetcher {
    fn get(&self, url: &str, auth: &Auth, cond: &Conditional) -> Result<Fetched, HttpError> {
        use base64::Engine as _;
        let mut req = self.agent.get(url);
        match auth {
            Auth::None => {}
            Auth::Basic { user, password } => {
                let token =
                    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
                req = req.header("Authorization", format!("Basic {token}"));
            }
            Auth::Bearer(t) => req = req.header("Authorization", format!("Bearer {t}")),
            Auth::Header { name, value } => req = req.header(name.as_str(), value.as_str()),
        }
        if let Some(e) = &cond.etag {
            req = req.header("If-None-Match", e.as_str());
        }
        if let Some(m) = &cond.last_modified {
            req = req.header("If-Modified-Since", m.as_str());
        }
        let mut resp = req.call().map_err(|e| HttpError(e.to_string()))?;
        match resp.status().as_u16() {
            304 => Ok(Fetched::NotModified),
            200 => {
                let conditional = Conditional {
                    etag: header(&resp, "etag"),
                    last_modified: header(&resp, "last-modified"),
                };
                let bytes = resp
                    .body_mut()
                    .with_config()
                    .limit(self.max_bytes)
                    .read_to_vec()
                    .map_err(|e| HttpError(format!("reading the body: {e}")))?;
                Ok(Fetched::Body { bytes, conditional })
            }
            s => Err(HttpError(format!("HTTP status {s}"))),
        }
    }
}

/// Decompresses gzip bodies (by magic number); other bodies pass through.
pub fn gunzip_if_needed(bytes: Vec<u8>, max: u64) -> Result<Vec<u8>, HttpError> {
    use std::io::Read;
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        flate2::read::MultiGzDecoder::new(bytes.as_slice())
            .take(max)
            .read_to_end(&mut out)
            .map_err(|e| HttpError(format!("gzip: {e}")))?;
        Ok(out)
    } else {
        Ok(bytes)
    }
}
