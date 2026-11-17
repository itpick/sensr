//! Downloading lists into a local cache.
//!
//! As OPNsense: a list is reused from the cache until it is older than the
//! policy's refresh interval (the shortest one when several policies use
//! it), and a failed download keeps the cached copy. sensr also revalidates
//! with `If-None-Match` / `If-Modified-Since`, so an unchanged list costs a
//! 304, and caps the size of a download.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The largest list accepted (the biggest curated lists are ~40 MB).
pub const MAX_LIST_BYTES: u64 = 256 << 20;

/// Result of a conditional download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// The server says the cached copy is current.
    NotModified,
    /// A new body was written to the destination.
    Body {
        /// `ETag`, if the server sent one.
        etag: Option<String>,
        /// `Last-Modified`, if the server sent one.
        last_modified: Option<String>,
    },
}

/// Fetch errors.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// Transport or HTTP failure.
    #[error("{0}")]
    Http(String),
    /// Writing the cache.
    #[error("writing the cache: {0}")]
    Io(#[from] io::Error),
}

/// Something that downloads a URL into a file (HTTP in production, a map
/// in tests).
pub trait Fetch: Sync {
    /// Download `url` into `dest`, conditionally on the validators.
    fn fetch(
        &self,
        url: &str,
        etag: Option<&str>,
        last_modified: Option<&str>,
        dest: &Path,
    ) -> Result<Fetched, FetchError>;
}

/// HTTP(S) with rustls and the webpki roots.
pub struct HttpFetcher {
    agent: ureq::Agent,
}

impl Default for HttpFetcher {
    fn default() -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(120)))
            .timeout_connect(Some(Duration::from_secs(15)))
            .user_agent("sensr-dns")
            .build()
            .into();
        Self { agent }
    }
}

impl Fetch for HttpFetcher {
    fn fetch(
        &self,
        url: &str,
        etag: Option<&str>,
        last_modified: Option<&str>,
        dest: &Path,
    ) -> Result<Fetched, FetchError> {
        let mut req = self.agent.get(url);
        if let Some(e) = etag {
            req = req.header("If-None-Match", e);
        }
        if let Some(l) = last_modified {
            req = req.header("If-Modified-Since", l);
        }
        let resp = req.call().map_err(|e| FetchError::Http(e.to_string()))?;
        if resp.status().as_u16() == 304 {
            return Ok(Fetched::NotModified);
        }
        if !resp.status().is_success() {
            return Err(FetchError::Http(format!("HTTP {}", resp.status())));
        }
        let header = |n: &str| {
            resp.headers()
                .get(n)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let (etag, last_modified) = (header("etag"), header("last-modified"));
        let mut reader = resp
            .into_body()
            .into_with_config()
            .limit(MAX_LIST_BYTES)
            .reader();
        let mut f = fs::File::create(dest)?;
        io::copy(&mut reader, &mut f).map_err(|e| FetchError::Http(e.to_string()))?;
        f.flush()?;
        f.sync_all()?;
        Ok(Fetched::Body {
            etag,
            last_modified,
        })
    }
}

/// What the cache knows about one list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// The URL.
    pub url: String,
    /// Validators from the last download.
    pub etag: Option<String>,
    /// Validators from the last download.
    pub last_modified: Option<String>,
    /// Unix time of the last successful download or revalidation.
    pub fetched: u64,
}

/// Outcome of refreshing one list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refreshed {
    /// The cached file, if there is one.
    pub path: Option<PathBuf>,
    /// Unix time the cached copy was last confirmed current.
    pub fetched: Option<u64>,
    /// Served from the cache without a download (fresh enough, revalidated
    /// as unchanged, or kept after a failure).
    pub from_cache: bool,
    /// Why the download failed, if it did.
    pub error: Option<String>,
}

/// The list cache (`<state>/cache`).
pub struct Cache {
    dir: PathBuf,
}

impl Cache {
    /// A cache in `dir` (created on first use).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn stem(url: &str) -> String {
        blake3::hash(url.as_bytes()).to_hex()[..24].to_owned()
    }

    /// The cached body for `url`.
    pub fn body_path(&self, url: &str) -> PathBuf {
        self.dir.join(format!("{}.list", Self::stem(url)))
    }

    fn meta_path(&self, url: &str) -> PathBuf {
        self.dir.join(format!("{}.json", Self::stem(url)))
    }

    /// The cache's record for `url`.
    pub fn meta(&self, url: &str) -> Option<Meta> {
        let text = fs::read_to_string(self.meta_path(url)).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn write_meta(&self, m: &Meta) -> io::Result<()> {
        let tmp = self.dir.join(format!(".{}.json.tmp", Self::stem(&m.url)));
        fs::write(&tmp, serde_json::to_vec_pretty(m).unwrap_or_default())?;
        fs::rename(tmp, self.meta_path(&m.url))
    }

    /// Brings `url` up to date: no request while the copy is younger than
    /// `max_age` seconds (unless `force`), else a conditional download.
    pub fn refresh(
        &self,
        fetcher: &dyn Fetch,
        url: &str,
        max_age: u64,
        force: bool,
        now: u64,
    ) -> Refreshed {
        let body = self.body_path(url);
        let meta = self.meta(url).filter(|_| body.exists());
        let cached = |error: Option<String>, meta: &Option<Meta>| Refreshed {
            path: meta.as_ref().map(|_| body.clone()),
            fetched: meta.as_ref().map(|m| m.fetched),
            from_cache: true,
            error,
        };
        if let Some(m) = &meta
            && !force
            && now.saturating_sub(m.fetched) < max_age
        {
            return cached(None, &meta);
        }
        if let Err(e) = fs::create_dir_all(&self.dir) {
            return cached(Some(e.to_string()), &meta);
        }
        let tmp = self.dir.join(format!(".{}.list.tmp", Self::stem(url)));
        let result = fetcher.fetch(
            url,
            meta.as_ref().and_then(|m| m.etag.as_deref()),
            meta.as_ref().and_then(|m| m.last_modified.as_deref()),
            &tmp,
        );
        match result {
            Ok(Fetched::NotModified) if meta.is_some() => {
                let m = Meta {
                    fetched: now,
                    ..meta.clone().unwrap_or_default()
                };
                let _ = self.write_meta(&m);
                cached(None, &Some(m))
            }
            Ok(Fetched::NotModified) => {
                // A 304 without a cached copy: the validators were stale.
                cached(
                    Some("server answered 304 but nothing is cached".into()),
                    &meta,
                )
            }
            Ok(Fetched::Body {
                etag,
                last_modified,
            }) => {
                let m = Meta {
                    url: url.to_owned(),
                    etag,
                    last_modified,
                    fetched: now,
                };
                match fs::rename(&tmp, &body).and_then(|_| self.write_meta(&m)) {
                    Ok(()) => Refreshed {
                        path: Some(body),
                        fetched: Some(now),
                        from_cache: false,
                        error: None,
                    },
                    Err(e) => cached(Some(e.to_string()), &meta),
                }
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                cached(Some(e.to_string()), &meta)
            }
        }
    }

    /// Removes cached lists no URL in `keep` refers to.
    pub fn prune(&self, keep: &[String]) {
        let keep: Vec<String> = keep.iter().map(|u| Self::stem(u)).collect();
        let Ok(dir) = fs::read_dir(&self.dir) else {
            return;
        };
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let stem = name
                .trim_start_matches('.')
                .split('.')
                .next()
                .unwrap_or_default();
            if !keep.iter().any(|k| k == stem) {
                let _ = fs::remove_file(e.path());
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::Mutex;

    /// A scripted fetcher: URL → body (`None`: fail), counting calls.
    #[derive(Default)]
    pub(crate) struct MapFetcher {
        pub(crate) bodies: Mutex<BTreeMap<String, Option<String>>>,
        pub(crate) calls: Mutex<Vec<String>>,
    }

    impl Fetch for MapFetcher {
        fn fetch(
            &self,
            url: &str,
            etag: Option<&str>,
            _: Option<&str>,
            dest: &Path,
        ) -> Result<Fetched, FetchError> {
            self.calls.lock().unwrap().push(url.to_owned());
            match self.bodies.lock().unwrap().get(url).cloned().flatten() {
                Some(b) => {
                    let tag = blake3::hash(b.as_bytes()).to_hex()[..8].to_owned();
                    if etag == Some(tag.as_str()) {
                        return Ok(Fetched::NotModified);
                    }
                    fs::write(dest, b)?;
                    Ok(Fetched::Body {
                        etag: Some(tag),
                        last_modified: None,
                    })
                }
                None => Err(FetchError::Http("HTTP 503 Service Unavailable".into())),
            }
        }
    }

    #[test]
    fn reuses_revalidates_and_keeps_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().join("cache"));
        let f = MapFetcher::default();
        let url = "https://lists.example/pro.txt";
        f.bodies
            .lock()
            .unwrap()
            .insert(url.into(), Some("*.ads.example.com\n".into()));
        let r = cache.refresh(&f, url, 3600, false, 1000);
        assert!(!r.from_cache && r.error.is_none());
        assert_eq!(
            fs::read_to_string(r.path.unwrap()).unwrap(),
            "*.ads.example.com\n"
        );
        // Fresh: no request.
        let r = cache.refresh(&f, url, 3600, false, 2000);
        assert!(r.from_cache);
        assert_eq!(f.calls.lock().unwrap().len(), 1);
        // Stale and unchanged: a 304, the copy is confirmed.
        let r = cache.refresh(&f, url, 3600, false, 9000);
        assert!(r.from_cache && r.error.is_none());
        assert_eq!(r.fetched, Some(9000));
        // Failing: the old copy stays, with the error.
        f.bodies.lock().unwrap().insert(url.into(), None);
        let r = cache.refresh(&f, url, 3600, true, 9500);
        assert!(r.from_cache);
        assert!(r.error.unwrap().contains("503"));
        assert!(r.path.is_some());
        // Nothing cached and failing: no file, an error.
        let r = cache.refresh(&f, "https://down.example/x", 3600, false, 1);
        assert!(r.path.is_none() && r.error.is_some());
        cache.prune(&[url.to_owned()]);
        assert_eq!(fs::read_dir(dir.path().join("cache")).unwrap().count(), 2);
    }

    #[test]
    fn http_fetcher_downloads_and_honours_etag() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                let mut s = stream.unwrap();
                let mut head = String::new();
                let mut r = BufReader::new(s.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                    head.push_str(&line);
                }
                let resp = if head.to_ascii_lowercase().contains("if-none-match: \"v1\"") {
                    "HTTP/1.1 304 Not Modified\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                        .to_owned()
                } else {
                    let body = "0.0.0.0 ads.example.com\n";
                    format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nETag: \"v1\"\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                };
                use std::io::Write as _;
                s.write_all(resp.as_bytes()).unwrap();
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("x");
        let url = format!("http://{addr}/list.txt");
        let f = HttpFetcher::default();
        let got = f.fetch(&url, None, None, &dest).unwrap();
        assert_eq!(
            got,
            Fetched::Body {
                etag: Some("\"v1\"".into()),
                last_modified: None
            }
        );
        assert_eq!(
            fs::read_to_string(&dest).unwrap(),
            "0.0.0.0 ads.example.com\n"
        );
        let got = f.fetch(&url, Some("\"v1\""), None, &dest).unwrap();
        assert_eq!(got, Fetched::NotModified);
    }
}
