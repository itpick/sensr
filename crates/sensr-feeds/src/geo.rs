//! Country databases for GeoIP aliases. Three formats are understood (as
//! upstream's `GEOIP.process_zip`/`process_gzip`, plus DB-IP): a MaxMind
//! GeoLite2 country CSV zip, an IPinfo country CSV (`network,…,country_code`
//! header) and DB-IP's range CSV (`first,last,…,cc`). The default source is
//! DB-IP Lite: free, no account, CC BY 4.0 ("IP Geolocation by DB-IP",
//! <https://db-ip.com>).
//!
//! Only the countries some alias uses are kept, one file per country and
//! family (`<CC>-IPv4`, one network per line), so the store stays small on an
//! SD card; a newly used country triggers a fresh download.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use sensr_rules::alias::geoip as mm;
use sensr_rules::alias::ipset;
use sensr_rules::ir::IpFamily;

use crate::cache::write_atomic;

/// `(country, family)` → networks.
pub type CountryNets = BTreeMap<(String, IpFamily), Vec<IpNet>>;

/// Attribution the UI shows next to GeoIP aliases fed by the default source.
pub const DBIP_ATTRIBUTION: &str = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0";

/// DB-IP Lite country CSV for a month (published monthly).
pub fn dbip_url(year: i32, month: u32) -> String {
    format!("https://download.db-ip.com/free/dbip-country-lite-{year:04}-{month:02}.csv.gz")
}

/// Calendar year and month of a Unix time (UTC).
pub fn year_month(unix: u64) -> (i32, u32) {
    // civil-from-days (Howard Hinnant), days since 1970-01-01
    let z = (unix / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = (yoe + era * 400 + i64::from(month <= 2)) as i32;
    (year, month)
}

/// The month before `(year, month)`.
pub fn previous_month(year: i32, month: u32) -> (i32, u32) {
    if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    }
}

/// Why a database could not be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("GeoIP database: {0}")]
pub struct GeoError(pub String);

fn family(n: &IpNet) -> IpFamily {
    match n {
        IpNet::V4(_) => IpFamily::V4,
        IpNet::V6(_) => IpFamily::V6,
    }
}

fn keep(wanted: Option<&BTreeSet<String>>, cc: &str) -> bool {
    wanted.is_none_or(|w| w.contains(cc))
}

fn unquote(s: &str) -> &str {
    s.trim().trim_matches('"')
}

fn is_cc(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Parses a database body (already decompressed if it was gzip). `wanted`
/// limits the countries kept.
pub fn parse(body: &[u8], wanted: Option<&BTreeSet<String>>) -> Result<CountryNets, GeoError> {
    if body.starts_with(b"PK\x03\x04") {
        return parse_maxmind_zip(body, wanted);
    }
    let text = std::str::from_utf8(body).map_err(|_| GeoError("not UTF-8 text".into()))?;
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let Some(first) = lines.next() else {
        return Err(GeoError("empty".into()));
    };
    let header: Vec<&str> = first.split(',').map(unquote).collect();
    let mut out = CountryNets::new();
    if let (Some(net_i), Some(cc_i)) = (
        header.iter().position(|h| *h == "network"),
        header.iter().position(|h| *h == "country_code"),
    ) {
        // IPinfo: network,…,country_code,…
        for l in lines {
            let f: Vec<&str> = l.split(',').map(unquote).collect();
            let (Some(net), Some(cc)) = (f.get(net_i), f.get(cc_i)) else {
                continue;
            };
            let (Ok(net), true) = (net.parse::<IpNet>(), is_cc(cc)) else {
                continue;
            };
            if keep(wanted, cc) {
                out.entry(((*cc).to_owned(), family(&net)))
                    .or_default()
                    .push(net.trunc());
            }
        }
    } else {
        // DB-IP: first,last,cc or first,last,continent,…,cc,… (7 fields)
        for l in std::iter::once(first).chain(lines) {
            let f: Vec<&str> = l.split(',').map(unquote).collect();
            let cc = match f.len() {
                3 => f[2],
                n if n >= 5 => f[4],
                _ => continue,
            };
            let (Ok(lo), Ok(hi)) = (f[0].parse::<IpAddr>(), f[1].parse::<IpAddr>()) else {
                continue;
            };
            if !is_cc(cc) || !keep(wanted, cc) || lo.is_ipv4() != hi.is_ipv4() || lo > hi {
                continue;
            }
            let fam = if lo.is_ipv4() {
                IpFamily::V4
            } else {
                IpFamily::V6
            };
            out.entry((cc.to_owned(), fam))
                .or_default()
                .extend(ipset::summarize(lo, hi));
        }
    }
    if out.is_empty() && wanted.is_none_or(|w| !w.is_empty()) {
        // a valid database has countries; an HTML error page has none
        if !text.contains(',') {
            return Err(GeoError("no CSV records".into()));
        }
    }
    Ok(out)
}

fn parse_maxmind_zip(
    body: &[u8],
    wanted: Option<&BTreeSet<String>>,
) -> Result<CountryNets, GeoError> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(body))
        .map_err(|e| GeoError(format!("zip: {e}")))?;
    let mut locations = None;
    let mut blocks: Vec<(IpFamily, String)> = Vec::new();
    for i in 0..z.len() {
        let mut f = z.by_index(i).map_err(|e| GeoError(format!("zip: {e}")))?;
        let name = f.name().map(|n| n.to_ascii_lowercase()).unwrap_or_default();
        let which = if name.contains("locations-en.csv") {
            0
        } else if name.contains("ipv4.csv") {
            4
        } else if name.contains("ipv6.csv") {
            6
        } else {
            continue;
        };
        let mut s = String::new();
        f.read_to_string(&mut s)
            .map_err(|e| GeoError(format!("zip member {name}: {e}")))?;
        match which {
            0 => locations = Some(s),
            4 => blocks.push((IpFamily::V4, s)),
            _ => blocks.push((IpFamily::V6, s)),
        }
    }
    let Some(loc) = locations else {
        return Err(GeoError("zip has no country locations file".into()));
    };
    let refs: Vec<(IpFamily, &str)> = blocks.iter().map(|(f, s)| (*f, s.as_str())).collect();
    let mut all = mm::process(&loc, &refs);
    all.retain(|(cc, _), _| keep(wanted, cc));
    Ok(all)
}

/// The per-country files.
#[derive(Clone, Debug)]
pub struct GeoStore {
    dir: PathBuf,
}

impl GeoStore {
    /// Files under `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> GeoStore {
        GeoStore { dir: dir.into() }
    }

    fn path(&self, cc: &str, fam: IpFamily) -> PathBuf {
        let f = match fam {
            IpFamily::V4 => "IPv4",
            IpFamily::V6 => "IPv6",
        };
        self.dir.join(format!("{}-{f}", cc.to_ascii_uppercase()))
    }

    /// True if `cc` has been stored (possibly empty for one family).
    pub fn has(&self, cc: &str) -> bool {
        IpFamily::BOTH.iter().any(|f| self.path(cc, *f).exists())
    }

    /// Replaces the files of every country in `countries` with `nets`
    /// (countries absent from the database get empty files, so they count as
    /// stored and do not trigger downloads forever).
    pub fn store(
        &self,
        countries: &BTreeSet<String>,
        nets: &CountryNets,
    ) -> std::io::Result<usize> {
        let mut total = 0;
        for cc in countries {
            for fam in IpFamily::BOTH {
                let v = nets
                    .get(&(cc.clone(), fam))
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                total += v.len();
                let mut text = String::with_capacity(v.len() * 20);
                for n in v {
                    text.push_str(&n.to_string());
                    text.push('\n');
                }
                write_atomic(&self.path(cc, fam), text.as_bytes())?;
            }
        }
        Ok(total)
    }

    /// Networks of `cc` in `fam` (empty when unknown).
    pub fn lookup(&self, cc: &str, fam: IpFamily) -> Vec<IpNet> {
        read_nets(&self.path(cc, fam))
    }
}

/// One network per line; anything else is skipped.
pub fn read_nets(path: &Path) -> Vec<IpNet> {
    std::fs::read_to_string(path)
        .map(|s| s.lines().filter_map(|l| l.trim().parse().ok()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn dbip_three_and_seven_field_rows() {
        let body = "1.0.0.0,1.0.0.255,AU\n\
                    \"198.51.100.0\",\"198.51.100.255\",\"ZZ\"\n\
                    2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,ZZ\n\
                    192.0.2.0,192.0.2.127,EU,Europe,YY,1,Somewhere\n";
        let db = parse(body.as_bytes(), Some(&set(&["ZZ", "YY"]))).unwrap();
        assert_eq!(
            db[&("ZZ".into(), IpFamily::V4)],
            vec!["198.51.100.0/24".parse::<IpNet>().unwrap()]
        );
        assert_eq!(
            db[&("ZZ".into(), IpFamily::V6)],
            vec!["2001:db8::/32".parse::<IpNet>().unwrap()]
        );
        assert_eq!(
            db[&("YY".into(), IpFamily::V4)],
            vec!["192.0.2.0/25".parse::<IpNet>().unwrap()]
        );
        assert!(!db.contains_key(&("AU".into(), IpFamily::V4)));
    }

    #[test]
    fn dbip_ranges_become_minimal_cidrs() {
        let db = parse(b"192.0.2.1,192.0.2.6,ZZ\n", None).unwrap();
        let v: Vec<String> = db[&("ZZ".into(), IpFamily::V4)]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            v,
            [
                "192.0.2.1/32",
                "192.0.2.2/31",
                "192.0.2.4/31",
                "192.0.2.6/32"
            ]
        );
    }

    #[test]
    fn ipinfo_header_format() {
        let body = "network,country,country_code,continent,continent_code\n\
                    198.51.100.0/25,Nowhere,ZZ,Oceania,OC\n\
                    2001:db8:1::/48,Nowhere,ZZ,Oceania,OC\n";
        let db = parse(body.as_bytes(), None).unwrap();
        assert_eq!(db[&("ZZ".into(), IpFamily::V4)].len(), 1);
        assert_eq!(db[&("ZZ".into(), IpFamily::V6)].len(), 1);
    }

    #[test]
    fn html_error_pages_are_rejected() {
        assert!(parse(b"<html><body>404</body></html>", None).is_err());
        assert!(parse(b"", None).is_err());
    }

    #[test]
    fn calendar_months() {
        // 2026-11-16 12:00 UTC
        assert_eq!(year_month(1_794_830_400), (2026, 11));
        assert_eq!(year_month(0), (1970, 1));
        // 2024-02-29
        assert_eq!(year_month(1_709_164_800), (2024, 2));
        assert_eq!(previous_month(2027, 1), (2026, 12));
        assert_eq!(
            dbip_url(2026, 11),
            "https://download.db-ip.com/free/dbip-country-lite-2026-11.csv.gz"
        );
    }

    #[test]
    fn store_and_lookup() {
        let d = tempfile::tempdir().unwrap();
        let g = GeoStore::new(d.path());
        let db = parse(b"198.51.100.0,198.51.100.255,ZZ\n", None).unwrap();
        g.store(&set(&["ZZ", "QQ"]), &db).unwrap();
        assert!(g.has("ZZ") && g.has("QQ") && !g.has("XX"));
        assert_eq!(g.lookup("ZZ", IpFamily::V4).len(), 1);
        assert!(g.lookup("QQ", IpFamily::V4).is_empty());
    }
}
