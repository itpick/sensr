//! Services › Runtime Guard: the server-rendered page, its plain-form endpoints and the
//! mock daemon behind them.

use leptos::prelude::*;
use scraper::{ElementRef, Html, Selector};
use sensr_ui::api::BackendHandle;
use sensr_ui::guard::{CONFIRM_WARNING, GuardQuery, GuardView, NOT_RUNNING, PER_PAGE};
use sensr_ui::mock::MockBackend;
use std::sync::Arc;

const LISTENERS: &str = "Unexpected listening sockets";
const SHELLS: &str = "Shells started by the web server";

fn render(f: impl FnOnce() -> AnyView) -> Html {
    let owner = Owner::new();
    let html = owner.with(|| f().to_html());
    Html::parse_fragment(&html)
}

fn sel(s: &str) -> Selector {
    Selector::parse(s).unwrap()
}

fn text(e: ElementRef<'_>) -> String {
    e.text().collect()
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// A mock with a seeded guard event database.
fn guard_mock() -> (tempfile::TempDir, MockBackend) {
    let d = tempfile::tempdir().unwrap();
    sensr_ui::mock::seed_guard(d.path(), now()).unwrap();
    let m = MockBackend::new().with_guard_dir(d.path());
    (d, m)
}

/// Runs a server function with `b` as the signed-in backend.
fn as_user<T>(
    b: &BackendHandle,
    f: impl std::future::Future<Output = Result<T, ServerFnError>>,
) -> Result<T, ServerFnError> {
    let owner = Owner::new();
    owner.with(|| {
        provide_context(b.clone());
        futures::executor::block_on(f)
    })
}

/// Runs a plain-form server function and returns where it redirects.
fn post<F, Fut>(b: &BackendHandle, f: F) -> String
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), ServerFnError>>,
{
    let (parts, _) = axum::http::Request::builder()
        .header("accept", "text/html")
        .body(())
        .unwrap()
        .into_parts();
    let res = leptos_axum::ResponseOptions::default();
    let owner = Owner::new();
    owner.with(|| {
        provide_context(b.clone());
        provide_context(parts);
        provide_context(res.clone());
        futures::executor::block_on(f()).unwrap();
    });
    let parts = res.0.read().unwrap();
    parts
        .headers
        .get("location")
        .expect("a redirect")
        .to_str()
        .expect("visible ASCII")
        .to_owned()
}

fn query(loc: &str) -> GuardQuery {
    let q = loc
        .strip_prefix("/ui/guard?")
        .unwrap_or_else(|| panic!("{loc}"));
    let pairs: Vec<(String, String)> = q
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_owned(), url_decode(v)))
        .collect();
    GuardQuery::from_query(|k| pairs.iter().find(|p| p.0 == k).map(|p| p.1.clone()))
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            let h = std::str::from_utf8(&b[i + 1..i + 3]).unwrap();
            out.push(u8::from_str_radix(h, 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn page(b: &BackendHandle, q: &GuardQuery) -> GuardView {
    as_user(
        b,
        sensr_ui::actions::guard_page(
            q.hook.clone(),
            q.q.clone(),
            q.range.clone(),
            q.offset,
            q.edit.clone(),
        ),
    )
    .unwrap()
}

fn body(p: GuardView, q: &GuardQuery) -> Html {
    let q = q.clone();
    render(move || sensr_ui::pages::guard_body(p, &q))
}

fn all(q: &GuardQuery) -> GuardQuery {
    GuardQuery {
        range: "all".into(),
        ..q.clone()
    }
}

fn table<'a>(doc: &'a Html, caption: &str) -> ElementRef<'a> {
    doc.select(&sel("table"))
        .find(|t| t.select(&sel("caption")).any(|c| text(c) == caption))
        .unwrap_or_else(|| panic!("no {caption} table"))
}

/// The cells of the table row whose text contains `needle`.
fn row(doc: &Html, caption: &str, needle: &str) -> Vec<String> {
    table(doc, caption)
        .select(&sel("tbody tr"))
        .find(|r| text(*r).contains(needle))
        .unwrap_or_else(|| panic!("no {needle} row in {caption}"))
        .select(&sel("td"))
        .map(|c| text(c).split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

fn writer() -> (tempfile::TempDir, BackendHandle) {
    let (d, m) = guard_mock();
    (d, Arc::new(m))
}

#[test]
fn inactive_rule_shows_reason() {
    let (_d, b) = writer();
    let q = all(&GuardQuery::default());
    let p = page(&b, &q);
    assert!(p.status.running && p.status.note.is_none());
    let doc = body(p, &q);
    let shells = row(&doc, "Rules", SHELLS);
    assert!(shells.iter().any(|c| c == "active"), "{shells:?}");
    assert!(shells.iter().any(|c| c == "3"), "hits: {shells:?}");
    let listeners = row(&doc, "Rules", LISTENERS);
    let state = listeners
        .iter()
        .find(|c| c.starts_with("inactive"))
        .unwrap_or_else(|| panic!("{listeners:?}"));
    assert!(
        state.contains("the listen program is not attached"),
        "the reason is shown: {state}"
    );
    // pack rules from the daemon, with their pack
    let module = row(&doc, "Rules", "core-module-load");
    assert!(module.iter().any(|c| c == "core"), "{module:?}");

    // the daemon is down: the configured rules are still listed, every one inactive
    let (_d, m) = guard_mock();
    let down: BackendHandle = Arc::new(m.with_guard_down());
    let p = page(&down, &q);
    assert!(!p.status.running);
    assert_eq!(p.status.note.as_deref(), Some(NOT_RUNNING));
    assert!(p.rules.iter().all(|r| !r.active && r.pack.is_none()));
    assert_eq!(p.rules.len(), 2);
    let doc = body(p, &q);
    let status = text(
        doc.select(&sel("section[aria-labelledby=guard-status]"))
            .next()
            .unwrap(),
    );
    assert!(status.contains(NOT_RUNNING), "{status}");
    for name in [SHELLS, LISTENERS] {
        let cells = row(&doc, "Rules", name);
        assert!(
            cells
                .iter()
                .any(|c| *c == format!("inactive {NOT_RUNNING}")),
            "{cells:?}"
        );
    }
}

#[test]
fn block_choice_warns_confirm() {
    let (_d, b) = writer();
    let q = GuardQuery::default();
    let doc = body(page(&b, &q), &q);
    let form = doc
        .select(&sel("form#guard-rule-form"))
        .next()
        .expect("the add rule form");
    assert_eq!(
        form.value().attr("action"),
        Some("/ui/fn/guard_rule_submit")
    );
    let action = form.select(&sel("select[name=action]")).next().unwrap();
    // new rules default to alert
    let chosen: Vec<_> = action
        .select(&sel("option[selected]"))
        .map(|o| o.value().attr("value").unwrap().to_owned())
        .collect();
    assert_eq!(chosen, ["alert"]);
    let warn_id = action
        .value()
        .attr("aria-describedby")
        .expect("the action describes its warning");
    let warn = form
        .select(&sel(&format!("#{warn_id}")))
        .next()
        .expect("the warning");
    assert_eq!(text(warn), CONFIRM_WARNING);
    assert!(warn.value().classes().any(|c| c == "confirm-warn"));
    // the stylesheet shows it only while Block is chosen
    let css = include_str!("../style/main.css");
    assert!(
        css.contains(".confirm-warn {\n  display: none;"),
        "hidden by default"
    );
    assert!(
        css.contains(".field:has(option[value=\"block\"]:checked) .confirm-warn"),
        "shown with Block"
    );
    assert_all_labelled(form);

    // saving a block rule says so, and applying it imposes the window
    let loc = post(&b, || {
        sensr_ui::actions::guard_rule_submit(
            None,
            Some("on".into()),
            "No curl to the LAN".into(),
            "connect".into(),
            "/usr/bin/curl".into(),
            String::new(),
            "net".into(),
            "192.168.0.0/16".into(),
            String::new(),
            "block".into(),
        )
    });
    assert_eq!(loc, "/ui/guard?saved=1&block=1");
    let msg = query(&loc).message().unwrap();
    assert!(!msg.0 && msg.1.contains(CONFIRM_WARNING), "{msg:?}");
    let p = page(&b, &q);
    assert!(p.staged);
    let loc = post(&b, sensr_ui::actions::guard_apply_form);
    assert_eq!(loc, "/ui/guard?applied=3&imposed=1");
    let aq = query(&loc);
    assert!(aq.message().unwrap().1.contains(CONFIRM_WARNING));
    let p = page(&b, &aq);
    let c = p.confirm.clone().expect("on probation");
    assert_eq!(c.revision, 3);
    assert!((110..=120).contains(&c.seconds_left), "{c:?}");
    let doc = body(p, &aq);
    let card = doc
        .select(&sel("section[aria-labelledby=guard-confirm]"))
        .next()
        .expect("the confirm card");
    assert!(text(card).contains(CONFIRM_WARNING));
    assert!(
        card.select(&sel("form[action='/ui/fn/guard_confirm_form'] button"))
            .any(|b| text(b) == "Confirm"),
    );
    let loc = post(&b, sensr_ui::actions::guard_confirm_form);
    assert_eq!(loc, "/ui/guard?confirmed=1");
    assert!(page(&b, &q).confirm.is_none());

    // an alert rule imposes nothing
    let (_d, b) = writer();
    post(&b, || {
        sensr_ui::actions::guard_rule_submit(
            None,
            Some("on".into()),
            "Note curl".into(),
            "exec".into(),
            String::new(),
            String::new(),
            "path_prefix".into(),
            "/usr/bin/curl".into(),
            String::new(),
            "alert".into(),
        )
    });
    assert_eq!(
        post(&b, sensr_ui::actions::guard_apply_form),
        "/ui/guard?applied=3"
    );
    assert!(page(&b, &q).confirm.is_none());
}

/// Every form control has a label (`<label for>`, `aria-label` or a wrapping label).
fn assert_all_labelled(scope: ElementRef<'_>) {
    let labels: Vec<String> = scope
        .select(&sel("label[for]"))
        .filter_map(|l| l.value().attr("for").map(str::to_owned))
        .collect();
    for c in scope.select(&sel("input:not([type=hidden]), select, textarea")) {
        let v = c.value();
        let ok = v.attr("aria-label").is_some()
            || v.attr("id")
                .is_some_and(|id| labels.iter().any(|l| l == id))
            || c.ancestors()
                .any(|a| a.value().as_element().is_some_and(|e| e.name() == "label"));
        assert!(ok, "unlabelled control {v:?}");
    }
}

#[test]
fn event_text_escaped() {
    let (d, b) = writer();
    let hostile = "<img src=x onerror=alert(1)>";
    {
        let mut s = sensr_guard::store::Store::open(&d.path().join("events.db")).unwrap();
        s.write_batch(&sensr_guard::events::Batch {
            rows: vec![sensr_guard::events::Row {
                ts: now(),
                ts_ms: 0,
                hook: "exec".into(),
                action: "alert".into(),
                blocked: false,
                rule_id: 0,
                exe: hostile.into(),
                target: "</td><script>alert(2)</script>".into(),
                unit: "\"><b>unit</b>".into(),
                pid: 1,
                uid: 0,
                count: 1,
            }],
        })
        .unwrap();
    }
    let q = all(&GuardQuery::default());
    let p = page(&b, &q);
    assert_eq!(p.events.rows[0].exe, hostile);
    let doc = body(p, &q);
    let events = table(&doc, "Events");
    assert_eq!(events.select(&sel("img, script, b")).count(), 0);
    let first = text(events.select(&sel("tbody tr")).next().unwrap());
    assert!(first.contains(hostile), "{first}");
    assert!(first.contains("</td><script>alert(2)</script>"), "{first}");
    assert!(first.contains("\"><b>unit</b>"), "{first}");
}

#[test]
fn menu_entry() {
    let menu = sensr_ui::menu::build(&[]);
    let services = menu.iter().find(|m| m.id == "Services").unwrap();
    let item = services
        .children
        .iter()
        .find(|c| c.id == "Guard")
        .expect("Services › Runtime Guard");
    assert_eq!(item.label, "Runtime Guard");
    assert_eq!(item.url.as_deref(), Some("/ui/guard"));
}

#[test]
fn kill_switch_needs_a_writer_and_a_running_daemon() {
    let (_d, b) = writer();
    let q = GuardQuery::default();
    let doc = body(page(&b, &q), &q);
    let status = doc
        .select(&sel("section[aria-labelledby=guard-status]"))
        .next()
        .unwrap();
    assert!(text(status).contains("Kill switch"));
    assert!(
        status
            .select(&sel("form[action='/ui/fn/guard_kill_switch_form'] button"))
            .any(|b| text(b) == "Turn kill switch on")
    );
    let loc = post(&b, || {
        sensr_ui::actions::guard_kill_switch_form("on".into())
    });
    assert_eq!(loc, "/ui/guard?kill=on");
    let p = page(&b, &q);
    assert!(p.status.kill_switch);
    let doc = body(p, &q);
    let status = text(
        doc.select(&sel("section[aria-labelledby=guard-status]"))
            .next()
            .unwrap(),
    );
    assert!(
        status.contains("on: nothing is blocked, alerts only"),
        "{status}"
    );
    assert_eq!(
        post(&b, || sensr_ui::actions::guard_kill_switch_form(
            "off".into()
        )),
        "/ui/guard?kill=off"
    );
    assert!(!page(&b, &q).status.kill_switch);

    // read-only: no buttons, and the endpoint refuses
    let (_d, m) = guard_mock();
    let ro: BackendHandle = Arc::new(m.with_privileges(&["page-all", "user-config-readonly"]));
    let p = page(&ro, &q);
    assert!(!p.can_write);
    let doc = body(p, &q);
    assert_eq!(doc.select(&sel("form[method=post]")).count(), 0);
    assert!(doc.select(&sel("form#guard-rule-form")).next().is_none());
    assert_eq!(
        post(&ro, || sensr_ui::actions::guard_kill_switch_form(
            "on".into()
        )),
        "/ui/guard?error=forbidden"
    );
    // the daemon is down
    let (_d, m) = guard_mock();
    let down: BackendHandle = Arc::new(m.with_guard_down());
    assert_eq!(
        post(&down, || sensr_ui::actions::guard_kill_switch_form(
            "on".into()
        )),
        "/ui/guard?error=not_running"
    );
    // callers without the guard privilege see nothing
    let (_d, m) = guard_mock();
    let none: BackendHandle = Arc::new(m.with_privileges(&["page-sensr-hosts"]));
    assert!(
        as_user(
            &none,
            sensr_ui::actions::guard_page(None, String::new(), "all".into(), 0, None)
        )
        .is_err()
    );
    assert_eq!(
        post(&none, || sensr_ui::actions::guard_kill_switch_form(
            "on".into()
        )),
        "/ui/guard?error=forbidden"
    );
}

#[test]
fn packs_switch_through_the_config_and_check_for_updates() {
    let (_d, b) = writer();
    let q = GuardQuery::default();
    let doc = body(page(&b, &q), &q);
    let core = row(&doc, "Packs", "core");
    assert_eq!(
        core[..5],
        ["core", "1.0.0", "built in", "verified", "active"]
    );
    let loc = post(&b, || {
        sensr_ui::actions::guard_pack_form("net-watch".into(), "off".into())
    });
    assert_eq!(loc, "/ui/guard?pack=net-watch&pack_on=0");
    let p = page(&b, &q);
    assert!(p.staged);
    let pack = p.packs.iter().find(|p| p.name == "net-watch").unwrap();
    assert!(!pack.enabled, "staged off");
    // a bad name never reaches the config
    assert_eq!(
        post(&b, || sensr_ui::actions::guard_pack_form(
            "../x".into(),
            "on".into()
        )),
        "/ui/guard?error=failed"
    );
    // Check for pack updates: the outcome comes back as codes
    let loc = post(&b, sensr_ui::actions::guard_check_packs_form);
    assert_eq!(
        loc,
        "/ui/guard?checked=core~1.0.0~1.0.0~current%2Cnet-watch~0.3.1~0.4.0~bad_signature"
    );
    let cq = query(&loc);
    let doc = body(page(&b, &cq), &cq);
    let packs = text(
        doc.select(&sel("section[aria-labelledby=guard-packs]"))
            .next()
            .unwrap(),
    );
    assert!(packs.contains("core: 1.0.0 is the latest."), "{packs}");
    assert!(
        packs.contains("net-watch: 0.4.0 not installed: its signature does not verify."),
        "{packs}"
    );
}

#[test]
fn events_filter_and_page() {
    let (_d, b) = writer();
    let q = all(&GuardQuery::default());
    let p = page(&b, &q);
    assert!(p.events.available);
    assert!(p.events.total > u64::from(PER_PAGE), "{}", p.events.total);
    assert_eq!(p.events.rows.len(), PER_PAGE as usize);
    let total = p.events.total;
    let doc = body(p, &q);
    let older = doc
        .select(&sel("nav[aria-label='Event pages'] a"))
        .find(|a| text(*a).contains("Older"))
        .expect("a link to older events");
    assert_eq!(
        older.value().attr("href"),
        Some("/ui/guard?offset=50#guard-events")
    );
    let next = page(
        &b,
        &GuardQuery {
            offset: PER_PAGE,
            ..q.clone()
        },
    );
    assert_eq!(next.events.rows.len() as u64, total - u64::from(PER_PAGE));
    // by hook
    let p = page(
        &b,
        &GuardQuery {
            hook: Some("module".into()),
            ..q.clone()
        },
    );
    assert!(!p.events.rows.is_empty());
    assert!(p.events.rows.iter().all(|r| r.hook == "module"));
    // by text, case-insensitive, in the executable, target or unit
    let p = page(
        &b,
        &GuardQuery {
            q: "NGINX".into(),
            ..q.clone()
        },
    );
    assert!(!p.events.rows.is_empty());
    assert!(p.events.rows.iter().all(|r| {
        (r.exe.clone() + &r.target + &r.unit)
            .to_lowercase()
            .contains("nginx")
    }));
    // by time: the seed's oldest events are two days old
    let p = page(
        &b,
        &GuardQuery {
            range: "24h".into(),
            ..q.clone()
        },
    );
    assert!(p.events.total < total, "{} < {total}", p.events.total);
    // the rule each event matched
    let p = page(&b, &q);
    assert!(p.events.rows.iter().any(|r| r.rule == SHELLS));
    // the daemon down: events still read, rules unknown
    let (_d, m) = guard_mock();
    let down: BackendHandle = Arc::new(m.with_guard_down());
    let p = page(&down, &q);
    assert!(p.events.available && !p.events.rows.is_empty());
    // no database yet
    let empty = tempfile::tempdir().unwrap();
    let b: BackendHandle = Arc::new(MockBackend::new().with_guard_dir(empty.path()));
    let p = page(&b, &q);
    assert!(!p.events.available);
    let doc = body(p, &q);
    assert!(text(doc.root_element()).contains("No events yet"));
}

#[test]
fn rule_form_saves_edits_and_deletes_with_codes_only() {
    let (_d, b) = writer();
    let submit = |b: &BackendHandle, key: Option<String>, target_kind: &str, target: &str| {
        let (k, t, tk) = (key, target.to_owned(), target_kind.to_owned());
        post(b, move || {
            sensr_ui::actions::guard_rule_submit(
                k,
                None,
                "x".into(),
                "exec".into(),
                String::new(),
                String::new(),
                tk,
                t,
                String::new(),
                "alert".into(),
            )
        })
    };
    // refused: the fields come back as codes, hostile text is never echoed
    for bad in ["etc", "\r\nSet-Cookie: x=1", "\"><script>"] {
        let loc = submit(&b, None, "path_prefix", bad);
        assert_eq!(loc, "/ui/guard?invalid=target", "{bad:?}");
    }
    let loc = submit(&b, None, "net", "10.0.0.0/8");
    assert_eq!(loc, "/ui/guard?invalid=target_kind");
    let q = query(&loc);
    assert_eq!(
        q.message(),
        Some((
            true,
            "The rule was not saved: check the marked fields.".into()
        ))
    );
    let doc = body(page(&b, &q), &q);
    let err = doc
        .select(&sel("form#guard-rule-form .field-error"))
        .map(text)
        .collect::<Vec<_>>();
    assert_eq!(
        err,
        [sensr_ui::guard::invalid_message("target_kind").to_owned()]
    );

    // edit: the form is filled from the stored rule; saving keeps its key
    let p = page(&b, &GuardQuery::default());
    let key = p
        .rules
        .iter()
        .find(|r| r.description == SHELLS)
        .and_then(|r| r.key.clone())
        .unwrap();
    let eq = GuardQuery {
        edit: Some(key.clone()),
        ..GuardQuery::default()
    };
    let p = page(&b, &eq);
    let edit = p.edit.clone().expect("the rule to edit");
    assert_eq!(edit.inputs["description"], SHELLS);
    assert_eq!(edit.inputs["unit"], "nginx.service");
    let doc = body(p, &eq);
    let form = doc.select(&sel("form#guard-rule-form")).next().unwrap();
    assert!(text(form).contains("Edit rule"));
    let key_input = form.select(&sel("input[name=key]")).next().unwrap();
    assert_eq!(key_input.value().attr("value"), Some(key.as_str()));
    let desc = form.select(&sel("input[name=description]")).next().unwrap();
    assert_eq!(desc.value().attr("value"), Some(SHELLS));
    assert_eq!(
        submit(&b, Some(key.clone()), "path_prefix", "/bin/"),
        "/ui/guard?saved=1"
    );
    let p = page(&b, &GuardQuery::default());
    let r = p
        .rules
        .iter()
        .find(|r| r.key.as_deref() == Some(&key))
        .unwrap();
    assert_eq!((r.description.as_str(), r.target.as_str()), ("x", "/bin/…"));
    assert_eq!(p.rules.iter().filter(|r| r.pack.is_none()).count(), 2);
    // an unchecked Enabled box turns the rule off
    assert!(
        !p.rules
            .iter()
            .find(|r| r.key.as_deref() == Some(&key))
            .unwrap()
            .active
    );
    // an unknown key is refused, not created
    assert_eq!(
        submit(&b, Some("ffff-0000".into()), "any", ""),
        "/ui/guard?error=no_rule"
    );
    assert_eq!(
        submit(&b, Some("../x".into()), "any", ""),
        "/ui/guard?error=no_rule"
    );
    // delete
    assert_eq!(
        post(&b, || sensr_ui::actions::guard_rule_delete(key.clone())),
        "/ui/guard?deleted=1"
    );
    let p = page(&b, &GuardQuery::default());
    assert!(!p.rules.iter().any(|r| r.key.as_deref() == Some(&key)));
    // read-only callers may not save
    let (_d, m) = guard_mock();
    let ro: BackendHandle = Arc::new(m.with_privileges(&["page-all", "user-config-readonly"]));
    assert_eq!(submit(&ro, None, "any", ""), "/ui/guard?error=forbidden");
}
