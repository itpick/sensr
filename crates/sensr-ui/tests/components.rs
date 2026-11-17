//! Component tests: render islands and chrome to HTML on the server and check structure and
//! accessibility basics (every control labelled, errors wired to fields, table semantics).

use leptos::prelude::*;
use scraper::{Html, Selector};
use sensr_ui::api::{FieldError, Pending};
use sensr_ui::form::{get_path, to_inputs};
use sensr_ui::grid::{GridQuery, run_query};
use sensr_ui::islands::{ApplyBanner, FormFields, GridIsland, SettingsFormIsland};
use sensr_ui::models::{FormId, GridId};

fn render(f: impl FnOnce() -> AnyView) -> Html {
    let owner = Owner::new();
    let html = owner.with(|| f().to_html());
    Html::parse_fragment(&html)
}

fn sel(s: &str) -> Selector {
    Selector::parse(s).unwrap()
}

/// Every form control has a visible label (`<label for>`), `aria-label`, or a wrapping label.
fn assert_all_labelled(doc: &Html, what: &str) {
    let labels: Vec<String> = doc
        .select(&sel("label[for]"))
        .filter_map(|l| l.value().attr("for").map(str::to_owned))
        .collect();
    for control in doc.select(&sel("input:not([type=hidden]), select, textarea")) {
        let v = control.value();
        let ok = v.attr("aria-label").is_some()
            || v.attr("id")
                .is_some_and(|id| labels.iter().any(|l| l == id))
            || control
                .ancestors()
                .any(|a| a.value().as_element().is_some_and(|e| e.name() == "label"));
        assert!(ok, "{what}: unlabelled control {:?}", v);
    }
}

const FORMS: [FormId; 5] = [
    FormId::SystemGeneral,
    FormId::Interface,
    FormId::SourceNatMode,
    FormId::DhcpSettings,
    FormId::UnboundGeneral,
];

const GRIDS: [GridId; 10] = [
    GridId::Assignments,
    GridId::Aliases,
    GridId::FilterRules,
    GridId::SourceNat,
    GridId::PortForwards,
    GridId::DhcpRanges,
    GridId::StaticMaps,
    GridId::HostOverrides,
    GridId::WgInstances,
    GridId::WgPeers,
];

#[test]
fn settings_forms_render_every_field_labelled() {
    let seed = sensr_ui::mock::seed();
    for form in FORMS {
        let initial = sensr_ui::adapt::form_to_view(form, &seed, &form.scope(&None)).unwrap();
        let doc = render(|| {
            view! { <SettingsFormIsland form scope=None initial choices=Default::default()/> }
                .into_any()
        });
        assert_all_labelled(&doc, &format!("{form:?}"));
        let controls = doc
            .select(&sel("form input, form select, form textarea"))
            .count();
        assert_eq!(
            controls,
            form.fields().len(),
            "{form:?}: one control per field"
        );
        assert!(doc.select(&sel("button[type=submit]")).next().is_some());
        // Help text is referenced by its input.
        for help in doc.select(&sel("p.help")) {
            let id = help.value().attr("id").unwrap();
            let referenced = doc.select(&sel("[aria-describedby]")).any(|e| {
                e.value()
                    .attr("aria-describedby")
                    .unwrap()
                    .split(' ')
                    .any(|x| x == id)
            });
            assert!(referenced, "{form:?}: help {id} not referenced");
        }
    }
}

#[test]
fn field_errors_attach_to_their_field() {
    let fields = FormId::SystemGeneral.fields();
    let doc = render(|| {
        let values = RwSignal::new(to_inputs(fields, &serde_json::json!({})));
        let errors = RwSignal::new(vec![FieldError::new("hostname", "Bad host name.")]);
        view! { <FormFields fields form_id="f".to_owned() values errors/> }.into_any()
    });
    let input = doc
        .select(&sel("#f--hostname"))
        .next()
        .expect("hostname input");
    assert_eq!(input.value().attr("aria-invalid"), Some("true"));
    let described = input.value().attr("aria-describedby").unwrap();
    assert!(described.split(' ').any(|x| x == "f--hostname-err"));
    let err = doc.select(&sel("#f--hostname-err")).next().unwrap();
    assert_eq!(err.text().collect::<String>(), "Bad host name.");
    // Other fields stay valid.
    let domain = doc.select(&sel("#f--domain")).next().unwrap();
    assert_eq!(domain.value().attr("aria-invalid"), None);
}

#[test]
fn grids_render_rows_with_table_semantics() {
    let seed = sensr_ui::mock::seed();
    for grid in GRIDS {
        let scope = grid.scope(&None);
        let store = sensr_ui::adapt::store(grid, &scope, &seed);
        let (sensr_ui::adapt::Store::Map(p) | sensr_ui::adapt::Store::Array(p)) = &store;
        let items: Vec<serde_json::Value> = match get_path(&seed, p).unwrap() {
            serde_json::Value::Object(m) => m.values().cloned().collect(),
            serde_json::Value::Array(a) => a.clone(),
            _ => unreachable!(),
        };
        let rows: Vec<_> = items
            .iter()
            .filter(|i| sensr_ui::adapt::in_scope(grid, &scope, &seed, i))
            .map(|i| sensr_ui::adapt::to_view(grid, &seed, i))
            .collect();
        let page = run_query(&rows, grid.columns(), &GridQuery::default());
        let n = page.rows.len();
        assert!(n > 0, "{grid:?}: seed has rows");
        let doc = render(|| {
            view! { <GridIsland grid scope=None initial=page label="item".to_owned() choices=Default::default()/> }.into_any()
        });
        assert_all_labelled(&doc, &format!("{grid:?}"));
        assert_eq!(doc.select(&sel("tbody tr")).count(), n, "{grid:?}");
        assert_eq!(
            doc.select(&sel("thead th[scope=col]")).count(),
            grid.columns().len() + 2,
            "{grid:?}: select + columns + actions"
        );
        for th in doc.select(&sel("thead th[aria-sort]")) {
            assert_eq!(th.value().attr("aria-sort"), Some("none"));
        }
        for b in doc.select(&sel("tbody button")) {
            assert!(
                b.value().attr("aria-label").is_some(),
                "{grid:?}: icon button without a name"
            );
        }
        assert_eq!(
            doc.select(&sel(".drag-handle")).count(),
            if grid.meta().ordered { n } else { 0 },
            "{grid:?}: reorder controls only on ordered grids"
        );
        assert!(doc.select(&sel("dialog[aria-labelledby]")).next().is_some());
    }
}

#[test]
fn apply_banner_states() {
    let clean = render(|| view! { <ApplyBanner initial=Pending::default()/> }.into_any());
    assert!(clean.select(&sel(".banner")).next().is_none());

    let dirty = Pending {
        changed: vec!["firewall".into()],
        ..Default::default()
    };
    let doc = render(|| view! { <ApplyBanner initial=dirty/> }.into_any());
    let text: String = doc.root_element().text().collect();
    assert!(text.contains("You must apply the changes"));
    assert!(text.contains("Changed: firewall."));
    assert!(
        doc.select(&sel("button"))
            .any(|b| b.text().collect::<String>() == "Apply")
    );

    let probation = Pending {
        changed: vec![],
        confirm: Some(sensr_ui::api::ConfirmWindow {
            revision: 7,
            deadline: 1_060,
        }),
        now: 1_000,
    };
    let doc = render(|| view! { <ApplyBanner initial=probation/> }.into_any());
    let text: String = doc.root_element().text().collect();
    assert!(text.contains("Revision 7"), "{text}");
    assert!(text.contains("in 60 s"), "{text}");
    assert!(
        doc.select(&sel("button"))
            .any(|b| b.text().collect::<String>() == "Keep changes")
    );
}

#[test]
fn menu_tree_marks_current_page() {
    use sensr_ui::app::MenuTree;
    let menu = sensr_ui::menu::build(&[]);
    let doc = render(|| view! { <MenuTree menu path="/ui/firewall/alias".to_owned()/> }.into_any());
    let current: Vec<_> = doc.select(&sel("a[aria-current=page]")).collect();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].value().attr("href"), Some("/ui/firewall/alias"));
    let open: Vec<String> = doc
        .select(&sel("details[open] > summary"))
        .map(|s| s.text().collect::<String>())
        .collect();
    assert_eq!(open, ["Firewall"]);
    assert!(
        doc.select(&sel("nav[aria-label='Main menu']"))
            .next()
            .is_some()
    );
}

fn block<T>(f: futures::future::BoxFuture<'_, T>) -> T {
    futures::executor::block_on(f)
}

fn mock_runtime<T: serde::de::DeserializeOwned + Default>(
    section: sensr_ui::runtime::RuntimeSection,
) -> T {
    use sensr_ui::api::Backend;
    let m = sensr_ui::mock::MockBackend::with_clock(Box::new(|| 1_794_787_200));
    sensr_ui::runtime::parse(block(m.runtime(section)).unwrap())
}

fn text(e: scraper::ElementRef<'_>) -> String {
    e.text().collect()
}

#[test]
fn gateway_status_page_shows_badges_markers_and_groups() {
    use sensr_ui::islands::GatewaysLive;
    use sensr_ui::runtime::{GatewayState, GatewaysView, RuntimeSection};
    let mut initial: GatewaysView = mock_runtime(RuntimeSection::Gateways);
    initial.gateways[0].status = GatewayState::Down;
    initial.gateways.push(sensr_ui::runtime::GatewayRow {
        name: "LTE".into(),
        status: GatewayState::ForceDown,
        ..Default::default()
    });
    let doc = render(|| view! { <GatewaysLive initial/> }.into_any());
    let rows: Vec<_> = doc.select(&sel(".gw-table tbody tr")).collect();
    assert_eq!(rows.len(), 4);
    assert_eq!(doc.select(&sel(".gw-table thead th[scope=col]")).count(), 9);
    let row = |name: &str| {
        rows.iter()
            .find(|r| text(**r).contains(name))
            .copied()
            .unwrap()
    };
    // Colour per status: red for down, amber for latency, green for online.
    let badge = |name: &str| {
        let r = row(name);
        let b = r.select(&sel("td:last-child .pill")).next().unwrap();
        (b.value().attr("class").unwrap().to_owned(), text(b))
    };
    assert_eq!(badge("WAN_DHCP6"), ("pill pill-on".into(), "Online".into()));
    assert_eq!(
        badge("BACKUP_GW"),
        ("pill pill-warn".into(), "Latency".into())
    );
    assert_eq!(
        badge("LTE"),
        ("pill pill-off".into(), "Offline (forced)".into())
    );
    let first = text(rows[0]);
    assert!(
        first.contains("WAN_DHCP") && first.contains("Offline"),
        "{first}"
    );
    // The default gateway is marked; the backup is not.
    assert!(text(row("WAN_DHCP6")).contains("active"));
    assert!(!text(row("BACKUP_GW")).contains("active"));
    let backup = text(row("BACKUP_GW"));
    assert!(backup.contains("198.51.100.1") && backup.contains("198.51.100.53"));
    assert!(
        backup.contains(" ms") && backup.contains("2.0 %"),
        "{backup}"
    );
    // LTE has no data yet: OPNsense's placeholder.
    assert!(text(row("LTE")).contains('~'));
    // Groups with their active members.
    let groups: String = doc
        .select(&sel("[aria-labelledby=gw-groups] tbody tr"))
        .map(text)
        .collect();
    assert!(
        groups.contains("WAN_FAILOVER") && groups.contains("WAN_DHCP"),
        "{groups}"
    );
}

#[test]
fn gateway_status_page_without_monitor_says_so() {
    use sensr_ui::islands::GatewaysLive;
    let doc = render(|| view! { <GatewaysLive initial=Default::default()/> }.into_any());
    let all = text(doc.root_element());
    assert!(all.contains("No gateways are monitored."));
    assert!(all.contains("No gateway groups."));
}

#[test]
fn dashboard_gateways_widget_is_filled() {
    use sensr_ui::api::Backend;
    use sensr_ui::islands::DashboardLive;
    use sensr_ui::runtime::{GatewaysView, RuntimeSection};
    let m = sensr_ui::mock::MockBackend::with_clock(Box::new(|| 1_794_787_200));
    let mut initial = block(m.status()).unwrap();
    initial.gateways = mock_runtime::<GatewaysView>(RuntimeSection::Gateways).gateways;
    let doc = render(|| view! { <DashboardLive initial/> }.into_any());
    let items: Vec<String> = doc.select(&sel(".gw-list li")).map(text).collect();
    assert_eq!(items.len(), 3);
    assert!(items[0].contains("WAN_DHCP") && items[0].contains("(active)"));
    assert!(items[0].contains("RTT") && items[0].contains("RTTd") && items[0].contains("Loss"));
    assert!(items[2].contains("Latency") && !items[2].contains("(active)"));

    initial = block(m.status()).unwrap();
    let doc = render(|| view! { <DashboardLive initial/> }.into_any());
    assert!(text(doc.root_element()).contains("No gateway data."));
}

#[test]
fn alias_grid_shows_feed_status_with_error_badge() {
    use sensr_ui::runtime::AliasFeed;
    let seed = sensr_ui::mock::seed();
    let mut rows: Vec<_> = get_path(&seed, "firewall.aliases")
        .unwrap()
        .as_object()
        .unwrap()
        .values()
        .map(|i| sensr_ui::adapt::to_view(GridId::Aliases, &seed, i))
        .collect();
    let feeds = [
        AliasFeed {
            name: "spamhaus_drop".into(),
            kind: "url_table".into(),
            entries: 1234,
            updated_at: Some(1_794_787_200),
            ..Default::default()
        },
        AliasFeed {
            name: "nas".into(),
            error: Some("HTTP 503".into()),
            ..Default::default()
        },
    ];
    sensr_ui::adapt::add_feed_status(&mut rows, &feeds);
    let page = run_query(&rows, GridId::Aliases.columns(), &GridQuery::default());
    let doc = render(|| {
        view! { <GridIsland grid=GridId::Aliases scope=None initial=page label="alias".to_owned() choices=Default::default()/> }.into_any()
    });
    let heads: Vec<String> = doc.select(&sel("thead th[scope=col]")).map(text).collect();
    assert!(
        heads.iter().any(|h| h.trim() == "Loaded")
            && heads.iter().any(|h| h.trim() == "Last updated"),
        "{heads:?}"
    );
    let tr = |name: &str| {
        doc.select(&sel("tbody tr"))
            .find(|r| text(*r).contains(name))
            .unwrap()
    };
    let ok = text(tr("spamhaus_drop"));
    assert!(
        ok.contains("1234") && ok.contains("2026-11-16 00:00:00 UTC"),
        "{ok}"
    );
    let bad = tr("nas");
    let badge = bad.select(&sel(".pill-off")).next().expect("error badge");
    assert_eq!(badge.value().attr("title"), Some("HTTP 503"));
    assert!(text(bad).contains("never"));
    // Aliases without a feed have no badge.
    assert!(tr("web_ports").select(&sel(".pill-off")).next().is_none());
}

#[test]
fn ipv6_panel_shows_prefix_lifetimes_and_deprecated_subnets() {
    use sensr_ui::pages::Ipv6Prefixes;
    use sensr_ui::runtime::{Ipv6Status, RuntimeSection};
    let status = Ipv6Status {
        uplinks: mock_runtime(RuntimeSection::Ipv6),
        now: 1_794_787_200,
    };
    let doc = render(|| view! { <Ipv6Prefixes status/> }.into_any());
    let all = text(doc.root_element());
    assert!(all.contains("2001:db8:42::/56"), "{all}");
    assert!(all.contains("30m 0s") && all.contains("1h 30m"), "{all}");
    let rows: Vec<_> = doc.select(&sel("tbody tr")).collect();
    assert_eq!(rows.len(), 2);
    assert!(text(rows[0]).contains("2001:db8:42:1::/64") && text(rows[0]).contains("preferred"));
    assert!(text(rows[1]).contains("deprecated"));
    assert_eq!(rows[1].value().attr("class"), Some("disabled"));
    // The withdrawn /56 is listed too.
    assert!(all.contains("2001:db8:17::/56"));

    let empty = render(|| view! { <Ipv6Prefixes status=Ipv6Status::default()/> }.into_any());
    assert!(text(empty.root_element()).contains("No interface requests a delegated prefix."));
}
