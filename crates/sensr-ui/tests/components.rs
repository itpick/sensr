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

const FORMS: [FormId; 12] = [
    FormId::SystemGeneral,
    FormId::Interface,
    FormId::SourceNatMode,
    FormId::DhcpSettings,
    FormId::UnboundGeneral,
    FormId::UnboundAdvanced,
    FormId::UnboundServeExpired,
    FormId::UnboundLogging,
    FormId::UnboundCache,
    FormId::UnboundAclDefault,
    FormId::UnboundForwarding,
    FormId::IdsSettings,
];

const GRIDS: [GridId; 13] = [
    GridId::Assignments,
    GridId::Aliases,
    GridId::FilterRules,
    GridId::SourceNat,
    GridId::PortForwards,
    GridId::DhcpRanges,
    GridId::StaticMaps,
    GridId::HostOverrides,
    GridId::AccessLists,
    GridId::Forwarders,
    GridId::Blocklists,
    GridId::WgInstances,
    GridId::WgPeers,
    GridId::IdsSuppressions,
    GridId::IdsUserRules,
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

    let alert = Pending {
        alert: Some("config.xml not imported: see import-report.txt".into()),
        ..Default::default()
    };
    let doc = render(|| view! { <ApplyBanner initial=alert/> }.into_any());
    let text: String = doc.root_element().text().collect();
    assert!(text.contains("config.xml not imported"), "{text}");

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
        alert: None,
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

#[test]
fn blocklist_dialog_groups_curated_lists_like_opnsense() {
    let fields = GridId::Blocklists.meta().fields;
    let doc = render(|| {
        let values = RwSignal::new(to_inputs(
            fields,
            &serde_json::json!({"lists": ["hagezi-pro", "oisd-small"]}),
        ));
        let errors = RwSignal::new(vec![FieldError::new("lists", "Pick one.")]);
        view! { <FormFields fields form_id="b".to_owned() values errors/> }.into_any()
    });
    assert_all_labelled(&doc, "blocklist dialog");
    let legends: Vec<String> = doc
        .select(&sel("#b--lists fieldset > legend"))
        .map(|l| l.text().collect())
        .collect();
    assert_eq!(
        legends,
        [
            "General Blocklists",
            "HaGeZi Multi - Clean the Internet",
            "OISD Blocklists",
            "HaGeZi Targeted Lists",
            "Minimal Hardware Requirements"
        ]
    );
    let checked: Vec<&str> = doc
        .select(&sel("#b--lists input[checked]"))
        .filter_map(|i| i.value().attr("value"))
        .collect();
    assert_eq!(checked, ["hagezi-pro", "oisd-small"]);
    // The group is named by the field label and carries the error.
    let group = doc.select(&sel("#b--lists")).next().unwrap();
    assert_eq!(group.value().attr("role"), Some("group"));
    let label_id = group.value().attr("aria-labelledby").unwrap();
    let label = doc.select(&sel(&format!("#{label_id}"))).next().unwrap();
    assert_eq!(label.text().collect::<String>(), "Type of DNSBL");
    assert_eq!(group.value().attr("aria-invalid"), Some("true"));
    assert!(
        group
            .value()
            .attr("aria-describedby")
            .unwrap()
            .contains("b--lists-err")
    );
}

#[test]
fn dns_stats_panel_shows_no_data_then_figures() {
    use sensr_ui::pages::DnsStatsPanel;
    let empty = render(|| view! { <DnsStatsPanel stats=Default::default()/> }.into_any());
    assert!(empty.select(&sel("#dnsbl-no-data")).next().is_some());
    assert!(empty.select(&sel("#unbound-no-data")).next().is_some());
    assert!(empty.select(&sel("#dnsbl-blocked-note")).next().is_some());

    let doc = render(|| {
        view! { <DnsStatsPanel stats=sensr_ui::mock::simulated_dns_stats()/> }.into_any()
    });
    let text = |s: &str| {
        doc.select(&sel(s))
            .next()
            .unwrap()
            .text()
            .collect::<String>()
    };
    assert_eq!(text("#dnsbl-names"), "412,731");
    assert_eq!(text("#unbound-queries"), "1,284,377");
    let all: String = doc.root_element().text().collect();
    assert!(all.contains("Default: 238,904 names"), "{all}");
    assert!(all.contains("2026-11-16 03:00:15 UTC"));
    assert!(all.contains("HTTP 503"), "source errors are shown");
    assert!(all.contains("does not count blocked queries per blocklist"));
    // Four sources across two policies, each table with column headers.
    assert_eq!(doc.select(&sel("tbody tr")).count(), 4);
    assert_eq!(doc.select(&sel("thead th[scope=col]")).count(), 10);

    let broken = sensr_ui::api::DnsStats {
        problems: vec!["/run/sensr-dns/unbound-stats.json: expected value".into()],
        ..Default::default()
    };
    let doc = render(|| view! { <DnsStatsPanel stats=broken/> }.into_any());
    assert!(
        doc.select(&sel("[role=alert]"))
            .any(|a| a.text().collect::<String>().contains("unbound-stats.json"))
    );
}
