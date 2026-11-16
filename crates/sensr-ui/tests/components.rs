//! Component tests: render islands and chrome to HTML on the server and check structure and
//! accessibility basics (every control labelled, errors wired to fields, table semantics).

use leptos::prelude::*;
use scraper::{Html, Selector};
use sensr_ui::api::{FieldError, Pending};
use sensr_ui::form::{get_path, to_inputs};
use sensr_ui::grid::{GridQuery, run_query};
use sensr_ui::islands::{ApplyBanner, FormFields, GridIsland, SettingsFormIsland};
use sensr_ui::models::{FormId, GridId, Location};

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
        let initial = match form.location(&None) {
            Location::Path(p) => get_path(&seed, &p).cloned().unwrap_or_default(),
            Location::Item { list, key, value } => get_path(&seed, &list)
                .and_then(|l| l.as_array())
                .and_then(|l| l.iter().find(|r| r[key] == value.as_str()))
                .cloned()
                .unwrap(),
        };
        let doc = render(|| view! { <SettingsFormIsland form scope=None initial/> }.into_any());
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
        let loc = grid.location(&None);
        let rows = get_path(&seed, &loc.list)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let rows: Vec<_> = rows
            .into_iter()
            .filter(|r| loc.filter.as_ref().is_none_or(|(f, v)| r[*f] == v.as_str()))
            .collect();
        let page = run_query(&rows, grid.columns(), &GridQuery::default());
        let n = page.rows.len();
        assert!(n > 0, "{grid:?}: seed has rows");
        let doc = render(|| {
            view! { <GridIsland grid scope=None initial=page label="item".to_owned()/> }.into_any()
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
