//! Document shell, routes and the OPNsense-style chrome: sidebar `<MenuTree>`, `<TopBar>`,
//! page header and the Apply banner.

use crate::actions::{LayoutData, chrome_data};
use crate::islands::{ApplyBanner, NavToggle, ThemeToggle};
use crate::menu::{self, Icon, MenuItem};
use crate::pages::*;
use leptos::prelude::*;
use leptos_meta::{Title, provide_meta_context};
use leptos_router::{
    SsrMode,
    components::{Outlet, ParentRoute, Route, Router, Routes},
    hooks::use_location,
    path,
};

/// The HTML document around every page.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    #[cfg(feature = "ssr")]
    let theme = crate::server::theme();
    #[cfg(not(feature = "ssr"))]
    let theme: Option<&str> = None;
    view! {
        <!DOCTYPE html>
        <html lang="en" data-theme=theme>
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <meta name="color-scheme" content="light dark"/>
                <link rel="icon" href="/favicon.svg" type="image/svg+xml"/>
                <style>{crate::theme::tokens_css()}</style>
                <link rel="stylesheet" href="/pkg/sensr-ui.css"/>
                <script src="/passkey.js" defer></script>
                <HydrationScripts options islands=true/>
                <leptos_meta::MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

/// Routes.
#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    view! {
        <Router>
            <Routes fallback=|| view! { <NotFound/> }>
                <Route path=path!("/login") view=Login ssr=SsrMode::Async/>
                <ParentRoute path=path!("") view=Layout ssr=SsrMode::Async>
                    <Route path=path!("") view=Dashboard/>
                    <Route path=path!("/ui/core/dashboard") view=Dashboard/>
                    <Route path=path!("/ui/core/password") view=PasswordPage/>
                    <Route path=path!("/ui/diagnostics/traffic") view=Traffic/>
                    <Route path=path!("/ui/unbound/overview") view=UnboundOverview/>
                    <Route path=path!("/ui/interfaces/assignment") view=Assignments/>
                    <Route path=path!("/ui/interfaces/if/:id") view=InterfacePage/>
                    <Route path=path!("/ui/interfaces/overview") view=InterfacesOverview/>
                    <Route path=path!("/ui/routing/configuration") view=GatewaysConfig/>
                    <Route path=path!("/ui/routing/gateway_groups") view=GatewayGroupsPage/>
                    <Route path=path!("/ui/routes") view=RoutesConfig/>
                    <Route path=path!("/ui/interfaces/bridge") view=Bridges/>
                    <Route path=path!("/ui/interfaces/lagg") view=Laggs/>
                    <Route path=path!("/ui/interfaces/loopback") view=Loopbacks/>
                    <Route path=path!("/ui/interfaces/vip") view=VirtualIpsPage/>
                    <Route path=path!("/ui/firewall/group") view=FirewallGroups/>
                    <Route path=path!("/ui/routing/status") view=GatewayStatusPage/>
                    <Route path=path!("/ui/firewall/alias") view=Aliases/>
                    <Route path=path!("/ui/firewall/filter") view=Rules/>
                    <Route path=path!("/ui/firewall/filter/:if") view=Rules/>
                    <Route path=path!("/ui/firewall/source_nat") view=SourceNat/>
                    <Route path=path!("/ui/firewall/d_nat") view=DestinationNat/>
                    <Route path=path!("/ui/dhcpv4/:if") view=Dhcpv4/>
                    <Route path=path!("/ui/unbound/general") view=UnboundGeneralPage/>
                    <Route path=path!("/ui/unbound/overrides") view=UnboundOverrides/>
                    <Route path=path!("/ui/unbound/advanced") view=UnboundAdvancedPage/>
                    <Route path=path!("/ui/unbound/acl") view=UnboundAcl/>
                    <Route path=path!("/ui/unbound/forward") view=UnboundForward/>
                    <Route path=path!("/ui/unbound/dnsbl") view=UnboundBlocklist/>
                    <Route path=path!("/ui/wireguard/instances") view=WireguardInstances/>
                    <Route path=path!("/ui/wireguard/peers") view=WireguardPeers/>
                    <Route path=path!("/ui/system/user") view=UsersPage/>
                    <Route path=path!("/ui/system/group") view=UserGroupsPage/>
                    <Route path=path!("/ui/system/oidc") view=OidcPage/>
                    <Route path=path!("/ui/system/saml") view=SamlPage/>
                    <Route path=path!("/ui/system/general") view=SystemGeneralPage/>
                    <Route path=path!("/ui/system/updates") view=UpdatesPage/>
                    <Route path=path!("/ui/core/backup/history") view=History/>
                    <Route path=path!("/ui/ids") view=IdsSettingsPage/>
                    <Route path=path!("/ui/ids/rules") view=IdsRulesPage/>
                    <Route path=path!("/ui/ids/userdefined") view=IdsUserRulesPage/>
                    <Route path=path!("/ui/ids/alerts") view=IdsAlertsPage/>
                    <Route path=path!("/ui/diagnostics/networkinsight") view=Insight/>
                    <Route path=path!("/*any") view=NotYet/>
                </ParentRoute>
            </Routes>
        </Router>
    }
}

/// The sensr wordmark: "s" green, "ens" yellow, "r" rusty red (docs/logo.svg).
#[component]
pub fn Wordmark() -> impl IntoView {
    view! {
        <svg class="wordmark" viewBox="0 0 174 72" role="img" aria-label="sensr">
            <text x="2" y="56" font-size="64" font-weight="800" letter-spacing="-2">
                <tspan class="wm-s">"s"</tspan><tspan class="wm-ens">"ens"</tspan><tspan class="wm-r">"r"</tspan>
            </text>
        </svg>
    }
}

/// Section icon, drawn as simple strokes.
#[component]
pub fn MenuIcon(icon: Icon) -> impl IntoView {
    let d = match icon {
        Icon::Star => "M8 1.8l1.9 3.9 4.3.6-3.1 3 .7 4.3L8 11.6l-3.8 2 .7-4.3-3.1-3 4.3-.6z",
        Icon::Lobby => "M3 3.5h10v6.5H3zM1.5 12.5h13",
        Icon::Reporting => "M2 13.5h12M4 11V8M7 11V4.5M10 11V6.5M13 11V3",
        Icon::System => "M2.5 2.5h11v4h-11zM2.5 9.5h11v4h-11zM5 4.5h.01M5 11.5h.01",
        Icon::Interfaces => {
            "M6 1.5h4v3H6zM1.5 11.5h4v3h-4zM10.5 11.5h4v3h-4zM8 4.5v3.5M3.5 11.5V8h9v3.5"
        }
        Icon::Firewall => {
            "M8 1.5c1 2.5 4.5 4 4.5 8a4.5 4.5 0 0 1-9 0c0-2 1-3 2-4 0 1.5.8 2.5 1.6 2.5C7 6 7 4 8 1.5z"
        }
        Icon::Vpn => {
            "M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM1.5 8h13M8 1.5c-2.2 2.2-2.2 10.8 0 13M8 1.5c2.2 2.2 2.2 10.8 0 13"
        }
        Icon::Services => {
            "M8 5.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zM8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M3.4 12.6l1.4-1.4M11.2 4.8l1.4-1.4"
        }
        Icon::Power => "M8 1.5v6M4.5 3.8a5.5 5.5 0 1 0 7 0",
        Icon::Help => {
            "M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM6 6a2 2 0 1 1 2.5 1.9c-.5.2-.5.6-.5 1.1M8 11.5h.01"
        }
    };
    view! {
        <svg class="mi" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
            <path d=d fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn menu_level(
    items: Vec<MenuItem>,
    path: String,
    current: Option<String>,
    depth: usize,
) -> impl IntoView {
    items
        .into_iter()
        .map(|item| {
            let active = item.contains(&path);
            // A section that holds a single page is a link, not a nest: show the
            // section name pointing at that page (see menu::sole_page).
            let sole = (!item.children.is_empty())
                .then(|| menu::sole_page(&item))
                .flatten()
                .map(|page| page.url.clone().unwrap_or_default());
            if item.children.is_empty() || sole.is_some() {
                let url = sole.unwrap_or_else(|| item.url.clone().unwrap_or_default());
                let current = current.as_deref() == Some(url.as_str());
                let external = url.starts_with("http");
                view! {
                    <li>
                        <a href=url class:active=current aria-current=current.then_some("page")
                            target=external.then_some("_blank") rel=external.then_some("noopener")>
                            {item.icon.map(|i| view! { <MenuIcon icon=i/> })}
                            <span>{item.label}</span>
                        </a>
                    </li>
                }
                .into_any()
            } else {
                let children =
                    menu_level(item.children, path.clone(), current.clone(), depth + 1).into_any();
                view! {
                    <li>
                        <details open=active class=format!("depth-{depth}")>
                            <summary class:active=active>
                                {item.icon.map(|i| view! { <MenuIcon icon=i/> })}
                                <span>{item.label}</span>
                            </summary>
                            <ul>{children}</ul>
                        </details>
                    </li>
                }
                .into_any()
            }
        })
        .collect_view()
}

/// The sidebar menu tree. Server-rendered `<details>`: works without JavaScript.
#[component]
pub fn MenuTree(menu: Vec<MenuItem>, path: String) -> impl IntoView {
    let current = menu::best_url(&menu, &path)
        .or_else(|| (path == "/").then(|| "/ui/core/dashboard".to_owned()));
    let path = if path == "/" {
        "/ui/core/dashboard".to_owned()
    } else {
        path
    };
    view! {
        <nav id="sidebar" class="sidebar" aria-label="Main menu">
            <ul class="menu">{menu_level(menu, path, current, 0)}</ul>
        </nav>
    }
}

/// The top bar: wordmark, host, theme switch, user and logout.
#[component]
pub fn TopBar(user: String) -> impl IntoView {
    #[cfg(feature = "ssr")]
    let theme = crate::server::theme().map(str::to_owned);
    #[cfg(not(feature = "ssr"))]
    let theme: Option<String> = None;
    view! {
        <header class="topbar">
            <NavToggle/>
            <a class="brand" href="/"><Wordmark/></a>
            <div class="topbar-right">
                <ThemeToggle initial=theme/>
                <span class="user" title="Signed in user">
                    <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path d="M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM2.5 14.5c.5-3 2.7-4.5 5.5-4.5s5 1.5 5.5 4.5" fill="none" stroke="currentColor" stroke-width="1.4"/></svg>
                    <span>{user}</span>
                </span>
                <form method="post" action="/ui/fn/logout">
                    <button type="submit" class="btn btn-sm btn-ghost">"Logout"</button>
                </form>
            </div>
        </header>
    }
}

/// Page chrome around every authenticated route.
#[component]
pub fn Layout() -> impl IntoView {
    let location = use_location();
    let path = location.pathname.get_untracked();
    let chrome = move || {
        let path = path.clone();
        Suspend::new(async move {
            let data = chrome_data().await.unwrap_or_else(|_| LayoutData {
                user: String::new(),
                interfaces: vec![],
                pending: Default::default(),
            });
            let menu = menu::build(&data.interfaces);
            let mut crumb = menu::breadcrumb(&menu, &path);
            if path == "/" {
                crumb = vec!["Lobby".into(), "Dashboard".into()];
            }
            let title = if crumb.is_empty() {
                "sensr".to_owned()
            } else {
                crumb.join(": ")
            };
            view! {
                <Title text=format!("{title} | sensr")/>
                <TopBar user=data.user/>
                <MenuTree menu path=path.clone()/>
                <div class="page-head">
                    <h1>{title}</h1>
                </div>
                <ApplyBanner initial=data.pending/>
            }
        })
    };
    view! {
        <a class="skip-link" href="#content">"Skip to content"</a>
        <div class="app">
            <Suspense fallback=|| ()>{chrome}</Suspense>
            <main id="content" class="content" tabindex="-1">
                <Outlet/>
            </main>
        </div>
    }
}

/// The login page. A plain form post: signing in needs no JavaScript.
#[component]
pub fn Login() -> impl IntoView {
    let failed =
        leptos_router::hooks::use_query_map().with_untracked(|q| q.get("failed").is_some());
    let oidc_failed = leptos_router::hooks::use_query_map()
        .with_untracked(|q| matches!(q.get("failed").as_deref(), Some("oidc" | "saml")));
    let load = move || {
        Suspend::new(async move {
            let providers = crate::actions::login_providers().await.unwrap_or_default();
            (!providers.is_empty()).then(|| {
                view! {
                    <div class="login-divider"><span>"or"</span></div>
                    {providers
                        .into_iter()
                        .map(|p| {
                            view! {
                                <a class="btn btn-block" href=p.start.clone()>
                                    {format!("Sign in with {}", p.name)}
                                </a>
                            }
                        })
                        .collect_view()}
                }
            })
        })
    };
    view! {
        <Title text="Login | sensr"/>
        <main class="login-page">
            <form class="login-card" method="post" action="/ui/fn/login">
                <h1 class="login-brand"><Wordmark/></h1>
                {failed.then(|| view! {
                    <p class="field-error" role="alert" id="login-error">
                        {if oidc_failed { "The single sign-on login did not complete. Please try again." } else { "Wrong username, password or one-time password." }}
                    </p>
                })}
                <div class="field-stack">
                    <label for="username">"Username"</label>
                    <input id="username" name="username" type="text" autocomplete="username" required autofocus
                        aria-describedby=failed.then_some("login-error")/>
                </div>
                <div class="field-stack">
                    <label for="password">"Password"</label>
                    <input id="password" name="password" type="password" autocomplete="current-password" required/>
                </div>
                <div class="field-stack">
                    <label for="otp">"One-time password"</label>
                    <input id="otp" name="otp" type="text" inputmode="numeric"
                        autocomplete="one-time-code" maxlength="6" pattern="[0-9]*"
                        aria-describedby="otp-help"/>
                    <p id="otp-help" class="muted small">"Six digits from your authenticator app, when two-factor login is enabled."</p>
                </div>
                <button type="submit" class="btn btn-primary btn-block">"Login"</button>
                <button type="button" id="passkey-login" class="btn btn-block" hidden>
                    "Sign in with a passkey"
                </button>
                <p id="passkey-error" class="field-error" role="alert" hidden></p>
                <Suspense fallback=|| ()>{load}</Suspense>
            </form>
        </main>
    }
}

/// Unknown URL outside the authenticated area.
#[component]
fn NotFound() -> impl IntoView {
    view! {
        <Title text="Not found | sensr"/>
        <main class="login-page"><div class="login-card"><h1>"Page not found"</h1><a href="/">"Go to the dashboard"</a></div></main>
    }
}
