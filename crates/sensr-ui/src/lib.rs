//! Leptos web UI with the OPNsense-style layout: sidebar menu tree, top bar, forms and grids.
//!
//! Server-side rendered with islands: pages are plain HTML from the server, and only the
//! interactive parts (forms, grids, the Apply banner, dashboard widgets) hydrate from a small
//! wasm bundle. Data comes from [`api::Backend`], implemented by [`mock::MockBackend`] until
//! sensr-api's routes are wired in.
#![recursion_limit = "256"]

pub mod actions;
pub mod api;
pub mod app;
pub mod form;
pub mod grid;
pub mod islands;
pub mod menu;
pub mod models;
pub mod pages;
pub mod theme;

#[cfg(feature = "ssr")]
pub mod adapt;
#[cfg(feature = "ssr")]
pub mod dnsstats;
#[cfg(feature = "ssr")]
pub mod hoststats;
#[cfg(feature = "ssr")]
pub mod insight;
#[cfg(feature = "ssr")]
pub mod mock;
#[cfg(feature = "ssr")]
pub mod server;

/// Browser entry point: hydrates the islands and nothing else.
#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_islands();
}
