//! Standalone UI server on the mock backend (`cargo leptos watch`, browser tests).

use leptos::prelude::get_configuration;
use sensr_ui::api::BackendHandle;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let conf = get_configuration(None)?;
    let options = conf.leptos_options;
    let addr = options.site_addr;
    let backend: BackendHandle = Arc::new(sensr_ui::mock::MockBackend::new());
    let app = sensr_ui::server::router(options, backend);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("sensr-ui listening on http://{addr} (mock backend, login root / sensr)");
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
