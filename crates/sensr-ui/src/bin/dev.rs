//! Standalone UI server on the mock backend (`cargo leptos watch`, browser tests).

use leptos::prelude::get_configuration;
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
    // Traffic and alert data: a real sensr-insight directory if one is named, else a fixture
    // written for this run.
    let insight = match std::env::var_os("SENSR_INSIGHT_DIR") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => {
            let dir = std::env::temp_dir().join(format!("sensr-ui-dev-{}", std::process::id()));
            std::fs::create_dir_all(&dir)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            sensr_ui::mock::seed_insight(&dir, i64::try_from(now)?)?;
            dir
        }
    };
    // Port scans: a real sensr-scan directory if one is named, else a fixture for this run.
    let scans = match std::env::var_os("SENSR_SCAN_DIR") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => {
            let dir =
                std::env::temp_dir().join(format!("sensr-ui-dev-scans-{}", std::process::id()));
            std::fs::create_dir_all(&dir)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            sensr_ui::mock::seed_scans(&dir, i64::try_from(now)?).map_err(anyhow::Error::msg)?;
            dir
        }
    };
    let mut backend = sensr_ui::mock::MockBackend::new()
        .with_insight_dir(insight)
        .with_scan_dir(scans);
    // SENSR_UI_PRIVILEGES="page-all,user-config-readonly" runs the server as a read-only user.
    if let Ok(list) = std::env::var("SENSR_UI_PRIVILEGES") {
        let names: Vec<&str> = list
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .collect();
        backend = backend.with_privileges(&names);
    }
    let backend = Arc::new(backend);
    let app = sensr_ui::server::router(options, Arc::new(sensr_ui::mock::MockSessions(backend)));
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("sensr-ui listening on http://{addr} (mock backend, login root / sensr)");
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
