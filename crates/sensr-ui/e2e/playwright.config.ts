import { defineConfig, devices } from "@playwright/test";

// By default the server is the release build from `cargo leptos build --release`, run on the
// mock backend. SENSR_UI_BASE_URL points the suite at a running stack instead (sensr-agent +
// sensr-api --ui-root, seeded with the mock's document plus a root/sensr user).
const external = process.env.SENSR_UI_BASE_URL;
const root = (process.env.SENSR_UI_ROOT ?? require("node:path").resolve(__dirname, "../../..")) + "/";
const port = Number(process.env.SENSR_UI_PORT ?? 3300);
const readOnlyPort = port + 1;
// Only the alias page: global search must not show anything else.
const aliasOnlyPort = port + 2;

function server(p: number, bin?: string, privileges?: string) {
  return {
    command: bin ?? `${root}target/release/sensr-ui-dev`,
    cwd: root,
    url: `http://127.0.0.1:${p}/healthz`,
    reuseExistingServer: false,
    env: {
      LEPTOS_SITE_ROOT: "target/site",
      LEPTOS_SITE_PKG_DIR: "pkg",
      LEPTOS_OUTPUT_NAME: "sensr-ui",
      LEPTOS_SITE_ADDR: `127.0.0.1:${p}`,
      LEPTOS_ENV: "PROD",
      ...(privileges ? { SENSR_UI_PRIVILEGES: privileges } : {}),
    },
  };
}

export default defineConfig({
  testDir: "tests",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"]],
  outputDir: process.env.SENSR_UI_ARTIFACTS ? `${process.env.SENSR_UI_ARTIFACTS}/results` : "test-results",
  use: {
    baseURL: external ?? `http://127.0.0.1:${port}`,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1366, height: 860 } } }],
  webServer: external ? undefined : [
    server(port, process.env.SENSR_UI_BIN),
    // A second instance whose only user is a read-only administrator.
    server(readOnlyPort, process.env.SENSR_UI_BIN, "page-all,user-config-readonly"),
    // A third whose only privilege is the alias page.
    server(aliasOnlyPort, process.env.SENSR_UI_BIN, "page-firewall-alias-edit"),
  ],
});
