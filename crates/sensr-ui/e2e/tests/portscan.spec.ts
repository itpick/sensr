import { expect, test, type Page } from "@playwright/test";
import { hydrated, login } from "./helpers";

// The port scanner on the dashboard Hosts card and Services › Port Scanner. The mock backend
// seeds a scan database and answers like sensr-scan (refusals included) but never runs a
// scan, so a queued job stays queued: each test cancels what it queued.
test.skip(!!process.env.SENSR_UI_BASE_URL, "relies on the mock's seeded scans and canned scanner");

const card = (page: Page) => page.locator("section.hosts-card");
const row = (page: Page, host: string) =>
  card(page).locator("tbody tr").filter({ has: page.locator("a.host-link", { hasText: new RegExp(`^${host}$`) }) });
const queue = (page: Page) => page.getByRole("region", { name: "Running" });

/** Cancels any queued scan of `target` on the Port Scanner page. */
async function cancelQueued(page: Page, target: string) {
  await page.goto("/ui/portscan");
  await hydrated(page);
  const cancel = queue(page).getByRole("button", { name: `Cancel the scan of ${target}` });
  while ((await cancel.count()) > 0) {
    await cancel.first().click();
    await expect(cancel).toHaveCount(0);
  }
}

test.describe("port scanner", () => {
  test("Scan now on a host shows scanning…", async ({ page }) => {
    await login(page);
    await cancelQueued(page, "192.168.1.112");
    await page.goto("/ui/core/dashboard");
    await hydrated(page);
    const line = row(page, "bench-pi").locator(".host-ports");
    await expect(line).toHaveText(/^22 ssh · \+3389 new · scanned \w{3} \d{1,2} · Scan now$/);
    // what the port said is its tooltip
    await expect(line.locator(".port-chip").first()).toHaveAttribute("title", /OpenSSH/);
    await line.getByRole("button", { name: "Scan now: bench-pi" }).click();
    await expect(line).toHaveText("22 ssh · +3389 new · scanning…");
    await expect(line.getByRole("button")).toHaveCount(0);
    // the Port Scanner page lists it as queued
    await cancelQueued(page, "192.168.1.112");
  });

  test("New scan refuses a public address without the tick and queues a range", async ({ page }) => {
    await login(page);
    await cancelQueued(page, "192.168.1.0/24");
    await expect(queue(page)).toContainText(/12 of 254 alive/);
    // the actions the read-only test expects to be absent, by the same pattern
    await expect(page.getByRole("button", { name: /^Cancel( |$)|^Scan now(: |$)/ }).first()).toBeVisible();
    const form = page.getByRole("region", { name: "New scan" });
    const target = form.getByLabel("Address, network or range");
    await target.fill("8.8.8.8");
    await form.getByRole("button", { name: "Scan", exact: true }).click();
    await expect(form.getByRole("alert")).toHaveText('Not scanned: the target is outside the local networks. Tick "Scan addresses outside the local networks" to scan it anyway.');
    await target.fill("192.168.1.0/24");
    await form.getByRole("button", { name: "Scan", exact: true }).click();
    await expect(form.getByRole("status")).toContainText("Scan of 192.168.1.0/24 queued");
    const queued = queue(page).getByRole("row").filter({ hasText: "192.168.1.0/24" });
    await expect(queued).toContainText("queued");
    await queue(page).getByRole("button", { name: "Cancel the scan of 192.168.1.0/24" }).click();
    await expect(queued).toHaveCount(0);
  });

  test("Scan now on an excluded device asks first, Scan anyway queues it", async ({ page }) => {
    await login(page);
    await cancelQueued(page, "192.168.72.2");
    const devices = page.getByRole("table", { name: "Device scans" });
    await devices.getByRole("button", { name: "Scan now: old-router" }).click();
    const form = page.getByRole("region", { name: "New scan" });
    await expect(form.getByRole("alert")).toHaveText("Not scanned: the device is on the exclude list (Never scanned).");
    await form.getByRole("button", { name: "Scan 192.168.72.2 anyway" }).click();
    await expect(form.getByRole("status")).toContainText("Scan of 192.168.72.2 queued");
    await cancelQueued(page, "192.168.72.2");
  });

  test("a device's ports are on its host page, with Scan now", async ({ page }) => {
    await login(page);
    await cancelQueued(page, "192.168.1.20");
    await page.goto("/ui/hosts/52:54:00:aa:bb:01#ports");
    const ports = page.getByRole("region", { name: "Ports" });
    await expect(ports.getByRole("row").filter({ hasText: "Synology" })).toContainText("http");
    await expect(ports.locator("ol.scan-history li")).toHaveCount(2);
    await ports.getByRole("button", { name: "Scan now" }).click();
    await page.waitForURL(/\/ui\/hosts\/52:54:00:aa:bb:01\?scan_started=\d+/);
    await expect(ports.getByRole("status")).toHaveText(/^Scan of 192\.168\.1\.20 queued \(job \d+\)\.$/);
    await expect(ports).toContainText("scanning…");
    await cancelQueued(page, "192.168.1.20");
  });
});

test.describe("read-only user", () => {
  const port = Number(process.env.SENSR_UI_PORT ?? 3300) + 1;
  test.use({ baseURL: `http://127.0.0.1:${port}` });

  test("sees results but cannot scan", async ({ page }) => {
    await login(page);
    await page.goto("/ui/core/dashboard");
    await hydrated(page);
    await expect(row(page, "nas").locator(".host-ports")).toContainText('80 http "Synology"');
    await expect(card(page).getByRole("button", { name: /^Scan now(: |$)/ })).toHaveCount(0);
    await page.goto("/ui/portscan");
    await hydrated(page);
    await expect(page.getByRole("table", { name: "Device scans" })).toContainText("nas");
    await expect(page.getByRole("region", { name: "New scan" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /^Cancel( |$)|^Scan now(: |$)/ })).toHaveCount(0);
    // (the same pattern finds them for an administrator: see the New scan test)
  });
});
