import { expect, test } from "@playwright/test";
import { hydrated, login, shots } from "./helpers";

// Intrusion detection, Reporting › Insight and the dashboard traffic graph, on the mock
// backend's traffic and alert fixture (sensr-ui-dev seeds one per run).

test.describe.configure({ mode: "serial" });

test("ids alerts: filter, page, suppress from source, staged in the rules tab", async ({ page }) => {
  await login(page);
  await page.goto("/ui/ids/alerts");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Services: Intrusion Detection: Administration");
  await expect(page.getByRole("navigation", { name: "Intrusion detection" }).getByRole("link", { name: "Alerts" }))
    .toHaveAttribute("aria-current", "page");
  const rows = page.locator(".card table tbody tr");
  await expect(rows).toHaveCount(25);
  await expect(page.getByText(/Showing 1 to 25 of \d+ alerts/)).toBeVisible();

  await page.getByRole("link", { name: "Next page" }).click();
  await expect(page.getByText(/Showing 26 to/)).toBeVisible();

  // Already suppressed in the seed document: no buttons.
  await page.goto("/ui/ids/alerts?text=2013504");
  await expect(rows.first()).toContainText("suppressed");
  await expect(rows.first().getByRole("button")).toHaveCount(0);

  await page.getByLabel("Signature or sid").fill("ssh scan");
  await page.getByRole("button", { name: "Filter" }).click();
  await expect(page).toHaveURL(/text=ssh%20scan|text=ssh\+scan/);
  const n = await rows.count();
  expect(n).toBeGreaterThan(0);
  for (const t of await rows.locator("td:nth-child(3)").allInnerTexts()) expect(t).toContain("SSH Scan");

  await page.getByLabel("Host address").fill("192.168.1.101");
  await page.getByRole("button", { name: "Filter" }).click();
  await expect(page.getByText("No alerts match.")).toBeVisible();
  await page.getByRole("link", { name: "Clear" }).click();

  await page.goto("/ui/ids/alerts?text=2001219");
  await rows.first().getByRole("button", { name: /Source only: suppress sid 2001219 from 198\.51\.100\.23/ }).click();
  await expect(page.getByRole("status").filter({ hasText: "staged" })).toContainText("signature 2001219");
  await expect(page).toHaveURL(/text=2001219/);
  // The banner lists every staged section; another test may have staged dns too.
  await expect(page.getByRole("region", { name: "Pending changes" })).toContainText(
    /Changed: [^.]*\bids\b/,
  );
  await expect(rows.first()).toContainText("suppressed");
  await page.screenshot({ path: `${shots}/interaction-ids-suppress.png`, fullPage: true });

  await page.getByRole("navigation", { name: "Intrusion detection" }).getByRole("link", { name: "Rules" }).click();
  await hydrated(page);
  const sup = page.locator(".grid tbody tr", { hasText: "2001219" });
  await expect(sup).toContainText("source 198.51.100.23/32");
  await expect(sup).toContainText("ET SCAN Potential SSH Scan");

  // Leave the shared mock as it was.
  await page.getByRole("region", { name: "Pending changes" }).getByRole("button", { name: "Discard" }).click();
  await expect(page.getByRole("region", { name: "Pending changes" })).not.toContainText("The configuration has been changed");
});

test("ids settings: home net help, validation, user defined rule dialog", async ({ page }) => {
  await login(page);
  await page.goto("/ui/ids");
  await hydrated(page);
  await expect(page.getByLabel("Add interface addresses")).toBeChecked();
  await expect(page.getByLabel("Add interface addresses")).toHaveAccessibleDescription(/WAN's current address.*after NAT/);
  await expect(page.getByLabel("Capture mode")).toHaveValue("detect");
  await page.getByLabel("Interfaces").fill("");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByLabel("Interfaces")).toHaveAccessibleDescription(/at least one interface/);
  await page.getByLabel("Interfaces").fill("wan\nlan");
  await page.getByLabel("Capture mode").selectOption("prevent");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Saved" })).toBeVisible();
  const banner = page.getByRole("region", { name: "Pending changes" });
  await expect(banner).toContainText("Changed: ids.");

  await page.goto("/ui/ids/userdefined");
  await hydrated(page);
  await page.getByRole("button", { name: "Add" }).click();
  const dialog = page.getByRole("dialog", { name: "Add rule" });
  await dialog.getByLabel("Description").fill("Block a known bad host");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(dialog.getByLabel("Source")).toHaveAccessibleDescription(/Set a source, a destination or a fingerprint/);
  await dialog.getByLabel("Destination").fill("192.0.2.66/32");
  await dialog.getByLabel("Action").selectOption("drop");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.locator(".grid tbody tr", { hasText: "Block a known bad host" })).toContainText("192.0.2.66/32");

  await banner.getByRole("button", { name: "Discard" }).click();
  await expect(banner).not.toContainText("The configuration has been changed");
});

test("insight: ranges, top talkers, per-host detail", async ({ page }) => {
  await login(page);
  await page.goto("/ui/diagnostics/networkinsight");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Reporting: Insight");
  const ranges = page.getByRole("navigation", { name: "Time range" });
  await expect(ranges.getByRole("link")).toHaveText(["2 hours", "24 hours", "7 days", "31 days", "1 year"]);
  await expect(ranges.getByRole("link", { name: "24 hours" })).toHaveAttribute("aria-current", "page");
  for (const h of ["Top hosts", "Top services", "Top remotes", "Interfaces"]) {
    await expect(page.getByRole("heading", { name: h })).toBeVisible();
  }
  await expect(page.getByRole("img", { name: /received above the line/ })).toBeVisible();
  const hosts = page.locator("section", { has: page.getByRole("heading", { name: "Top hosts" }) }).locator("tbody tr");
  await expect(hosts.first()).toContainText("192.168.1.20");
  await expect(page.locator("section", { has: page.getByRole("heading", { name: "Interfaces" }) })).toContainText("WAN (wan)");

  await ranges.getByRole("link", { name: "1 year" }).click();
  await expect(page).toHaveURL(/range=1y/);
  await expect(page.getByText(/per day/)).toBeVisible();

  await hosts.filter({ hasText: "192.168.1.100" }).getByRole("link").click();
  await expect(page).toHaveURL(/range=1y&host=192\.168\.1\.100/);
  await expect(page.getByRole("heading", { name: "Host 192.168.1.100" })).toBeVisible();
  await expect(page.locator("section", { has: page.getByRole("heading", { name: "Top services" }) })).toContainText("QUIC (udp/443)");
  await page.getByRole("navigation", { name: "Time range" }).getByRole("link", { name: "2 hours" }).click();
  await expect(page).toHaveURL(/range=2h&host=192\.168\.1\.100/);
  await expect(page.getByText(/per minute/)).toBeVisible();
  await page.getByRole("link", { name: "← All hosts" }).click();
  await expect(page.getByRole("heading", { name: "Top hosts" })).toBeVisible();
});

test("dashboard: traffic graph switches between live samples and the last hour", async ({ page }) => {
  await login(page);
  await hydrated(page);
  const card = page.locator("section", { has: page.getByRole("heading", { name: "Traffic graph" }) });
  await expect(card.getByRole("slider", { name: "Traffic, all interfaces, last ten minutes" })).toBeVisible();
  await card.getByRole("button", { name: "Last hour" }).click();
  await expect(card.getByRole("button", { name: "Last hour" })).toHaveAttribute("aria-pressed", "true");
  await expect(card.getByRole("slider", { name: "Traffic, all interfaces, last hour" })).toBeVisible();
  await expect(card).toContainText(/In [\d.]+ [kMG]?bit\/s/);
});
