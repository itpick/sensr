import { expect, test, type Page } from "@playwright/test";
import { expectAccessible, hydrated, login, setTheme, shots } from "./helpers";

// The Open ports card on the host page, the "N open" count on the dashboard Hosts card and
// port queries in global search, on the mock's seeded port scan: device-05 has telnet open
// (new), bench-pi 22/8080/8443, the laptop was scanned and has nothing open, kid-tablet was
// never scanned. Scan now runs on the laptop so the other hosts keep their seeded state.
test.skip(!!process.env.SENSR_UI_BASE_URL, "relies on the mock's seeded port scan");

const DEVICE_05 = "02:00:00:00:00:05";
const BENCH_PI = "b8:27:eb:7d:4e:25";
const LAPTOP = "3c:22:fb:81:4d:0a";
const KID = "e2:5b:7a:31:90:c4";

const portsCard = (page: Page) =>
  page.locator("section.card").filter({ has: page.getByRole("heading", { level: 2, name: "Open ports" }) });

async function open(page: Page, mac: string, query = "") {
  await login(page);
  await page.goto(`/ui/hosts/${mac}${query}`);
  await hydrated(page);
  await expect(portsCard(page)).toBeVisible();
}

test.describe("host ports", () => {
  test("the card lists open ports with a new pill", async ({ page }) => {
    await open(page, DEVICE_05);
    const card = portsCard(page);
    await expect(card.locator(".ports-status")).toHaveText("Last scanned 3 h ago");
    const rows = card.locator("tbody tr");
    await expect(rows).toHaveCount(1);
    await expect(rows.first().locator("td").nth(0)).toHaveText("23/tcp");
    await expect(rows.first().locator("td").nth(1)).toHaveText("telnet");
    await expect(rows.first().locator(".pill")).toHaveText("new");
    await expect(card.getByRole("button", { name: "Scan now" })).toBeEnabled();

    await open(page, BENCH_PI);
    await expect(portsCard(page).locator("tbody tr td:first-child")).toHaveText(["22/tcp", "8080/tcp", "8443/tcp"]);
    await expect(portsCard(page).locator(".pill")).toHaveCount(0);

    await open(page, KID);
    await expect(portsCard(page).locator(".ports-status")).toHaveText("Not scanned yet");
    await expect(portsCard(page).locator("table")).toHaveCount(0);
  });

  test("Scan now polls until the scan is done", async ({ page }) => {
    await open(page, LAPTOP);
    const card = portsCard(page);
    await expect(card).toContainText("No open ports found.");
    const polls: string[] = [];
    page.on("request", (r) => {
      if (r.url().includes("/ui/fn/host_scanning")) polls.push(r.postData() ?? "");
    });
    await card.getByRole("button", { name: "Scan now" }).click();
    await page.waitForURL(/scan=started/);
    // the mock's scan takes 3 s: scanning first, then the page reloads with the result
    await expect(portsCard(page).getByRole("button", { name: "Scanning…" })).toBeDisabled();
    await expect(portsCard(page).locator(".ports-status")).toContainText("Scanning…");
    await expect(portsCard(page)).toContainText("Scan finished.", { timeout: 15_000 });
    await expect(portsCard(page).locator(".ports-status")).toHaveText("Last scanned now");
    await expect(portsCard(page).getByRole("button", { name: "Scan now" })).toBeEnabled();
    expect(polls.length).toBeGreaterThan(0);
    expect(JSON.parse(polls[0])).toEqual({ mac: LAPTOP });
    expect(new URL(page.url()).hash).toBe("#open-ports");
  });

  test("the Hosts card shows how many ports are open", async ({ page }) => {
    await login(page);
    await page.goto("/ui/core/dashboard");
    await hydrated(page);
    const hosts = page.locator("section.hosts-card");
    const row = (name: string) =>
      hosts.locator("tbody tr").filter({ has: page.getByRole("link", { name: new RegExp(`^${name}`) }) });
    await expect(row("bench-pi").locator(".host-open-ports")).toHaveText("3 open");
    await expect(row("kid-tablet").locator(".host-open-ports")).toHaveCount(0);
    await row("bench-pi").scrollIntoViewIfNeeded();
    await row("bench-pi").screenshot({ path: `${shots}/hosts-card-open-ports.png` });
  });

  test("global search finds hosts by open port", async ({ page }) => {
    await login(page);
    await page.goto("/ui/core/dashboard");
    await hydrated(page);
    const box = page.getByRole("combobox", { name: "Search sensr" });
    for (const q of ["port 23", "23/tcp", "tcp 23"]) {
      await box.fill(q);
      const hit = page.locator("#gsearch-list").getByRole("group", { name: "Hosts", exact: true }).getByRole("option");
      await expect(hit).toHaveCount(1);
      await expect(hit.first()).toHaveAttribute("data-url", `/ui/hosts/${DEVICE_05}`);
      await expect(hit.first().locator(".gsearch-detail")).toHaveText("23/tcp open");
    }
    await page.locator("#gsearch-list").getByRole("group", { name: "Hosts", exact: true }).getByRole("option").first().click();
    await page.waitForURL(`**/ui/hosts/${DEVICE_05}`);
    await expect(portsCard(page)).toContainText("telnet");
  });

  for (const theme of ["light", "dark"] as const) {
    test(`is accessible (${theme})`, async ({ page }) => {
      await login(page);
      await setTheme(page, theme);
      await page.goto(`/ui/hosts/${DEVICE_05}`);
      await hydrated(page);
      await expect(portsCard(page)).toBeVisible();
      await expectAccessible(page);
      await portsCard(page).screenshot({ path: `${shots}/host-open-ports-${theme}.png` });
    });
  }
});
