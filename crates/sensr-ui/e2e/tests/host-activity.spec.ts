import { expect, test, type Page } from "@playwright/test";
import { expectAccessible, hydrated, login, setTheme } from "./helpers";

// The per-host DNS activity page (/ui/hosts/<mac>) on the mock's seeded "kid-tablet": its
// screen time, services, timeline and domains, the Today / 7 days ranges, the domain search
// and pager, and the service override editor. Each test drops changes an earlier one left
// staged, and the override test removes what it set.
test.skip(!!process.env.SENSR_UI_BASE_URL, "relies on the mock's seeded DNS activity");

const KID = "e2:5b:7a:31:90:c4";
const PAGE = `/ui/hosts/${KID}`;

const card = (page: Page, heading: string | RegExp) =>
  page.locator("section.card").filter({ has: page.getByRole("heading", { level: 2, name: heading }) });
const domains = (page: Page) => card(page, "Domains");
const domainRow = (page: Page, name: string) =>
  domains(page).locator("tbody tr").filter({ has: page.locator("code", { hasText: new RegExp(`^${name.replace(/\./g, "\\.")}$`) }) });
const banner = (page: Page) => page.getByRole("region", { name: "Pending changes" });

async function discardStaged(page: Page) {
  const discard = banner(page).getByRole("button", { name: "Discard" });
  if (await discard.isVisible()) {
    page.once("dialog", (d) => void d.accept());
    await discard.click();
    await expect(banner(page)).not.toContainText("The configuration has been changed");
  }
}

async function open(page: Page, query = "") {
  await login(page);
  await page.goto(PAGE + query);
  await hydrated(page);
  await expect(page.getByRole("heading", { level: 2, name: "kid-tablet" })).toBeVisible();
}

test.describe("host activity", () => {
  test("opens from the Hosts card", async ({ page }) => {
    await login(page);
    await page.goto("/ui/core/dashboard");
    await hydrated(page);
    const hosts = page.locator("section.hosts-card");
    await discardStaged(page);
    const row = hosts.locator("tbody tr").filter({ has: page.getByRole("link", { name: /^kid-tablet/ }) });
    // the row carries the DNS mix preview and today's screen time
    await expect(row).toHaveAttribute("style", /--mix:/);
    await expect(row).toHaveAttribute("title", /Video \d/);
    await expect(row.locator(".host-today")).toHaveText(/\d+ h \d\d m/);
    await expect(hosts.getByRole("list", { name: "Row colours" })).toBeVisible();
    await row.getByRole("link", { name: /^kid-tablet/ }).click();
    await page.waitForURL(new RegExp(`/ui/hosts/${KID}$`));
    await expect(page.getByRole("heading", { level: 2, name: "kid-tablet" })).toBeVisible();
    await expect(page.locator(".hp-meta")).toContainText(KID);
  });

  test("shows service minutes and switches Today / 7 days", async ({ page }) => {
    await open(page);
    const range = page.getByRole("navigation", { name: "Time range" });
    await expect(range.getByRole("link", { name: "Today" })).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("heading", { level: 2, name: "Screen time today" })).toBeVisible();

    const services = card(page, "Services");
    const youtube = services.locator("li.svc").filter({ has: page.locator(".svc-name", { hasText: /^YouTube$/ }) });
    await expect(youtube.locator(".t")).toHaveText("1 h 22 m");
    await expect(youtube).toContainText("Video");
    await expect(services.locator("li.svc").filter({ hasText: "Roblox" }).locator(".t")).toHaveText("48 m");
    // the timeline has one row today, with its table alternative
    await expect(card(page, "When").locator(".heat .dl")).toHaveCount(1);
    await expect(card(page, "When").locator("table tbody tr")).toHaveCount(1);
    const today = Number((await page.locator("p.big").textContent())?.match(/(\d+) h/)?.[1] ?? 0);

    await range.getByRole("link", { name: "7 days" }).click();
    await page.waitForURL(/range=7d/);
    await expect(range.getByRole("link", { name: "7 days" })).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("heading", { level: 2, name: "Screen time, last 7 days" })).toBeVisible();
    await expect(card(page, "When").locator(".heat .dl")).toHaveCount(7);
    await expect(card(page, "When").locator("table tbody tr")).toHaveCount(7);
    const week = Number((await page.locator("p.big").textContent())?.match(/(\d+) h/)?.[1] ?? 0);
    expect(week).toBeGreaterThan(4 * today);

    await range.getByRole("link", { name: "Today" }).click();
    await page.waitForURL(/range=today/);
    await expect(page.getByRole("heading", { level: 2, name: "Screen time today" })).toBeVisible();
  });

  test("new and blocked pills", async ({ page }) => {
    await open(page);
    await expect(domainRow(page, "ads.tiktok.com").locator(".pill")).toHaveText("blocked");
    await expect(domainRow(page, "some-new-game-cdn.net").locator(".pill")).toHaveText("new");
    await expect(domainRow(page, "www.youtube.com").locator(".pill")).toHaveCount(0);
    await expect(domainRow(page, "www.youtube.com")).toContainText("YouTube");
  });

  test("domain search, kept across pages", async ({ page }) => {
    await open(page);
    const search = domains(page).getByRole("searchbox", { name: "Search domains" });
    await search.fill("roblox");
    await search.press("Enter");
    await page.waitForURL(/q=roblox/);
    await expect(domains(page).locator("tbody tr")).toHaveCount(2);
    await expect(domains(page)).toContainText("2 matching on this page");
    await expect(domains(page).getByRole("searchbox", { name: "Search domains" })).toHaveValue("roblox");

    // 7 days has a second page of one-off names: the search follows the pager
    await page.goto(`${PAGE}?range=7d`);
    await expect(domains(page)).toContainText("100 of 132 names");
    await domains(page).getByRole("searchbox", { name: "Search domains" }).fill("tail-cdn");
    await domains(page).getByRole("searchbox", { name: "Search domains" }).press("Enter");
    await page.waitForURL(/q=tail-cdn/);
    await expect(domains(page).locator("tbody tr")).toHaveCount(88);
    const pager = domains(page).getByRole("navigation", { name: "Domain pages" });
    await expect(pager).toContainText("Page 1 of 2");
    await pager.getByRole("link", { name: "Next" }).click();
    await page.waitForURL(/page=1/);
    expect(new URL(page.url()).searchParams.get("q")).toBe("tail-cdn");
    expect(new URL(page.url()).searchParams.get("range")).toBe("7d");
    await expect(pager).toContainText("Page 2 of 2");
    await expect(domains(page).locator("tbody tr")).toHaveCount(32);
    await expect(domains(page).getByRole("searchbox", { name: "Search domains" })).toHaveValue("tail-cdn");
    // a new search from page 2 stays on page 2
    await domains(page).getByRole("searchbox", { name: "Search domains" }).fill("edge-119");
    await domains(page).getByRole("searchbox", { name: "Search domains" }).press("Enter");
    await page.waitForURL(/q=edge-119/);
    expect(new URL(page.url()).searchParams.get("page")).toBe("1");
    await expect(domains(page).locator("tbody tr")).toHaveCount(1);
  });

  test("set a service override, then remove it", async ({ page }) => {
    await login(page);
    await page.goto("/ui/core/dashboard");
    await hydrated(page);
    await discardStaged(page);
    await page.goto(PAGE);
    const name = "some-new-game-cdn.net";
    await expect(domainRow(page, name).locator(".dom-svc")).toContainText(name);

    await domainRow(page, name).getByRole("link", { name: `Set service for ${name}` }).click();
    const dialog = page.getByRole("dialog", { name: "Set service" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByLabel("Domain suffix")).toHaveValue(name);
    await expect(dialog.getByLabel("Service")).toBeFocused();
    await dialog.getByLabel("Service").fill("Fortnite");
    await dialog.getByLabel("Category").selectOption({ label: "Games" });
    await dialog.getByRole("button", { name: "Save" }).click();
    await page.waitForURL(/saved=applied/);
    await expect(page.getByRole("status").filter({ hasText: "Service override saved" })).toBeVisible();
    await expect(dialog).toHaveCount(0);
    await expect(domainRow(page, name).locator(".dom-svc")).toContainText("Fortnite");
    await expect(domainRow(page, name).locator(".dom-svc")).toContainText("(Games)");

    await domainRow(page, name).getByRole("link", { name: `Set service for ${name}` }).click();
    await expect(dialog.getByLabel("Service")).toHaveValue("Fortnite");
    await dialog.getByRole("button", { name: "Remove override" }).click();
    await page.waitForURL(/saved=removed/);
    await expect(page.getByRole("status").filter({ hasText: "Service override removed" })).toBeVisible();
    await expect(domainRow(page, name).locator(".dom-svc")).not.toContainText("Fortnite");
    await expect(domainRow(page, name).locator(".dom-svc")).toContainText(name);
  });

  test("Escape closes the override editor", async ({ page }) => {
    await open(page);
    await domainRow(page, "www.youtube.com").getByRole("link", { name: "Set service for www.youtube.com" }).click();
    const dialog = page.getByRole("dialog", { name: "Set service" });
    await expect(dialog).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    expect(new URL(page.url()).searchParams.get("edit")).toBeNull();
  });

  test("phone layout", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await open(page);
    for (const q of ["", "?range=7d", "?edit=www.youtube.com"]) {
      await page.goto(PAGE + q);
      await expect(page.getByRole("heading", { level: 2, name: "kid-tablet" })).toBeVisible();
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow, `horizontal scroll at 390 px on ${q || "today"}`).toBeLessThanOrEqual(0);
    }
    // the optional columns fold away, the name and service stay
    await page.goto(PAGE);
    await expect(domains(page).locator("thead th.col-opt").first()).toBeHidden();
    await expect(domainRow(page, "www.youtube.com").locator(".dom-svc")).toBeVisible();
  });

  for (const theme of ["light", "dark"] as const) {
    test(`accessible (${theme})`, async ({ page }) => {
      await login(page);
      await setTheme(page, theme);
      for (const q of ["", "?range=7d", "?edit=some-new-game-cdn.net"]) {
        await page.goto(PAGE + q);
        await hydrated(page);
        await expect(page.getByRole("heading", { level: 2, name: "kid-tablet" })).toBeVisible();
        await expectAccessible(page);
      }
      await page.goto("/ui/core/dashboard");
      await hydrated(page);
      await expectAccessible(page);
    });
  }
});
