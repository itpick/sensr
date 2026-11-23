import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { expectAccessible, hydrated, login, setTheme } from "./helpers";

// The global search box in the top bar (combobox + grouped listbox), on the mock backend.

const box = (page: Page) => page.getByRole("combobox", { name: "Search sensr" });
const pop = (page: Page) => page.locator("#gsearch-pop");
const group = (page: Page, name: string) => page.locator("#gsearch-list").getByRole("group", { name, exact: true });
const SERVER_FN = /\/ui\/fn\/global_search/;

async function at(page: Page, url: string) {
  await login(page);
  await page.goto(url);
  await hydrated(page);
}

/** Types into the box and waits for the results of exactly that query. */
async function search(page: Page, q: string) {
  await box(page).fill(q);
  await expect(page.locator("#gsearch-opt-0")).toBeVisible();
}

test("finds a page", async ({ page }) => {
  await at(page, "/ui/core/dashboard");
  await search(page, "dhcp");
  await expect(group(page, "Pages").getByRole("option").first()).toHaveAttribute("data-url", "/ui/dhcpv4/lan");
  await box(page).press("Enter");
  await page.waitForURL("**/ui/dhcpv4/lan");
});

test("interface pages are titled without the menu brackets", async ({ page }) => {
  await at(page, "/ui/core/dashboard");
  await search(page, "dhcp");
  const first = group(page, "Pages").getByRole("option").first();
  await expect(first.locator(".gsearch-title")).toHaveText("LAN");
  await expect(first.locator(".gsearch-detail")).toContainText("DHCPv4");
});

test("finds a setting and flashes it", async ({ page }) => {
  await at(page, "/ui/core/dashboard");
  await search(page, "hostname");
  await group(page, "Settings").getByRole("option", { name: /^Hostname/ }).click();
  await page.waitForURL("**/ui/system/general#form-systemgeneral--hostname");
  await hydrated(page);
  await expect(page.locator("#form-systemgeneral--hostname")).toBeFocused();
  await expect(page.locator(".field.field-flash")).toHaveCount(1);
});

test("a setting on the page already open flashes without a reload", async ({ page }) => {
  await at(page, "/ui/system/general");
  const field = page.locator("#form-systemgeneral--hostname");
  const hit = () => group(page, "Settings").getByRole("option", { name: /^Hostname/ });
  await page.evaluate(() => ((window as unknown as { gsMarker: number }).gsMarker = 1));
  await search(page, "hostname");
  await hit().click();
  await expect(field).toBeFocused();
  await expect(page.locator(".field.field-flash")).toHaveCount(1);
  await expect(page.locator(".field.field-flash")).toHaveCount(0, { timeout: 4000 });
  // the same hit again: the hash does not change, and it still flashes
  await search(page, "hostname");
  await hit().click();
  await expect(page.locator(".field.field-flash")).toHaveCount(1);
  expect(await page.evaluate(() => (window as unknown as { gsMarker?: number }).gsMarker), "no reload").toBe(1);
});

test("finds an alias and opens its dialog", async ({ page }) => {
  await at(page, "/ui/core/dashboard");
  await search(page, "web_ports");
  await group(page, "Aliases").getByRole("option", { name: /^web_ports/ }).click();
  await page.waitForURL("**/ui/firewall/alias**");
  await hydrated(page);
  const dlg = page.locator("dialog.modal[open]");
  await expect(dlg).toBeVisible();
  await expect(dlg.locator("#grid-aliases-dlg--name")).toHaveValue("web_ports");
});

test("no Show all when the matches span several grid tabs", async ({ page }) => {
  await at(page, "/ui/core/dashboard");
  // 6 rules match "an", on the LAN, WireGuard and floating tabs: no one tab lists them all
  await search(page, "an");
  const rules = group(page, "Rules");
  await expect(rules.getByRole("option")).toHaveCount(5);
  await expect(rules.getByRole("option", { name: /^Show all/ })).toHaveCount(0);
});

test("finds a host", async ({ page }) => {
  await at(page, "/ui/core/dashboard");
  await search(page, "b8:27:eb");
  await group(page, "Hosts").getByRole("option", { name: /^bench-pi/ }).click();
  await page.waitForURL(/\/ui\/core\/dashboard\?host=b8%3A27%3Aeb%3A7d%3A4e%3A25#w-hosts$/);
  await hydrated(page);
  await expect(page.locator(".hosts-card input[type=search]")).toHaveValue("b8:27:eb:7d:4e:25");
});

test("keyboard", async ({ page }) => {
  await at(page, "/ui/firewall/alias");
  await page.locator("h1").click();
  await page.keyboard.press("/");
  await expect(box(page)).toBeFocused();
  await page.keyboard.type("dhcp");
  await expect(page.locator("#gsearch-opt-1")).toBeVisible();
  await expect(box(page)).toHaveAttribute("aria-expanded", "true");
  // arrows wrap
  await page.keyboard.press("ArrowUp");
  const n = await page.locator("#gsearch-list [role=option]").count();
  await expect(box(page)).toHaveAttribute("aria-activedescendant", `gsearch-opt-${n - 1}`);
  await page.keyboard.press("ArrowDown");
  await expect(box(page)).toHaveAttribute("aria-activedescendant", "gsearch-opt-0");
  await page.keyboard.press("ArrowDown");
  await expect(page.locator("#gsearch-opt-1")).toHaveAttribute("aria-selected", "true");
  // Esc closes, a second Esc clears
  await page.keyboard.press("Escape");
  await expect(pop(page)).toBeHidden();
  await expect(box(page)).toHaveAttribute("aria-expanded", "false");
  await expect(box(page)).toHaveValue("dhcp");
  await page.keyboard.press("Escape");
  await expect(box(page)).toHaveValue("");
  // Ctrl+K and ⌘K focus
  await page.locator("h1").click();
  await page.keyboard.press("Control+k");
  await expect(box(page)).toBeFocused();
  await page.locator("h1").click();
  await page.keyboard.press("Meta+k");
  await expect(box(page)).toBeFocused();
  // ↓↓ Enter opens the second option
  await page.keyboard.type("dhcp");
  await expect(page.locator("#gsearch-opt-1")).toBeVisible();
  const url = (await page.locator("#gsearch-opt-1").getAttribute("data-url"))!;
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await page.waitForURL(`**${url}`);
});

test("shortcuts stay out of the way", async ({ page }) => {
  await at(page, "/ui/firewall/alias");
  // `/` typed into another field is just a slash
  const grid = page.locator(".grid-toolbar input[type=search]");
  await grid.click();
  await page.keyboard.press("/");
  await expect(grid).toHaveValue("/");
  await expect(box(page)).not.toBeFocused();
  await grid.fill("");
  await page.locator("h1").click();
  // Shift or Alt with Ctrl+K is another shortcut
  await page.keyboard.press("Control+Shift+k");
  await expect(box(page)).not.toBeFocused();
  await page.keyboard.press("Control+Alt+k");
  await expect(box(page)).not.toBeFocused();
  // a modal dialog owns the keyboard
  await page.getByRole("button", { name: "Add" }).click();
  await expect(page.locator("dialog[open]")).toBeVisible();
  await page.keyboard.press("Control+k");
  await expect(box(page)).not.toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await page.locator("h1").click();
  await page.keyboard.press("Control+k");
  await expect(box(page)).toBeFocused();
});

test("focus leaving the search closes it; Esc works from the popup", async ({ page }) => {
  await at(page, "/ui/firewall/alias");
  await search(page, "dhcp");
  // Tab into the scrollable popup stays inside the search
  await page.keyboard.press("Tab");
  await expect(pop(page)).toBeFocused();
  await expect(pop(page)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(pop(page)).toBeHidden();
  // Tab out of it
  await box(page).focus();
  await expect(pop(page)).toBeVisible();
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");
  await expect(pop(page)).toBeHidden();
  // a click elsewhere
  await box(page).focus();
  await expect(pop(page)).toBeVisible();
  await page.locator("h1").click();
  await expect(pop(page)).toBeHidden();
});

test("debounces_and_drops_stale", async ({ page }) => {
  await at(page, "/ui/core/dashboard");
  const sent: string[] = [];
  let first = true;
  await page.route(SERVER_FN, async (route) => {
    sent.push(JSON.parse(route.request().postData() ?? "{}").q);
    // the first answer is slow; the second is slowed too, so a wrongly applied first
    // answer would stay on screen long enough to be seen
    await new Promise((f) => setTimeout(f, first ? 1200 : 800));
    first = false;
    await route.continue();
  });
  // 8 keystrokes well inside 150 ms: one call
  await box(page).focus();
  await page.keyboard.type("firewall", { delay: 5 });
  await expect.poll(() => sent.length).toBe(1);
  await page.waitForTimeout(400);
  expect(sent).toEqual(["firewall"]);
  // a new query while that slow answer is out: it is asked once the first is back
  await box(page).fill("hostname");
  const stale = page.waitForResponse(SERVER_FN);
  await stale;
  // the late "firewall" answer is dropped: its Pages group never appears
  await page.waitForTimeout(300);
  await expect(group(page, "Pages")).toHaveCount(0);
  await expect(pop(page)).toBeHidden();
  await expect(group(page, "Settings").getByRole("option", { name: /^Hostname/ })).toBeVisible();
  await expect(group(page, "Pages")).toHaveCount(0);
  expect(sent).toEqual(["firewall", "hostname"]);
});

test("Enter does not open a stale hit", async ({ page }) => {
  await at(page, "/ui/core/dashboard");
  await search(page, "fire");
  await page.route(SERVER_FN, async (route) => {
    await new Promise((f) => setTimeout(f, 1200));
    await route.continue();
  });
  const answered = page.waitForResponse(SERVER_FN);
  await box(page).press("End");
  await page.keyboard.type("wall");
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await page.waitForTimeout(400);
  expect(new URL(page.url()).pathname, "the list was still for “fire”").toBe("/ui/core/dashboard");
  await answered;
  await expect(page.locator("#gsearch-opt-0")).toBeVisible();
  await page.keyboard.press("Enter");
  await page.waitForURL((u) => u.pathname !== "/ui/core/dashboard");
});

test("no matches", async ({ page }) => {
  await at(page, "/ui/core/dashboard");
  await box(page).fill("zzzz");
  await expect(page.locator(".gsearch-status")).toHaveText("No matches for “zzzz”");
  await expect(page.locator("#gsearch-list [role=option]")).toHaveCount(0);
});

for (const theme of ["light", "dark"] as const) {
  test(`dropdown is accessible (${theme})`, async ({ page }) => {
    await login(page);
    await setTheme(page, theme);
    await page.goto("/ui/firewall/alias");
    await hydrated(page);
    await search(page, "lan");
    await page.keyboard.press("ArrowDown");
    await expectAccessible(page);
  });
}

test("phone sheet", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await at(page, "/ui/core/dashboard");
  const open = page.getByRole("button", { name: "Search", exact: true });
  await expect(box(page)).toBeHidden();
  await open.click();
  await expect(box(page)).toBeVisible();
  await expect(box(page)).toBeFocused();
  await page.keyboard.type("fire");
  await expect(page.locator("#gsearch-opt-0")).toBeVisible();
  // the dashboard itself fails scrollable-region-focusable at this width; check only the search
  const r = await new AxeBuilder({ page }).include(".gsearch").withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(r.violations.map((v) => v.id)).toEqual([]);
  await page.keyboard.press("Escape");
  await expect(box(page)).toBeHidden();
  await expect(open).toBeFocused();
  // `/` opens it too; Esc from the close button dismisses it
  await page.keyboard.press("/");
  await expect(box(page)).toBeFocused();
  await page.getByRole("button", { name: "Close search" }).focus();
  await page.keyboard.press("Escape");
  await expect(box(page)).toBeHidden();
  // the close button, and focus leaving the sheet
  await open.click();
  await page.getByRole("button", { name: "Close search" }).click();
  await expect(box(page)).toBeHidden();
  // putting the keyboard away (a blur with nowhere to go) keeps the sheet and its results
  await open.click();
  await page.keyboard.type("fire");
  await expect(page.locator("#gsearch-opt-0")).toBeVisible();
  await page.evaluate(() => (document.activeElement as HTMLElement).blur());
  await page.waitForTimeout(200);
  await expect(box(page)).toBeVisible();
  await expect(page.locator("#gsearch-opt-0")).toBeVisible();
  // back in the box, focus moving to the page behind closes it
  await box(page).focus();
  await page.locator("#content").focus();
  await expect(box(page)).toBeHidden();
});

test("results are announced", async ({ page }) => {
  await at(page, "/ui/core/dashboard");
  const live = page.locator(".gsearch [aria-live=polite]");
  await expect(live).toBeAttached();
  await expect(live).toHaveText("");
  await search(page, "hostname");
  await expect(live).toHaveText("3 results");
  await box(page).fill("zzzz");
  await expect(live).toHaveText("No matches for “zzzz”");
});

test.describe("read-only user", () => {
  test.skip(!!process.env.SENSR_UI_BASE_URL, "needs the read-only dev server");
  const port = Number(process.env.SENSR_UI_PORT ?? 3300) + 1;
  test.use({ baseURL: `http://127.0.0.1:${port}` });

  // page-all + read-only: a read-only user searches everything it can read
  test("read-only user finds what it can read", async ({ page }) => {
    await at(page, "/ui/core/dashboard");
    await search(page, "192.168");
    await expect(group(page, "Hosts")).toBeVisible();
    await expect(group(page, "Aliases")).toBeVisible();
    const urls = await page.locator("#gsearch-list [role=option]").evaluateAll((os) => os.map((o) => o.getAttribute("data-url")!));
    for (const u of urls) {
      const res = await page.request.get(u);
      expect(res.status(), u).toBe(200);
    }
  });
});

test.describe("alias-only user", () => {
  test.skip(!!process.env.SENSR_UI_BASE_URL, "needs the alias-only dev server");
  const port = Number(process.env.SENSR_UI_PORT ?? 3300) + 2;
  test.use({ baseURL: `http://127.0.0.1:${port}` });
  test.describe.configure({ mode: "serial" });

  test("sees no hidden pages", async ({ page }) => {
    // (the dashboard's hosts card stays empty for this user, so wait on the alias page)
    await at(page, "/ui/firewall/alias");
    // root on the main server gets Rules and Hosts for these; this user may only open aliases
    for (const q of ["192.168", "lan", "an", "b8:27:eb"]) {
      await box(page).fill(q);
      await expect(page.locator(".gsearch [aria-live=polite]")).not.toHaveText("");
      const groups = await page.locator("#gsearch-list [role=group]").evaluateAll((gs) => gs.map((g) => g.getAttribute("aria-label")));
      for (const hidden of ["Rules", "Users", "Hosts", "Settings", "Assignments", "Port Forward"]) {
        expect(groups, `${q}: ${hidden}`).not.toContain(hidden);
      }
      const urls = await page.locator("#gsearch-list [role=option]").evaluateAll((os) => os.map((o) => o.getAttribute("data-url")!));
      for (const u of urls) expect(u, q).toMatch(/^\/ui\/firewall\/alias(\?|$)/);
      await box(page).fill("");
    }
    await box(page).fill("192.168");
    await expect(group(page, "Aliases").getByRole("option")).toHaveCount(3);
  });

  test("show all opens the grid listing every match", async ({ page }) => {
    await at(page, "/ui/firewall/alias");
    // six new aliases: one more than a group shows (this server's own mock state)
    for (let i = 1; i <= 6; i++) {
      await page.getByRole("button", { name: "Add" }).click();
      const dialog = page.getByRole("dialog", { name: "Add alias" });
      await dialog.getByLabel("Name").fill(`qsall_${i}`);
      await dialog.getByLabel("Content").fill(`10.9.9.${i}`);
      await dialog.getByRole("button", { name: "Save" }).click();
      await expect(dialog).toBeHidden();
    }
    await search(page, "qsall");
    const aliases = group(page, "Aliases");
    const more = aliases.getByRole("option", { name: /^Show all \(\d+\)$/ });
    await expect(more).toHaveText("Show all (6)");
    await expect(more).toHaveAttribute("data-url", "/ui/firewall/alias?q=qsall");
    await more.click();
    await page.waitForURL("**/ui/firewall/alias?q=qsall");
    await hydrated(page);
    await expect(page.locator(".grid-toolbar input[type=search]")).toHaveValue("qsall");
    // the grid lists as many as Show all promised
    await expect(page.locator(".grid tbody tr")).toHaveCount(6);
  });
});
