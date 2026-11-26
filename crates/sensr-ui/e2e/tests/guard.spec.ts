import { expect, test, type Page } from "@playwright/test";
import { expectAccessible, hydrated, login } from "./helpers";

// Services › Runtime Guard on the mock's canned sensr-guard: status with the kill switch,
// the rules (one inactive with its reason), the seeded events and the packs. The page is
// server-rendered with plain forms. Each test drops what it staged and turns the kill
// switch back off.
test.skip(!!process.env.SENSR_UI_BASE_URL, "relies on the mock's canned sensr-guard");

const WARNING = "Blocking: you'll have 2 minutes to confirm";
const region = (page: Page, name: string) => page.getByRole("region", { name, exact: true });
const banner = (page: Page) => page.getByRole("region", { name: "Pending changes" });
const ruleRow = (page: Page, name: string) =>
  region(page, "Rules").getByRole("row").filter({ has: page.getByRole("cell", { name, exact: true }) });

async function open(page: Page, query = "") {
  await login(page);
  await page.goto("/ui/guard" + query);
  await hydrated(page);
  await expect(region(page, "Status")).toBeVisible();
}

async function discardStaged(page: Page) {
  const discard = banner(page).getByRole("button", { name: "Discard" });
  if (await discard.isVisible()) {
    page.once("dialog", (d) => void d.accept());
    await discard.click();
    await expect(banner(page)).not.toContainText("The configuration has been changed");
  }
}

test.describe("runtime guard", () => {
  test("the page loads with status, rules, events and packs", async ({ page }) => {
    await login(page);
    await expect(page.locator('nav[aria-label="Main menu"] a[href="/ui/guard"]')).toHaveText("Runtime Guard");
    await open(page);
    await expect(region(page, "Status")).toContainText("running");
    // an inactive rule says why
    const listeners = ruleRow(page, "Unexpected listening sockets");
    await expect(listeners).toContainText("inactive");
    await expect(listeners).toContainText("the listen program is not attached");
    await expect(ruleRow(page, "Shells started by the web server")).toContainText("active");
    await expect(ruleRow(page, "core-module-load")).toContainText("core");
    // events: filter by hook, page through
    const events = region(page, "Events");
    await expect(events.getByRole("table")).toContainText("/bin/sh");
    await expect(events.getByRole("navigation", { name: "Event pages" })).toContainText("1–50 of 60");
    await events.getByRole("link", { name: "Older" }).click();
    await expect(region(page, "Events").getByRole("navigation", { name: "Event pages" })).toContainText("51–60 of 60");
    await region(page, "Events").getByLabel("Watch").selectOption("module");
    await region(page, "Events").getByRole("button", { name: "Filter" }).click();
    await expect(page).toHaveURL(/hook=module/);
    const rows = region(page, "Events").locator("tbody tr");
    await expect(rows).toHaveCount(3);
    await expect(rows.first()).toContainText("kmod");
    // packs
    const core = region(page, "Packs").getByRole("row").filter({ hasText: "core" }).first();
    await expect(core).toContainText("built in");
    await expect(core).toContainText("verified");
    await expectAccessible(page);
  });

  test("add an alert rule; choosing Block warns about the confirm window", async ({ page }) => {
    await open(page);
    await discardStaged(page);
    const form = page.locator("form#guard-rule-form");
    const action = form.getByLabel("Action");
    const warn = form.getByText(WARNING);
    await expect(action).toHaveValue("alert");
    await expect(warn).toBeHidden();
    await action.selectOption("block");
    await expect(warn).toBeVisible();
    await action.selectOption("alert");
    await expect(warn).toBeHidden();
    await form.getByLabel("Description").fill("Curl started");
    await form.getByLabel("Watch").selectOption("exec");
    await form.getByLabel("Target", { exact: true }).selectOption("path_prefix");
    await form.getByLabel("Path, network or user id").fill("/usr/bin/curl");
    await form.getByRole("button", { name: "Add rule" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Rule saved" })).toHaveText("Rule saved. Apply the change to start it.");
    const row = ruleRow(page, "Curl started");
    await expect(row).toContainText("/usr/bin/curl…");
    await expect(row).toContainText("alert");
    await expect(row).toContainText("not applied yet");
    await hydrated(page);
    await discardStaged(page);
    await page.goto("/ui/guard");
    await expect(ruleRow(page, "Curl started")).toHaveCount(0);
  });

  test("the kill switch is shown and switches", async ({ page }) => {
    await open(page);
    const status = region(page, "Status");
    await expect(status).toContainText("Kill switch");
    await status.getByRole("button", { name: "Turn kill switch on" }).click();
    await expect(page.getByRole("status").first()).toHaveText("Kill switch on: nothing is blocked, alerts only.");
    await expect(region(page, "Status")).toContainText("on: nothing is blocked, alerts only");
    await region(page, "Status").getByRole("button", { name: "Turn kill switch off" }).click();
    await expect(page.getByRole("status").first()).toHaveText("Kill switch off: block rules are enforced again.");
    await expect(region(page, "Status").getByRole("button", { name: "Turn kill switch on" })).toBeVisible();
  });
});

test.describe("read-only user", () => {
  const port = Number(process.env.SENSR_UI_PORT ?? 3300) + 1;
  test.use({ baseURL: `http://127.0.0.1:${port}` });

  test("sees the guard but cannot change it", async ({ page }) => {
    await open(page);
    await expect(region(page, "Status")).toContainText("Kill switch");
    await expect(ruleRow(page, "Unexpected listening sockets")).toContainText("inactive");
    await expect(page.getByRole("button", { name: /kill switch|Add rule|Check for pack updates|^Turn (on|off)/ })).toHaveCount(0);
    await expect(page.locator("form#guard-rule-form")).toHaveCount(0);
  });
});
