import { expect, test } from "@playwright/test";
import { hydrated, login } from "./helpers";

const card = (page: import("@playwright/test").Page) => page.locator("section.hosts-card");
const rows = (page: import("@playwright/test").Page) => card(page).locator("tbody tr");

async function open(page: import("@playwright/test").Page) {
  await login(page);
  await page.goto("/ui/core/dashboard");
  await hydrated(page);
  await expect(card(page).getByRole("heading", { name: /^Hosts \(\d+\)$/ })).toBeVisible();
  await expect(rows(page)).toHaveCount(20);
}

async function count(page: import("@playwright/test").Page) {
  const t = (await card(page).getByRole("heading", { name: /^Hosts \(\d+\)$/ }).textContent()) ?? "";
  return Number(/\((\d+)\)/.exec(t)![1]);
}

test("dashboard shows the Hosts card with 20 rows and Show all", async ({ page }) => {
  await open(page);
  const n = await count(page);
  await card(page).getByRole("button", { name: `Show all (${n})` }).click();
  await expect(rows(page)).toHaveCount(n);
});

test("search filters by MAC", async ({ page }) => {
  await open(page);
  await card(page).getByPlaceholder("Search name, MAC or IP").fill("02:00:00:00:00:0a");
  await expect(rows(page)).toHaveCount(1);
  await expect(rows(page).first()).toContainText("device-10");
});

test("network filter shows only LAN2", async ({ page }) => {
  await open(page);
  await card(page).getByRole("combobox", { name: "Network", exact: true }).selectOption({ label: "LAN2" });
  const lan = rows(page).locator("td:nth-child(4)").filter({ hasNotText: /^LAN2$/ });
  await expect(lan).toHaveCount(0);
  await expect(rows(page).first()).toBeVisible();
  await expect(rows(page).filter({ hasText: "nas" })).toHaveCount(0);
});

test("mode select isolates a host and quarantine of your own device is refused", async ({ page }) => {
  // device-01 is the mock's own client; also runs before Forget, which may drop it
  test.skip(!!process.env.SENSR_UI_BASE_URL, "relies on the mock's client MAC");
  await open(page);
  const pi = rows(page).filter({ hasText: "bench-pi" });
  const mode = pi.getByRole("combobox", { name: "Mode for bench-pi" });
  await mode.selectOption("isolated");
  // in force at once, or staged when an earlier test left changes waiting for Apply
  await expect(pi.locator(".pill-warn, .host-mode-staged")).toHaveText(
    /^(Isolated|Staged — Apply to take effect)$/,
  );
  await expect(mode).toHaveValue("isolated");
  await expect(card(page)).toContainText("Same-network blocking works by redirecting");
  await mode.selectOption("normal");
  await expect(pi.locator(".pill, .host-mode-staged")).toHaveCount(0);
  await expect(mode).toHaveValue("normal");
  const own = rows(page).filter({ hasText: "device-01" });
  await own.getByRole("combobox", { name: "Mode for device-01" }).selectOption("quarantine");
  await expect(card(page).getByRole("alert")).toHaveText(
    "That's the device you're using — quarantine it from another device.",
  );
  await expect(own.getByRole("combobox", { name: "Mode for device-01" })).toHaveValue("normal");
});

test("forget removes a dynamic host", async ({ page }) => {
  await open(page);
  const before = await count(page);
  const row = rows(page).filter({ hasText: /device-\d+/ }).first();
  const name = ((await row.locator("td").first().textContent()) ?? "").trim();
  let message = "";
  page.once("dialog", (d) => {
    message = d.message();
    void d.accept();
  });
  await row.getByRole("button", { name: "Forget" }).click();
  await expect(card(page).getByRole("heading", { name: `Hosts (${before - 1})` })).toBeVisible();
  expect(message).toBe(`Forget ${name}? It reappears if it is still on the network.`);
  await expect(rows(page).filter({ hasText: name })).toHaveCount(0);
});

test.describe("read-only user", () => {
  test.skip(!!process.env.SENSR_UI_BASE_URL, "needs the read-only dev server");
  const port = Number(process.env.SENSR_UI_PORT ?? 3300) + 1;
  test.use({ baseURL: `http://127.0.0.1:${port}` });

  test("read-only user sees no actions", async ({ page }) => {
    await open(page);
    await expect(card(page).getByRole("button", { name: "Forget" })).toHaveCount(0);
    await expect(card(page).getByRole("button", { name: "Make static" })).toHaveCount(0);
    await expect(card(page).getByRole("combobox", { name: /^Mode for / })).toHaveCount(0);
  });
});
