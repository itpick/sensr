import { expect, test } from "@playwright/test";
import { hydrated, login } from "./helpers";

const card = (page: import("@playwright/test").Page) => page.locator("section.hosts-card");
const rows = (page: import("@playwright/test").Page) => card(page).locator("tbody tr");

async function open(page: import("@playwright/test").Page) {
  await login(page);
  await page.goto("/ui/core/dashboard");
  await hydrated(page);
  await expect(card(page).getByRole("heading", { name: "Hosts (25)" })).toBeVisible();
}

test("dashboard shows the Hosts card with 20 rows and Show all", async ({ page }) => {
  await open(page);
  await expect(rows(page)).toHaveCount(20);
  await card(page).getByRole("button", { name: "Show all (25)" }).click();
  await expect(rows(page)).toHaveCount(25);
});

test("search filters by MAC", async ({ page }) => {
  await open(page);
  await card(page).getByPlaceholder("Search name, MAC or IP").fill("02:00:00:00:00:0a");
  await expect(rows(page)).toHaveCount(1);
  await expect(rows(page).first()).toContainText("device-10");
});

test("network filter shows only LAN2", async ({ page }) => {
  await open(page);
  await card(page).getByRole("combobox").selectOption({ label: "LAN2" });
  await expect(rows(page).first()).toBeVisible();
  const cells = await rows(page).locator("td:nth-child(4)").allTextContents();
  expect(cells.length).toBeGreaterThan(0);
  expect(cells.every((c) => c.trim() === "LAN2")).toBe(true);
});

test("forget removes a dynamic host", async ({ page }) => {
  await open(page);
  const row = rows(page).filter({ hasText: "device-01" });
  await expect(row).toHaveCount(1);
  page.once("dialog", (d) => {
    expect(d.message()).toBe("Forget device-01? It reappears if it is still on the network.");
    void d.accept();
  });
  await row.getByRole("button", { name: "Forget" }).click();
  await expect(card(page).getByRole("heading", { name: "Hosts (24)" })).toBeVisible();
  await expect(rows(page).filter({ hasText: "device-01" })).toHaveCount(0);
});

test.describe("read-only user", () => {
  test.skip(!!process.env.SENSR_UI_BASE_URL, "needs the read-only dev server");
  const port = Number(process.env.SENSR_UI_PORT ?? 3300) + 1;
  test.use({ baseURL: `http://127.0.0.1:${port}` });

  test("read-only user sees no actions", async ({ page }) => {
    await open(page);
    await expect(rows(page)).toHaveCount(20);
    await expect(card(page).getByRole("button", { name: "Forget" })).toHaveCount(0);
    await expect(card(page).getByRole("button", { name: "Make static" })).toHaveCount(0);
  });
});
