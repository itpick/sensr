// Deep links the global search leads to: grid ?q= / ?edit=, form field anchors, dashboard ?host=.
import { test, expect } from "@playwright/test";
import { login, hydrated } from "./helpers";

test("grid ?q= prefills and filters", async ({ page }) => {
  await login(page);
  await page.goto("/ui/firewall/alias?q=web");
  await hydrated(page);
  await expect(page.locator(".grid-toolbar input[type=search]")).toHaveValue("web");
  await expect(page.locator("tbody tr")).toHaveCount(1);
});

test("grid ?edit= opens the dialog and leaves the URL", async ({ page }) => {
  await login(page);
  await page.goto("/ui/firewall/alias?edit=6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a03");
  await hydrated(page);
  const dlg = page.locator("dialog.modal[open]");
  await expect(dlg).toBeVisible();
  await expect(dlg.getByRole("heading")).toContainText("Edit");
  await expect(dlg.locator("#grid-aliases-dlg--name")).toHaveValue("nas");
  expect(new URL(page.url()).search).toBe("");
});

test("scoped grid ?edit= works", async ({ page }) => {
  await login(page);
  await page.goto("/ui/firewall/filter/lan?edit=a1e1c6f0-1d6e-4b1e-8f00-000000000003");
  await hydrated(page);
  await expect(page.locator("dialog.modal[open]")).toBeVisible();
});

test("grid ?edit= unknown uuid is ignored", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  await login(page);
  await page.goto("/ui/firewall/alias?edit=deadbeef-gone");
  await hydrated(page);
  await expect(page.locator("dialog.modal[open]")).toHaveCount(0);
  await expect(page.locator("tbody tr").first()).toBeVisible();
  await expect(page.locator(".grid p.status")).toHaveText("");
  expect(errors).toEqual([]);
});

test("form field anchor scrolls, focuses, flashes", async ({ page }) => {
  await login(page);
  await page.goto("/ui/system/general#form-systemgeneral--hostname");
  await hydrated(page);
  const input = page.locator("#form-systemgeneral--hostname");
  await expect(input).toBeFocused();
  await expect(page.locator(".field.field-flash")).toHaveCount(1);
  await expect(page.locator(".field.field-flash")).toHaveCount(0, { timeout: 4000 });
});

test("dashboard ?host= prefills hosts search", async ({ page }) => {
  await login(page);
  await page.goto("/ui/core/dashboard?host=nas#w-hosts");
  await hydrated(page);
  await expect(page.locator(".hosts-card input[type=search]")).toHaveValue("nas");
});

test("grid ?q=&edit= keeps q after opening", async ({ page }) => {
  await login(page);
  await page.goto("/ui/firewall/alias?q=file&edit=6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a03");
  await hydrated(page);
  await expect(page.locator("dialog.modal[open]")).toBeVisible();
  expect(new URL(page.url()).search).toBe("?q=file");
});
