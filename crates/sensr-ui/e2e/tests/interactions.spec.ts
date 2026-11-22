import { expect, test } from "@playwright/test";
import { hydrated, login, shots } from "./helpers";

test.describe.configure({ mode: "serial" });

test("login: focus order, wrong password, sign in", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByLabel("Username")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("Password", { exact: true })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("One-time password")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Login" })).toBeFocused();

  await page.getByLabel("Username").fill("root");
  await page.getByLabel("Password", { exact: true }).fill("wrong");
  await page.getByRole("button", { name: "Login" }).click();
  await expect(page.getByRole("alert")).toHaveText("Wrong username, password or one-time password.");

  await login(page);
  await expect(page).toHaveTitle("Lobby: Dashboard | sensr");
});

test("unauthenticated pages redirect to login", async ({ page }) => {
  await page.goto("/ui/firewall/alias");
  await expect(page).toHaveURL(/\/login$/);
});

test("menu tree mirrors OPNsense and marks the current page", async ({ page }) => {
  await login(page);
  const sections = page.locator("#sidebar > ul > li > details > summary");
  await expect(sections).toHaveText(["Lobby", "Reporting", "System", "Interfaces", "Firewall", "VPN", "Services", "Help"]);
  await page.goto("/ui/firewall/alias");
  const current = page.locator('#sidebar a[aria-current="page"]');
  await expect(current).toHaveText("Aliases");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Firewall: Aliases");
  // Dynamic entries: assigned interfaces and DHCP-capable ones.
  await expect(page.locator("#sidebar a", { hasText: "[WAN]" })).toHaveAttribute("href", "/ui/interfaces/if/wan");
  await expect(page.locator("#sidebar a", { hasText: "[LAN]" }).last()).toHaveAttribute("href", "/ui/dhcpv4/lan");
  // Unimplemented entries land on a placeholder inside the shell.
  await page.goto("/ui/trust/ca");
  await expect(page.getByRole("heading", { name: "Not available yet" })).toBeVisible();
  // The menu no longer lists unimplemented pages, so the title has no breadcrumb.
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("sensr");
});

test("grid: search, sort, paging info, bulk disable, validation, add, edit, delete", async ({ page }) => {
  await login(page);
  await page.goto("/ui/firewall/alias");
  await hydrated(page);
  const rows = page.locator(".grid tbody tr");
  await expect(rows).toHaveCount(6);
  await expect(page.getByText("Showing 1 to 6 of 6 entries")).toBeVisible();

  await page.getByLabel("Search alias").fill("port");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("web_ports");
  await page.getByLabel("Search alias").fill("");
  await expect(rows).toHaveCount(6);

  await page.getByRole("button", { name: "Name" }).click();
  await expect(page.getByRole("columnheader", { name: "Name" })).toHaveAttribute("aria-sort", "ascending");
  await expect(rows.first()).toContainText("admins");
  await page.getByRole("button", { name: "Name" }).click();
  await expect(rows.first()).toContainText("web_ports");

  // Bulk disable two rows.
  await page.getByLabel("Select web_ports").check();
  await page.getByLabel("Select spamhaus_drop").check();
  await page.getByRole("button", { name: "Disable", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "disabled" })).toHaveText("1 row disabled.");
  await expect(page.getByText("The configuration has been changed.")).toBeVisible();

  // Add with validation errors, per field path.
  await page.getByRole("button", { name: "Add" }).click();
  const dialog = page.getByRole("dialog", { name: "Add alias" });
  await expect(dialog).toBeVisible();
  await dialog.getByLabel("Name").fill("9bad name");
  await dialog.getByLabel("Type").selectOption("port");
  await dialog.getByLabel("Content").fill("80\nhttp alt");
  await dialog.getByRole("button", { name: "Save" }).click();
  const nameField = dialog.getByLabel("Name");
  await expect(nameField).toHaveAttribute("aria-invalid", "true");
  await expect(nameField).toHaveAccessibleDescription(/The name must be at most 31 characters/);
  await expect(dialog.getByLabel("Content")).toHaveAccessibleDescription(/http alt.*not valid/);
  await page.screenshot({ path: `${shots}/interaction-validation.png` });
  await nameField.fill("dns_servers");
  await dialog.getByLabel("Content").fill("53\n853");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(dialog).toBeHidden();
  await expect(rows).toHaveCount(7);

  // Edit.
  await rows.filter({ hasText: "dns_servers" }).getByRole("button", { name: "Edit" }).click();
  const edit = page.getByRole("dialog", { name: "Edit alias" });
  await edit.getByLabel("Description").fill("Resolvers");
  await edit.getByRole("button", { name: "Save" }).click();
  await expect(rows.filter({ hasText: "dns_servers" })).toContainText("Resolvers");

  // Delete.
  page.once("dialog", (d) => d.accept());
  await rows.filter({ hasText: "dns_servers" }).getByRole("button", { name: "Delete" }).click();
  await expect(rows).toHaveCount(6);
});

test("rules: per-interface tabs, reorder with buttons and drag", async ({ page }) => {
  await login(page);
  await page.goto("/ui/firewall/filter/lan");
  await hydrated(page);
  const rows = page.locator(".grid tbody tr");
  await expect(rows).toHaveCount(3);
  const descs = () => rows.locator("td:nth-child(9)").allInnerTexts();
  expect(await descs()).toEqual(["Default allow LAN to any rule", "Default allow LAN IPv6 to any rule", "No direct SMTP"]);

  await rows.nth(0).getByRole("button", { name: "Move down" }).click();
  await expect.poll(descs).toEqual(["Default allow LAN IPv6 to any rule", "Default allow LAN to any rule", "No direct SMTP"]);

  await rows.nth(2).dragTo(rows.nth(0));
  await expect.poll(descs).toEqual(["No direct SMTP", "Default allow LAN IPv6 to any rule", "Default allow LAN to any rule"]);

  await page.getByRole("link", { name: "WAN", exact: true }).click();
  await expect(rows).toHaveCount(2);
});

test("settings form, apply with rollback window, confirm, history diff, revert", async ({ page }) => {
  await login(page);
  await page.goto("/ui/system/general");
  await hydrated(page);
  await page.getByLabel("Hostname").fill("bad host");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByLabel("Hostname")).toHaveAccessibleDescription(/letters, digits, hyphens/i);
  await page.getByLabel("Hostname").fill("fw1");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Saved" })).toBeVisible();

  const banner = page.getByRole("region", { name: "Pending changes" });
  await expect(banner).toContainText("The configuration has been changed.");
  await expect(banner.getByLabel("Roll back unless confirmed within 60 s")).toBeChecked();
  await banner.getByRole("button", { name: "Apply" }).click();
  await expect(banner).toContainText(/rolls back automatically in \d+ s/);
  await page.screenshot({ path: `${shots}/interaction-confirm.png` });
  await banner.getByRole("button", { name: "Keep changes" }).click();
  await expect(banner).not.toContainText("rolls back");

  await page.goto("/ui/core/backup/history");
  await expect(page.locator("pre.diff")).toContainText('"hostname": "fw1"');
  const head = page.locator("tbody tr").first();
  await expect(head).toContainText("active");
  // Revert to the revision before: a plain form post.
  await page.locator("tbody tr").nth(1).getByRole("button", { name: "Revert to this" }).click();
  await expect(page.locator("tbody tr").first()).toContainText(/rollback to revision/i);
  await page.goto("/ui/system/general");
  await expect(page.getByLabel("Hostname")).not.toHaveValue("fw1");
});

test("phone: menu opens from the top bar", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page);
  await hydrated(page);
  const nav = page.locator('nav[aria-label="Main menu"]');
  await expect(nav).not.toBeInViewport();
  await page.getByRole("button", { name: "Menu" }).click();
  await expect(nav).toBeInViewport();
  await expect(page.getByRole("button", { name: "Menu" })).toHaveAttribute("aria-expanded", "true");
  for (const url of ["/", "/ui/firewall/alias", "/ui/firewall/filter/lan", "/ui/dhcpv4/lan", "/ui/core/backup/history"]) {
    await page.goto(url);
    const width = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(width, `no horizontal page scrolling at phone width on ${url}`).toBeLessThanOrEqual(390);
  }
});

test("theme toggle switches and persists", async ({ page }) => {
  await login(page);
  await hydrated(page);
  const toggle = page.getByRole("button", { name: "Dark theme" });
  const before = await toggle.getAttribute("aria-pressed");
  await toggle.click();
  const want = before === "true" ? "light" : "dark";
  await expect(page.locator("html")).toHaveAttribute("data-theme", want);
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", want);
});
