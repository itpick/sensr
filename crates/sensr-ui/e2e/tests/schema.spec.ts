import { expect, test } from "@playwright/test";
import { hydrated, login } from "./helpers";

// The document-backed behaviour: sensr-schema validation and runtime interface selects.

test("grid: backend (schema) validation lands on the field", async ({ page }) => {
  await login(page);
  await page.goto("/ui/firewall/alias");
  await hydrated(page);
  await page.getByRole("button", { name: "Add" }).click();
  const dialog = page.getByRole("dialog", { name: "Add alias" });
  await dialog.getByLabel("Name").fill("nas");
  await dialog.getByLabel("Content").fill("192.168.1.99");
  await dialog.getByRole("button", { name: "Save" }).click();
  // Passes the browser-side checks; sensr-schema rejects the duplicate name.
  await expect(dialog.getByLabel("Name")).toHaveAccessibleDescription(/already exists/);
  await dialog.getByRole("button", { name: "Cancel" }).click();
});

test("rules: add a rule on the WAN tab", async ({ page }) => {
  await login(page);
  await page.goto("/ui/firewall/filter/wan");
  await hydrated(page);
  const rows = page.locator(".grid tbody tr");
  const before = await rows.count();
  await page.getByRole("button", { name: "Add" }).click();
  const dialog = page.getByRole("dialog", { name: "Add rule" });
  await expect(dialog.getByLabel("Interface")).toHaveValue("wan");
  await dialog.getByLabel("Protocol").selectOption("tcp");
  await dialog.getByLabel("Destination port").fill("22");
  await dialog.getByLabel("Description").fill("SSH from anywhere");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(dialog).toBeHidden();
  await expect(rows).toHaveCount(before + 1);
  await expect(rows.last()).toContainText("SSH from anywhere");
});
