import { expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

export const shots = process.env.SENSR_UI_SHOTS ?? "screenshots";

export async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Username").fill("root");
  await page.getByLabel("Password", { exact: true }).fill("sensr");
  await page.getByRole("button", { name: "Login" }).click();
  // Attached, not visible: at phone width the menu is off-screen and visibility:hidden.
  await expect(page.locator('nav[aria-label="Main menu"]')).toBeAttached();
}

export async function setTheme(page: Page, theme: "light" | "dark") {
  await page.context().addCookies([{ name: "sensr_theme", value: theme, url: page.url() || "http://127.0.0.1" }]);
}

/** Waits until every island on the page has hydrated. */
export async function hydrated(page: Page) {
  await page.waitForFunction(() => {
    const n = document.querySelectorAll("leptos-island").length;
    return Number(document.documentElement.dataset.islands ?? 0) >= n;
  });
}

/** WCAG 2.x A/AA checks: labels, names, contrast, landmarks, ARIA. */
export async function expectAccessible(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const summary = results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(" ")).slice(0, 3).join(", ")})`);
  expect(summary, "accessibility violations").toEqual([]);
}
