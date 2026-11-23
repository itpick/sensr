import { expect, test, type Locator, type Page } from "@playwright/test";
import { expectAccessible, hydrated, login, setTheme, shots } from "./helpers";

// The dashboard traffic charts: rate and time axes, a crosshair tooltip on hover, touch and
// the arrow keys, kept inside the card.

const rate = /[\d.]+ [kMG]?bit\/s/;

/** Scrolls `el` to the middle of the viewport, clear of the sticky top bar. */
async function centre(el: Locator) {
  await el.evaluate((e) => e.scrollIntoView({ block: "center" }));
}

async function graph(page: Page): Promise<Locator> {
  await login(page);
  await page.goto("/ui/core/dashboard");
  await hydrated(page);
  return page.locator("section", { has: page.getByRole("heading", { name: "Traffic graph" }) });
}

test("traffic graph: axes with units and round values", async ({ page }) => {
  const card = await graph(page);
  const chart = card.locator(".tchart");
  await expect(chart.locator(".tc-unit")).toHaveText(/^[kMG]?bit\/s$/);
  const ys = await chart.locator(".tc-y span").allTextContents();
  expect(ys.length).toBeGreaterThanOrEqual(4);
  expect(ys[0]).toBe("0");
  // Equal steps.
  const v = ys.map(Number);
  for (let i = 2; i < v.length; i++) expect(v[i] - v[i - 1]).toBeCloseTo(v[1] - v[0], 5);
  const xs = await chart.locator(".tc-x span").allTextContents();
  expect(xs.length).toBeGreaterThanOrEqual(3);
  for (const x of xs) expect(x).toMatch(/^\d\d:\d\d(:\d\d)?$/);
  // Interface charts get the same axes.
  const ifaces = page.locator("section", { has: page.getByRole("heading", { name: "Traffic", exact: true }) });
  await expect(ifaces.locator(".tchart").first().locator(".tc-y span").first()).toHaveText("0");
});

test("traffic graph: hover shows the time and both rates, inside the card", async ({ page }) => {
  const card = await graph(page);
  const plot = card.getByRole("slider", { name: "Traffic, all interfaces, last ten minutes" });
  await centre(plot);
  const box = (await plot.boundingBox())!;
  const tip = card.locator(".tc-tip");
  await expect(tip).toHaveCount(0);

  for (const fx of [0.5, 0.02, 0.98]) {
    await page.mouse.move(box.x + box.width * fx, box.y + box.height / 2);
    await expect(tip).toBeVisible();
    await expect(tip.locator("time")).toHaveText(/^\d\d:\d\d:\d\d$/);
    await expect(tip).toContainText(new RegExp(`In ${rate.source}`));
    await expect(tip).toContainText(new RegExp(`Out ${rate.source}`));
    await expect(card.locator(".tc-cross")).toBeVisible();
    // Never past the card's edges.
    const t = (await tip.boundingBox())!;
    const c = (await card.boundingBox())!;
    expect(t.x).toBeGreaterThanOrEqual(c.x);
    expect(t.x + t.width).toBeLessThanOrEqual(c.x + c.width);
  }
  if (process.env.SENSR_UI_SHOTS) {
    await card.screenshot({ path: `${shots}/traffic-chart-hover.png` });
  }

  // Left half and right half pick different samples.
  await page.mouse.move(box.x + box.width * 0.1, box.y + box.height / 2);
  const early = await tip.locator("time").textContent();
  await page.mouse.move(box.x + box.width * 0.9, box.y + box.height / 2);
  await expect(tip.locator("time")).not.toHaveText(early!);

  await page.mouse.move(box.x + box.width / 2, box.y - 40);
  await expect(tip).toHaveCount(0);

  // The interface charts hover the same way.
  const ifaces = page.locator("section", { has: page.getByRole("heading", { name: "Traffic", exact: true }) });
  const first = ifaces.locator(".tc-plot").first();
  await centre(first);
  const b = (await first.boundingBox())!;
  await page.mouse.move(b.x + b.width * 0.3, b.y + b.height / 2);
  const small = ifaces.locator(".tc-tip");
  await expect(small).toContainText(new RegExp(`In ${rate.source}`));
  // Mid-way in a small chart the tooltip still stays inside the plot.
  for (const fx of [0.45, 0.5, 0.55, 0.98]) {
    await page.mouse.move(b.x + b.width * fx, b.y + b.height / 2);
    await expect(small).toBeVisible();
    const t = (await small.boundingBox())!;
    expect(t.x).toBeGreaterThanOrEqual(b.x - 0.5);
    expect(t.x + t.width).toBeLessThanOrEqual(b.x + b.width + 0.5);
  }
  if (process.env.SENSR_UI_SHOTS) {
    await ifaces.screenshot({ path: `${shots}/traffic-interfaces-hover.png` });
  }
});

test("traffic graph: keyboard moves the crosshair", async ({ page }) => {
  const card = await graph(page);
  const plot = card.getByRole("slider", { name: "Traffic, all interfaces, last ten minutes" });
  await plot.focus();
  const tip = card.locator(".tc-tip");
  const max = await plot.getAttribute("aria-valuemax");
  // The latest sample until an arrow key moves the crosshair.
  await expect(plot).toHaveAttribute("aria-valuenow", max!);
  await page.keyboard.press("End");
  await expect(tip).toBeVisible();
  await expect(plot).toHaveAttribute("aria-valuetext", new RegExp(`^\\d\\d:\\d\\d:\\d\\d: In ${rate.source}, Out ${rate.source}$`));
  const latest = await tip.locator("time").textContent();
  await page.keyboard.press("ArrowLeft");
  await expect(plot).toHaveAttribute("aria-valuenow", String(Number(max) - 1));
  await expect(tip.locator("time")).not.toHaveText(latest!);
  await page.keyboard.press("Home");
  await expect(plot).toHaveAttribute("aria-valuenow", "0");
  await page.keyboard.press("End");
  await expect(plot).toHaveAttribute("aria-valuenow", max!);
  await page.keyboard.press("Escape");
  await expect(tip).toHaveCount(0);
});

test("traffic graph: tap on a phone shows the tooltip inside the card", async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });
  const page = await ctx.newPage();
  const card = await graph(page);
  const plot = card.getByRole("slider", { name: "Traffic, all interfaces, last ten minutes" });
  await centre(plot);
  const box = (await plot.boundingBox())!;
  await page.touchscreen.tap(box.x + box.width - 3, box.y + box.height / 2);
  const tip = card.locator(".tc-tip");
  await expect(tip).toBeVisible();
  await expect(tip).toContainText(new RegExp(`In ${rate.source}`));
  const t = (await tip.boundingBox())!;
  const c = (await card.boundingBox())!;
  expect(t.x + t.width).toBeLessThanOrEqual(c.x + c.width);
  if (process.env.SENSR_UI_SHOTS) await card.screenshot({ path: `${shots}/traffic-chart-phone.png` });
  // A tap elsewhere hides it.
  const h = (await card.getByRole("heading", { name: "Traffic graph" }).boundingBox())!;
  await page.touchscreen.tap(h.x + 10, h.y + h.height / 2);
  await expect(tip).toHaveCount(0);
  // No sideways scroll at phone width.
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await ctx.close();
});

for (const theme of ["light", "dark"] as const) {
  test(`traffic graph with tooltip passes axe (${theme})`, async ({ page }) => {
    await page.goto("/login");
    await setTheme(page, theme);
    const card = await graph(page);
    const plot = card.getByRole("slider", { name: "Traffic, all interfaces, last ten minutes" });
    await plot.focus();
    await page.keyboard.press("ArrowLeft");
    await expect(card.locator(".tc-tip")).toBeVisible();
    if (process.env.SENSR_UI_SHOTS) {
      await card.screenshot({ path: `${shots}/traffic-chart-${theme}.png` });
    }
    await expectAccessible(page);
  });
}
