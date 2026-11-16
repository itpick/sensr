import { test } from "@playwright/test";
import { writeFileSync, mkdirSync } from "node:fs";
import { login, shots } from "./helpers";

// Cold-cache load timings in headless Chromium: first contentful paint, DOMContentLoaded,
// and time until every island has hydrated (interactive). Median of 5 runs per page.
const pages = [
  ["login", "/login"],
  ["dashboard", "/"],
  ["firewall-aliases", "/ui/firewall/alias"],
  ["firewall-rules-lan", "/ui/firewall/filter/lan"],
  ["system-general", "/ui/system/general"],
] as const;

const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];

test("load timings", async ({ browser }) => {
  const results: Record<string, Record<string, number>> = {};
  const auth = await browser.newContext();
  const authPage = await auth.newPage();
  await login(authPage);
  const cookies = await auth.cookies();
  await auth.close();
  for (const [name, url] of pages) {
    const runs: { fcp: number; dcl: number; tti: number; bytes: number }[] = [];
    for (let i = 0; i < 5; i++) {
      const ctx = await browser.newContext();
      if (name !== "login") await ctx.addCookies(cookies);
      const page = await ctx.newPage();
      await page.goto(url);
      const m = await page.evaluate(async () => {
        const deadline = performance.now() + 10_000;
        while (performance.now() < deadline) {
          const n = document.querySelectorAll("leptos-island").length;
          if (Number(document.documentElement.dataset.islands ?? 0) >= n) break;
          await new Promise((r) => setTimeout(r, 5));
        }
        const tti = performance.now();
        // FCP may land after an island-free page is already "interactive".
        await new Promise<void>((resolve) => {
          if (performance.getEntriesByName("first-contentful-paint").length) return resolve();
          new PerformanceObserver(() => resolve()).observe({ type: "paint", buffered: true });
          setTimeout(resolve, 3000);
        });
        const nav = performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming;
        const fcp = performance.getEntriesByName("first-contentful-paint")[0]?.startTime ?? NaN;
        const bytes = (performance.getEntriesByType("resource") as PerformanceResourceTiming[])
          .reduce((a, r) => a + r.transferSize, nav.transferSize);
        return { fcp, dcl: nav.domContentLoadedEventEnd, tti, bytes };
      });
      runs.push(m);
      await ctx.close();
    }
    results[name] = {
      fcp_ms: Math.round(median(runs.map((r) => r.fcp))),
      dcl_ms: Math.round(median(runs.map((r) => r.dcl))),
      interactive_ms: Math.round(median(runs.map((r) => r.tti))),
      transfer_kb: Math.round(median(runs.map((r) => r.bytes)) / 1024),
    };
  }
  console.table(results);
  mkdirSync(shots, { recursive: true });
  writeFileSync(`${shots}/perf.json`, JSON.stringify(results, null, 2));
});
