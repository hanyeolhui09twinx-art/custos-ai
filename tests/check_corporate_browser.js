/* Browser-level smoke and interaction checks for the Custos corporate site.
 * Requires Playwright and a local static server at http://127.0.0.1:4173.
 */
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");

const BASE = process.env.CUSTOS_BASE_URL || "http://127.0.0.1:4173";
const OUT = path.resolve(process.env.CUSTOS_BROWSER_ARTIFACTS || "artifacts/custos-browser");
const PAGES = [
  "/",
  "/mission.html",
  "/platform.html",
  "/technology.html",
  "/research.html",
  "/security.html",
  "/company.html",
  "/partnerships.html",
  "/media.html",
  "/contact.html",
  "/privacy.html",
  "/terms.html",
  "/updates.html",
  "/developers.html"
];

const RESPONSIVE_WIDTHS = [320, 360, 390, 430, 768, 900, 960, 961, 1024];

async function revealAll(page) {
  const totalHeight = await page.evaluate(() => document.body.scrollHeight);
  const viewportHeight = await page.evaluate(() => window.innerHeight);
  for (let y = 0; y < totalHeight; y += Math.max(320, Math.floor(viewportHeight * 0.75))) {
    await page.evaluate((scrollY) => window.scrollTo(0, scrollY), y);
    await page.waitForTimeout(90);
  }
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(120);
}

function recordError(bucket, pageName) {
  return (message) => bucket.push(pageName + ": " + message);
}

async function checkResponsiveLayout(page, route, failures) {
  for (const width of RESPONSIVE_WIDTHS) {
    await page.setViewportSize({ width, height: 900 });
    await page.waitForTimeout(25);
    const metrics = await page.evaluate(() => {
      const viewport = document.documentElement.clientWidth;
      const overflowCandidates = [...document.querySelectorAll("body *")]
        .map((element) => {
          const rect = element.getBoundingClientRect();
          const style = getComputedStyle(element);
          return {
            tag: element.tagName.toLowerCase(),
            id: element.id,
            className: typeof element.className === "string" ? element.className.slice(0, 70) : "",
            left: Math.round(rect.left),
            right: Math.round(rect.right),
            width: Math.round(rect.width),
            scrollWidth: element.scrollWidth,
            clientWidth: element.clientWidth,
            position: style.position,
            overflowX: style.overflowX
          };
        })
        .filter((item) => item.width > 0 && (item.right > viewport + 1 || item.left < -1))
        .sort((a, b) => b.right - a.right)
        .slice(0, 8);
      return {
        viewport,
        document: document.documentElement.scrollWidth,
        body: document.body.scrollWidth,
        desktopNavVisible: getComputedStyle(document.querySelector(".nav")).display !== "none",
        menuToggleVisible: getComputedStyle(document.querySelector("[data-menu-toggle]")).display !== "none",
        overflowCandidates
      };
    });

    if (metrics.document > metrics.viewport + 1 || metrics.body > metrics.viewport + 1) {
      failures.push(
        route + " at " + width + "px has horizontal overflow: " + JSON.stringify(metrics)
      );
    }

    const expectsMobileNavigation = width <= 960;
    if (metrics.menuToggleVisible !== expectsMobileNavigation) {
      failures.push(route + " at " + width + "px has an incorrect menu-toggle breakpoint");
    }
    if (metrics.desktopNavVisible === expectsMobileNavigation) {
      failures.push(route + " at " + width + "px has an incorrect desktop navigation state");
    }
  }
  await page.setViewportSize({ width: 1440, height: 1000 });
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const failures = [];
  const summary = [];
  try {
    const context = await browser.newContext({
      viewport: { width: 1440, height: 1000 },
      locale: "ko-KR",
      reducedMotion: "no-preference"
    });

    for (const route of PAGES) {
      const page = await context.newPage();
      const pageErrors = [];
      page.on("pageerror", recordError(pageErrors, route));
      page.on("console", (message) => {
        if (message.type() === "error") pageErrors.push(route + ": console: " + message.text());
      });
      const response = await page.goto(BASE + route, { waitUntil: "networkidle" });
      assert.ok(response && response.ok(), route + " returned a non-success response");
      await page.locator("main#main-content").waitFor({ state: "visible" });
      assert.equal(await page.locator("h1").count(), 1, route + " must have exactly one H1");
      assert.ok((await page.title()).includes("Custos"), route + " title is not branded");
      const mainHeading = (await page.locator("h1").innerText()).trim();
      assert.ok(mainHeading.length > 5, route + " primary heading is empty");
      assert.ok(await page.locator('a.header-cta[href="./local-console.html"]').count(), route + " lost the Local Control Room entry point");

      const currentNav = page.locator('[data-nav][aria-current="page"]');
      const pageKey = route === "/" ? "" : route.slice(1).replace(".html", "");
      const hasTopLevelNavItem = pageKey && (await page.locator('[data-nav="' + pageKey + '"]').count()) > 0;
      assert.equal(
        await currentNav.count(),
        hasTopLevelNavItem ? 1 : 0,
        route + " has an unexpected active navigation state"
      );

      if (route === "/") {
        await revealAll(page);
        await page.screenshot({ path: path.join(OUT, "home-desktop.png"), fullPage: true });
      } else if (route === "/mission.html") {
        await revealAll(page);
        await page.screenshot({ path: path.join(OUT, "mission-desktop.png"), fullPage: true });
      } else if (route === "/media.html") {
        const preview = page.locator(".film-preview");
        assert.equal(await preview.count(), 1, "Media Room must contain its motion preview");
        const sceneCount = await preview.locator(".film-scene").count();
        assert.equal(sceneCount, 6, "Brand motion preview must contain six scenes");
        const animation = await preview.locator(".film-scene.s1").evaluate((el) => getComputedStyle(el).animationName);
        assert.equal(animation, "film1", "Brand preview first scene animation is not running");
        await revealAll(page);
        await page.screenshot({ path: path.join(OUT, "media-desktop.png"), fullPage: true });
      }

      const internalLinks = await page.locator('a[href^="./"]').evaluateAll((links) =>
        links.map((a) => a.getAttribute("href")).filter((href) => href && !href.startsWith("./#"))
      );
      for (const href of internalLinks) {
        const target = new URL(href, BASE + route);
        const checked = await context.request.get(target.toString());
        if (!checked.ok()) failures.push(route + " internal link " + href + " returned " + checked.status());
      }

      await checkResponsiveLayout(page, route, failures);

      if (pageErrors.length) failures.push(...pageErrors);
      summary.push({ route, heading: mainHeading.replace(/\s+/g, " ").slice(0, 100), status: response.status() });
      await page.close();
    }

    // The language toggle must change both the document language and the mission message.
    const languagePage = await context.newPage();
    await languagePage.goto(BASE + "/mission.html", { waitUntil: "networkidle" });
    await languagePage.locator('[data-lang-button="en"]').click();
    assert.equal(await languagePage.locator("html").getAttribute("lang"), "en");
    assert.match(await languagePage.locator("h1").innerText(), /Human agency is the objective/i);
    assert.equal(await languagePage.locator('[data-lang-button="en"]').getAttribute("aria-pressed"), "true");
    await languagePage.locator('[data-lang-button="ko"]').click();
    assert.equal(await languagePage.locator("html").getAttribute("lang"), "ko");
    assert.match(await languagePage.locator("h1").innerText(), /인류의 주도권을 보존합니다/);
    await languagePage.close();

    // Check the mobile menu, Escape behavior, focus restoration, and narrow viewport overflow.
    const mobileContext = await browser.newContext({
      viewport: { width: 390, height: 844 },
      isMobile: true,
      hasTouch: true,
      locale: "ko-KR"
    });
    const mobile = await mobileContext.newPage();
    const mobileErrors = [];
    mobile.on("pageerror", recordError(mobileErrors, "mobile mission"));
    await mobile.goto(BASE + "/mission.html", { waitUntil: "networkidle" });
    const toggle = mobile.locator("[data-menu-toggle]");
    const menu = mobile.locator("[data-mobile-nav]");

    // Tablet-width navigation must use the compact menu before the desktop links become crowded.
    await mobile.setViewportSize({ width: 768, height: 900 });
    assert.equal(await toggle.isVisible(), true, "Tablet layout must show the mobile menu toggle");
    assert.equal(await mobile.locator(".nav").isVisible(), false, "Tablet layout must hide desktop navigation");
    await toggle.click();
    await menu.waitFor({ state: "visible" });
    await mobile.keyboard.press("Escape");
    assert.equal(await toggle.getAttribute("aria-expanded"), "false");
    assert.equal(await toggle.evaluate((el) => document.activeElement === el), true, "Tablet Escape must restore focus to the menu toggle");

    // Verify the narrow mobile menu and keyboard behavior as well.
    await mobile.setViewportSize({ width: 390, height: 844 });
    assert.equal(await toggle.getAttribute("aria-expanded"), "false");
    await toggle.click();
    assert.equal(await toggle.getAttribute("aria-expanded"), "true");
    await menu.waitFor({ state: "visible" });
    await mobile.keyboard.press("Escape");
    assert.equal(await toggle.getAttribute("aria-expanded"), "false");
    assert.equal(await toggle.evaluate((el) => document.activeElement === el), true, "Escape must restore focus to the menu toggle");
    const dimensions = await mobile.evaluate(() => ({ viewport: document.documentElement.clientWidth, content: document.documentElement.scrollWidth }));
    assert.ok(dimensions.content <= dimensions.viewport + 1, "Mobile page has horizontal overflow: " + JSON.stringify(dimensions));
    await revealAll(mobile);
    await mobile.screenshot({ path: path.join(OUT, "mission-mobile.png"), fullPage: true });
    if (mobileErrors.length) failures.push(...mobileErrors);
    await mobileContext.close();

    // Reduced-motion users should receive a static first-frame fallback.
    const reduced = await context.newPage();
    await reduced.emulateMedia({ reducedMotion: "reduce" });
    await reduced.goto(BASE + "/media.html", { waitUntil: "networkidle" });
    const reducedStyle = await reduced.locator(".film-scene.s1").evaluate((el) => {
      const style = getComputedStyle(el);
      return { name: style.animationName, duration: style.animationDuration };
    });
    const durationMs = reducedStyle.duration.endsWith("ms")
      ? Number.parseFloat(reducedStyle.duration)
      : Number.parseFloat(reducedStyle.duration) * 1000;
    assert.ok(
      Number.isFinite(durationMs) && durationMs <= 0.1,
      "Media preview must reduce motion to <= 0.1ms; computed style: " + JSON.stringify(reducedStyle)
    );
    await reduced.close();

    textSummary(summary, failures);
    if (failures.length) throw new Error(failures.join("\n"));
  } finally {
    await browser.close();
  }
}

function textSummary(summary, failures) {
  console.log("Custos corporate browser routes checked: " + summary.length);
  for (const item of summary) console.log("PASS " + item.status + " " + item.route + " — " + item.heading);
  console.log("Browser failures: " + failures.length);
  if (failures.length) for (const failure of failures) console.error("FAIL " + failure);
}

main().catch((error) => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
