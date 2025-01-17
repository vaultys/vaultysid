import { chromium, Browser, Page } from "@playwright/test";
import { expect } from "chai";
import path from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";
import express from "express";
import http from "http";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

describe("Browser Tests", () => {
  let browser: Browser;
  let page: Page;
  let server: http.Server;
  const PORT = 8740;

  before(async () => {
    // Set up Express app
    const app = express();
    app.use(express.static(path.join(__dirname, "..")));

    // Start server
    server = http.createServer(app);
    await new Promise<void>((resolve) => {
      server.listen(PORT, () => {
        console.log(`Test server running at http://localhost:${PORT}`);
        resolve();
      });
    });

    // Launch browser
    browser = await chromium.launch({
      headless: true,
    });

    page = await browser.newPage();

    // Add console logging
    page.on("console", (msg) => {
      const args = msg.args();
      Promise.all(args.map((arg) => arg.jsonValue())).then((values) => {
        if (values.length === 1) {
          console.log(values[0]);
        } else {
          console.log(...values);
        }
      });
    });

    page.on("pageerror", (error) => {
      //console.error("Page error:", error);
    });
  });

  after(async () => {
    await browser.close();
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  it("should run tests in browser", async () => {
    const testUrl = `http://localhost:${PORT}/test/test.html`;

    try {
      await page.goto(testUrl);

      // Wait for tests to complete
      const results = await page.evaluate(() => {
        return new Promise((resolve) => {
          const checkInterval = setInterval(() => {
            if (window.mochaResults) {
              clearInterval(checkInterval);
              resolve(window.mochaResults);
            }
          }, 100);
        });
      });

      //console.log("Test Results:", JSON.stringify(results, null, 2));
      expect(results.failures).to.equal(0);
    } catch (error) {
      console.error("Test execution failed:", error);
      throw error;
    }
  }).timeout(100000);
});
