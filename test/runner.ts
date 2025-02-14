import { chromium, Browser, Page, firefox, webkit } from "@playwright/test";
import { expect } from "chai";
import path from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";
import express from "express";
import http from "http";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

describe("Browser Tests on Chromium", () => {
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
    await page.goto(testUrl);

    // Wait for tests to complete
    const results: any = await page.evaluate(() => {
      return new Promise((resolve) => {
        const checkInterval = setInterval(() => {
          if (window.mochaResults) {
            clearInterval(checkInterval);
            resolve(window.mochaResults);
          }
        }, 100);
      });
    });
    expect(results.failures).to.equal(0);
  }).timeout(100000);
});

describe("Browser Tests on Firefox", () => {
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
    browser = await firefox.launch({
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
    await page.goto(testUrl);

    // Wait for tests to complete
    const results: any = await page.evaluate(() => {
      return new Promise((resolve) => {
        const checkInterval = setInterval(() => {
          if (window.mochaResults) {
            clearInterval(checkInterval);
            resolve(window.mochaResults);
          }
        }, 100);
      });
    });
    expect(results.failures).to.equal(0);
  }).timeout(100000);
});

describe("Browser Tests on Webkit", () => {
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
    browser = await webkit.launch({
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
    await page.goto(testUrl);

    // Wait for tests to complete
    const results: any = await page.evaluate(() => {
      return new Promise((resolve) => {
        const checkInterval = setInterval(() => {
          if (window.mochaResults) {
            clearInterval(checkInterval);
            resolve(window.mochaResults);
          }
        }, 100);
      });
    });
    expect(results.failures).to.equal(0);
  }).timeout(100000);
});