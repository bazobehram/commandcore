// Run only inside the isolated Steel PoC container.
// docker cp experiments/browser/visual-smoke.cjs commandcore-browser-poc:/tmp/visual-smoke.cjs
// docker exec commandcore-browser-poc node /tmp/visual-smoke.cjs
const puppeteer = require('/app/node_modules/puppeteer-core');

async function main() {
  const browser = await puppeteer.connect({
    browserURL: 'http://127.0.0.1:9222',
    defaultViewport: null,
  });
  try {
    const page = await browser.newPage();
    try {
      await page.setViewport({ width: 900, height: 600 });
      // Offline fixture. No website account or third-party domain involved.
      await page.setContent(
        '<html><body style="background:#101820;color:white;padding:50px">' +
        '<h1>CommandCore Browser PoC</h1>' +
        '<button id="test" style="font-size:24px;padding:30px" ' +
        'onclick="document.querySelector(\'#result\').textContent=\'CLICK ACCEPTED\'">' +
        'Click to verify</button><div id="result">WAITING</div></body></html>'
      );
      const button = await page.$('#test');
      if (!button) throw new Error('fixture button not found');
      const rect = await button.boundingBox();
      if (!rect) throw new Error('fixture button not visible');
      const x = rect.x + rect.width / 2;
      const y = rect.y + rect.height / 2;
      await page.mouse.move(x, y, { steps: 12 });
      await page.mouse.click(x, y);
      const value = await page.$eval('#result', (el) => el.textContent);
      await page.screenshot({ path: '/tmp/commandcore-browser-smoke.png' });
      console.log(JSON.stringify({
        result: value,
        screenshot: '/tmp/commandcore-browser-smoke.png',
        click_x: Math.round(x),
        click_y: Math.round(y),
      }));
      if (value !== 'CLICK ACCEPTED') throw new Error('coordinate click did not work');
    } finally {
      await page.close();
    }
  } finally {
    await browser.disconnect();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
