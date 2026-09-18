import { expect, test } from '@playwright/test';

function captureRuntimeFailures(page) {
  const failures = [];
  page.on('console', message => {
    if (message.type() === 'error') failures.push(`console: ${message.text()}`);
  });
  page.on('pageerror', error => failures.push(`pageerror: ${error.message}`));
  page.on('requestfailed', request => {
    if (['script', 'stylesheet'].includes(request.resourceType())) {
      failures.push(`requestfailed: ${request.method()} ${request.url()} ${request.failure()?.errorText ?? ''}`.trim());
    }
  });
  page.on('response', response => {
    if (['script', 'stylesheet'].includes(response.request().resourceType()) && response.status() >= 400) {
      failures.push(`response: ${response.status()} ${response.url()}`);
    }
  });
  return failures;
}

async function exerciseInitialize(page, { reducedMotion, viewportWidth }) {
  const failures = captureRuntimeFailures(page);
  await page.goto('/app/', { waitUntil: 'load' });

  expect(page.viewportSize()?.width).toBe(viewportWidth);
  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(reducedMotion);
  expect(await page.evaluate(() => matchMedia('(max-width: 430px)').matches)).toBe(viewportWidth <= 430);

  const initialize = page.getByRole('button', { name: 'INITIALIZE', exact: true });
  await expect(initialize).toBeVisible();
  await expect(initialize).toBeEnabled();
  await initialize.click();
  await expect(initialize).toBeDisabled();

  const snapshot = await page.evaluate(() => ({
    bootLog: document.querySelector('#boot-log')?.textContent ?? '',
    reducedMotion: document.body.classList.contains('reduced-terminal-motion'),
    skipDisabled: document.querySelector('#boot-skip')?.disabled,
  }));

  expect({ ...snapshot, runtimeFailures: [...failures] }).toEqual({
    bootLog: expect.stringContaining('power0: CRT terminal bus online'),
    reducedMotion,
    runtimeFailures: [],
    skipDisabled: false,
  });
}

test('Initialize accepts a desktop click and starts boot in normal motion', async ({ page }) => {
  await exerciseInitialize(page, { reducedMotion: false, viewportWidth: 1440 });
});

test('Initialize accepts a mobile click and starts boot in reduced motion', async ({ page }) => {
  await exerciseInitialize(page, { reducedMotion: true, viewportWidth: 390 });
});
