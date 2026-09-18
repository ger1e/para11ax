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

  const skip = page.getByRole('button', { name: 'SKIP', exact: true });
  await expect(skip).toBeVisible();
  await expect(skip).toBeEnabled();
  await skip.click();

  const snapshot = await page.evaluate(() => {
    const region = document.querySelector('[role="region"][aria-label="PARA11AX interactive analyst shell"]');
    return {
      bootStatus: document.querySelector('#boot-status')?.textContent ?? '',
      reducedMotion: document.body.classList.contains('reduced-terminal-motion'),
      regionExists: Boolean(region),
      shellCount: document.querySelectorAll('.unix-shell').length,
      shellState: document.querySelector('.shell-session-state')?.textContent ?? '',
      workspaceHidden: document.querySelector('#workspace')?.hidden,
    };
  });

  expect({ ...snapshot, runtimeFailures: [...failures] }).toEqual({
    bootStatus: 'pxsvcd: Gateway Terminal active',
    reducedMotion,
    regionExists: true,
    runtimeFailures: [],
    shellCount: 1,
    shellState: expect.stringContaining('AUTH:DOWN'),
    workspaceHidden: false,
  });
}

test('Initialize reaches the Gateway Terminal in normal motion', async ({ page }) => {
  await exerciseInitialize(page, { reducedMotion: false, viewportWidth: 1440 });
});

test('Initialize reaches the Gateway Terminal in reduced motion', async ({ page }) => {
  await exerciseInitialize(page, { reducedMotion: true, viewportWidth: 390 });
});
