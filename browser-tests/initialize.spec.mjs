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

  const body = page.locator('body');
  if (reducedMotion) await expect(body).toHaveClass(/reduced-terminal-motion/);
  else await expect(body).not.toHaveClass(/reduced-terminal-motion/);

  await expect(page.locator('#boot-log')).toContainText('pxsvc[provider-registry]: 39 sources registered');
  await expect.poll(async () => ({
    bootStatus: await page.locator('#boot-status').textContent(),
    runtimeFailures: [...failures],
    shellCount: await page.locator('.unix-shell').count(),
    workspaceHidden: await page.locator('#workspace').evaluate(node => node.hidden),
  })).toEqual({
    bootStatus: 'pxsvcd: Gateway Terminal active',
    runtimeFailures: [],
    shellCount: 1,
    workspaceHidden: false,
  });
  await expect(page.getByRole('region', { name: 'PARA11AX interactive analyst shell' })).toBeVisible();
  await expect(page.locator('.shell-session-state')).toContainText('AUTH:DOWN');
  expect(failures).toEqual([]);
}

test('Initialize reaches the Gateway Terminal in normal motion', async ({ page }) => {
  await exerciseInitialize(page, { reducedMotion: false, viewportWidth: 1440 });
});

test('Initialize reaches the Gateway Terminal in reduced motion', async ({ page }) => {
  await exerciseInitialize(page, { reducedMotion: true, viewportWidth: 390 });
});
