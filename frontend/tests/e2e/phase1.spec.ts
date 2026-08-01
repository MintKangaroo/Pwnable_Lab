import { expect, test } from '@playwright/test';

test('upload an ELF, complete analysis, and preserve tab state in the URL', async ({
  page,
}) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Analysis workspace' })).toBeVisible();

  const artifact = await page.request.get('/api/v1/challenges/ret2win/artifact');
  expect(artifact.ok()).toBeTruthy();
  await page
    .locator('input[type="file"]')
    .first()
    .setInputFiles({
      name: 'phase1-ret2win.elf',
      mimeType: 'application/octet-stream',
      buffer: await artifact.body(),
    });

  await expect(page).toHaveURL(/\/binaries\/[0-9a-f]{64}\/overview$/);
  await expect(page.getByRole('heading', { name: 'phase1-ret2win.elf' })).toBeVisible();
  await expect(page.getByLabel('Analysis status: Verified').first()).toBeVisible();
  await expect(page.getByText('MITIGATION MAP')).toBeVisible();
  await expect(page.getByText('EXECUTABLE STACK', { exact: true })).toBeVisible();
  await expect(page.getByText('LINKING MODE', { exact: true })).toBeVisible();

  await page.getByRole('tab', { name: 'Disassembly' }).click();
  await expect(page).toHaveURL(/\/disassembly$/);
  await expect(page.getByText('LINEAR DISASSEMBLY')).toBeVisible();

  await page.reload();
  await expect(page).toHaveURL(/\/disassembly$/);
  await expect(page.getByText('LINEAR DISASSEMBLY')).toBeVisible();
});
