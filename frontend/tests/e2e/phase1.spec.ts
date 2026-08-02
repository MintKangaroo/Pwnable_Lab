import { expect, test } from '@playwright/test';

function samplePe(): Buffer {
  const data = Buffer.alloc(0x800);
  const optional = 0x98;
  const sectionTable = optional + 0xf0;
  data.write('MZ', 0, 'ascii');
  data.writeUInt32LE(0x80, 0x3c);
  data.write('PE\0\0', 0x80, 'binary');
  data.writeUInt16LE(0x8664, 0x84);
  data.writeUInt16LE(2, 0x86);
  data.writeUInt32LE(0x65000000, 0x88);
  data.writeUInt16LE(0xf0, 0x94);
  data.writeUInt16LE(0x22, 0x96);
  data.writeUInt16LE(0x20b, optional);
  data.writeUInt32LE(0x1000, optional + 16);
  data.writeBigUInt64LE(0x140000000n, optional + 24);
  data.writeUInt32LE(0x1000, optional + 32);
  data.writeUInt32LE(0x200, optional + 36);
  data.writeUInt32LE(0x3000, optional + 56);
  data.writeUInt32LE(0x200, optional + 60);
  data.writeUInt16LE(3, optional + 68);
  data.writeUInt16LE(0x4160, optional + 70);
  data.writeUInt32LE(16, optional + 108);
  data.writeUInt32LE(0x2000, optional + 120);
  data.writeUInt32LE(0x40, optional + 124);
  data.writeUInt32LE(0x2100, optional + 152);
  data.writeUInt32LE(12, optional + 156);
  data.write('.text\0\0\0', sectionTable, 'binary');
  data.writeUInt32LE(0x20, sectionTable + 8);
  data.writeUInt32LE(0x1000, sectionTable + 12);
  data.writeUInt32LE(0x200, sectionTable + 16);
  data.writeUInt32LE(0x200, sectionTable + 20);
  data.writeUInt32LE(0x60000020, sectionTable + 36);
  data.write('.rdata\0\0', sectionTable + 40, 'binary');
  data.writeUInt32LE(0x400, sectionTable + 48);
  data.writeUInt32LE(0x2000, sectionTable + 52);
  data.writeUInt32LE(0x400, sectionTable + 56);
  data.writeUInt32LE(0x400, sectionTable + 60);
  data.writeUInt32LE(0x40000040, sectionTable + 76);
  data.set([0x90, 0x90, 0xc3], 0x200);
  data.writeUInt32LE(0x2050, 0x400);
  data.writeUInt32LE(0x2080, 0x40c);
  data.writeUInt32LE(0x2070, 0x410);
  data.writeBigUInt64LE(0x2090n, 0x450);
  data.write('KERNEL32.dll\0', 0x480, 'binary');
  data.write('CreateProcessA\0', 0x492, 'binary');
  data.writeUInt32LE(0x1000, 0x500);
  data.writeUInt32LE(12, 0x504);
  data.writeUInt16LE(0xa010, 0x508);
  return data;
}

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
  await expect(page.getByLabel('Analysis status: Completed').first()).toBeVisible();
  await expect(page.getByText('MITIGATION MAP')).toBeVisible();
  await expect(page.getByText('EXECUTABLE STACK', { exact: true })).toBeVisible();
  await expect(page.getByText('LINKING MODE', { exact: true })).toBeVisible();

  await page.getByRole('tab', { name: 'Disassembly' }).click();
  await expect(page).toHaveURL(/\/disassembly$/);
  await expect(page.getByText('LINEAR DISASSEMBLY')).toBeVisible();

  await page.reload();
  await expect(page).toHaveURL(/\/disassembly$/);
  await expect(page.getByText('LINEAR DISASSEMBLY')).toBeVisible();

  await page.getByRole('tab', { name: 'Functions' }).click();
  await expect(page.getByText('FUNCTION INDEX')).toBeVisible();
  const mainRow = page.getByRole('row').filter({ hasText: 'main' }).first();
  await mainRow.getByRole('button', { name: 'main', exact: true }).click();
  await expect(page).toHaveURL(/\/functions\?address=0x[0-9a-f]+$/);
  await mainRow.getByRole('button', { name: 'Open CFG' }).click();
  await expect(page).toHaveURL(/\/cfg\?address=0x[0-9a-f]+$/);
  await expect(page.getByText('CONTROL-FLOW GRAPH')).toBeVisible();
  await expect(page.getByText('CFG INSPECTOR')).toBeVisible();
  if (process.env.PWNPILOT_CAPTURE_DOCS === '1') {
    await page.screenshot({
      path: '../docs/screenshots/13-function-cfg.png',
      fullPage: true,
    });
  }
});

test('upload PE and raw artifacts with format-specific workspace capabilities', async ({
  page,
}) => {
  await page.goto('/');
  const fileInput = page.locator('input[type="file"]').first();

  await fileInput.setInputFiles({
    name: 'authorized.exe',
    mimeType: 'application/octet-stream',
    buffer: samplePe(),
  });
  await expect(page.getByRole('heading', { name: 'authorized.exe' })).toBeVisible();
  await expect(page.getByText('DEP / NX COMPAT', { exact: true })).toBeVisible();
  await expect(page.getByText('CONTROL FLOW GUARD', { exact: true })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Functions' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'CFG' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'ROP Gadgets' })).toHaveCount(0);
  await expect(page.getByRole('tab', { name: 'GOT / PLT' })).toHaveCount(0);

  await page.goto('/');
  await page
    .locator('input[type="file"]')
    .first()
    .setInputFiles({
      name: 'shellcode.bin',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from([
        ...Array(16).fill(0x90),
        0x48,
        0x45,
        0x4c,
        0x4c,
        0x4f,
        0,
        0x48,
        0x31,
        0xc0,
        0xc3,
      ]),
    });
  await expect(page.getByRole('heading', { name: 'shellcode.bin' })).toBeVisible();
  await expect(page.getByText('LOADER MITIGATIONS', { exact: true })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Functions' })).toHaveCount(0);
  await expect(page.getByRole('tab', { name: 'CFG' })).toHaveCount(0);
  await page.getByRole('tab', { name: 'Disassembly' }).click();
  await expect(page.getByLabel('Raw binary base address')).toBeVisible();
  await expect(page.getByText('LINEAR DISASSEMBLY', { exact: true })).toBeVisible();
});
