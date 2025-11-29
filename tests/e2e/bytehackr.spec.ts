import path from 'path';
import { test, expect } from '@playwright/test';

const fixtureFile = path.resolve(__dirname, '../fixtures/sample.txt');
const fixtureMd5 = '40867bb03727c95d593f7829af845a83';
const testJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlBsYXl3cmlnaHQiLCJpYXQiOjE1MTYyMzkwMjJ9.935FSTdGIKAmq_pe2TS92aqY3XQaJKtCdgloO40z11E';
const testJwtSecret = 'playwright-secret';

test.beforeEach(async ({ page }) => {
  await page.goto('/');
});

test.describe('Hashing & Encoding Toolkit', () => {
  test('hashes text input and file uploads', async ({ page }) => {
    await page.click('a[data-section="hash"]');
    await page.fill('#hash-input', 'hello');
    await page.click('#hash .btn:has-text("MD5")');
    await expect(page.locator('#hash-output')).toHaveValue('5d41402abc4b2a76b9719d911017c592');

    await page.setInputFiles('#hash-file-input', fixtureFile);
    await expect(page.locator('#file-md5')).toHaveText(fixtureMd5, { timeout: 10_000 });
    await expect(page.locator('#file-sha1')).not.toHaveText('Computing...', { timeout: 10_000 });
  });
});

test('JWT inspector decodes and verifies tokens', async ({ page }) => {
  await page.click('a[data-section="jwt"]');
  await page.fill('#jwt-input', testJwt);
  await page.click('#jwt .btn.btn-primary:has-text("Decode Token")');
  await expect(page.locator('#jwt-header')).toContainText('"alg": "HS256"');
  await page.fill('#jwt-secret', testJwtSecret);
  await page.click('#jwt .btn.btn-secondary:has-text("Verify")');
  await expect(page.locator('#jwt-verify-result')).toContainText('verified');
});

test('Regex tester finds matches and shows replace preview', async ({ page }) => {
  await page.click('a[data-section="regex"]');
  await page.fill('#regex-pattern', '\\d+');
  await page.fill('#regex-test-string', 'Invoice 42 due 2025');
  await expect(page.locator('#match-count')).toHaveText('2');
  await page.fill('#regex-replace', 'NUM');
  await expect(page.locator('#regex-replace-preview')).toContainText('NUM');
});

test('JSON/YAML converter converts JSON to YAML', async ({ page }) => {
  await page.click('a[data-section="json"]');
  const sampleJson = '{"name":"Alice","items":[1,2]}';
  await page.fill('#json-input', sampleJson);
  await page.click('#json .btn.btn-primary:has-text("Convert")');
  await expect(page.locator('#json-output')).toHaveValue(/name: Alice/);
});

test('Hex viewer renders pasted text as hex bytes', async ({ page }) => {
  await page.click('a[data-section="hex"]');
  await page.fill('#hex-input', 'Hi');
  await page.click('#hex-paste-tab .btn.btn-primary:has-text("Analyze")');
  await expect(page.locator('#hex-results')).toBeVisible();
  await expect(page.locator('#hex-view .hex-byte').first()).toHaveText('48');
});

test('Checksum tool calculates file hashes and verifies expected values', async ({ page }) => {
  await page.click('a[data-section="checksum"]');
  await page.setInputFiles('#checksum-file-input', fixtureFile);
  await expect(page.locator('#checksum-md5')).toHaveText(fixtureMd5, { timeout: 10_000 });
  await page.fill('#expected-checksum', fixtureMd5);
  await expect(page.locator('#verify-md5')).toContainText('MATCH');
});
