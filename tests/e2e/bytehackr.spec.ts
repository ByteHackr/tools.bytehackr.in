import path from 'path';
import { test, expect } from '@playwright/test';

const fixtureFile = path.resolve(__dirname, '../fixtures/sample.txt');
const samplePeFile = path.resolve(__dirname, '../fixtures/sample-pe.bin');
const fixtureMd5 = '40867bb03727c95d593f7829af845a83';
const testJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlBsYXl3cmlnaHQiLCJpYXQiOjE1MTYyMzkwMjJ9.935FSTdGIKAmq_pe2TS92aqY3XQaJKtCdgloO40z11E';
const testJwtSecret = 'playwright-secret';

test.beforeEach(async ({ page }) => {
  await page.route('https://cloudflare-dns.com/dns-query*', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/dns-json',
      body: JSON.stringify({
        Answer: [
          { name: 'example.com', type: 1, TTL: 300, data: '93.184.216.34' }
        ]
      })
    });
  });
  await page.goto('/');
});

test('Crypto AES workflow encrypts and decrypts deterministically', async ({ page }) => {
  await page.click('a[data-section="crypto"]');
  await page.fill('#aes-input', 'attack at dawn');
  await page.fill('#aes-password', 'pentester');
  await page.selectOption('#aes-mode', 'AES-GCM');
  await page.fill('#aes-iv', '000102030405060708090a0b');
  await page.click('#aes-encrypt-btn');
  await expect(page.locator('#aes-output')).toHaveValue('Hk8SlkVmJ60EXcM6ItfkM7UA/NSe7vQ7F/UcHxpX');
  const cipher = await page.locator('#aes-output').inputValue();
  await page.fill('#aes-input', cipher);
  await page.click('#aes-decrypt-btn');
  await expect(page.locator('#aes-output')).toHaveValue('attack at dawn');
});

test('Network HTTP builder and DNS resolver respond', async ({ page }) => {
  await page.click('a[data-section="network"]');
  const base = page.url();
  await page.fill('#http-url', `${base}README.md`);
  await page.click('#http-send-btn');
  await expect(page.locator('#http-status')).toContainText('200');
  await expect(page.locator('#http-response-body')).toHaveValue(/ByteHackr Tools/);

  await page.fill('#dns-host', 'example.com');
  await page.click('#dns-resolve-btn');
  await expect(page.locator('#dns-results')).toContainText('93.184.216.34');
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

test('Binary lab parses PE headers and strings', async ({ page }) => {
  await page.click('a[data-section="binary"]');
  await page.setInputFiles('#binary-file-input', samplePeFile);
  await expect(page.locator('#binary-type')).toContainText('PE32+');
  await expect(page.locator('#binary-sections-table')).toContainText('.text');
  await expect(page.locator('#binary-strings-list')).toContainText('ByteHackr');
});
