import { expect, test, type Page } from '@playwright/test';
import { login } from './auth';
import { expectResponsiveExampleLayout } from './layout';

const environment = {
  authBase: `http://127.0.0.1:${process.env.MINIO_AUTH_PORT ?? '8291'}`,
  mailpitBase: `http://127.0.0.1:${process.env.MINIO_MAILPIT_PORT ?? '8391'}`,
};
const password = 'Example!Passw0rd9';

async function userID(token: string): Promise<string> {
  const response = await fetch(`${environment.authBase}/v1/me`, { headers: { Authorization: `Bearer ${token}` } });
  expect(response.status).toBe(200);
  return (await response.json() as { id: string }).id;
}

async function openFolder(page: Page, token: string, owner: string, path: string): Promise<void> {
  await page.goto(`/?owner=${encodeURIComponent(owner)}&path=${encodeURIComponent(path)}`);
  await page.getByTestId('access-token').fill(token);
  await page.getByTestId('open-root').click();
}

test('seeded storage personas exercise folder navigation, files, and inherited access', async ({ page }) => {
  test.setTimeout(120_000);
  const [owner, reader, writer, taggedAdmin, stranger] = await Promise.all([
    login(environment, { login: 'storage-owner', email: 'storage-owner@example.test', password }),
    login(environment, { login: 'storage-reader', email: 'storage-reader@example.test', password }),
    login(environment, { login: 'storage-writer', email: 'storage-writer@example.test', password }),
    login(environment, { login: 'storage-admin', email: 'storage-admin@example.test', password }),
    login(environment, { login: 'storage-stranger', email: 'storage-stranger@example.test', password }),
  ]);
  const [ownerID, strangerID] = await Promise.all([userID(owner), userID(stranger)]);

  await page.goto('/');
  await expectResponsiveExampleLayout(page, ['registration-card', 'workspace-card'], ['register-login', 'access-token']);
  await expect(page.getByRole('heading', { name: 'MinIO storage workspace' })).toBeVisible();
  await expect(page.getByTestId('workspace-card')).toContainText('make -C examples token EXAMPLE=minio-storage PERSONA=owner');

  const browserCredentials = { login: 'storage-browser', email: 'storage-browser@example.test', password };
  await page.getByTestId('register-login').fill(browserCredentials.login);
  await page.getByTestId('register-email').fill(browserCredentials.email);
  await page.getByTestId('register-password').fill(browserCredentials.password);
  await page.getByTestId('register').click();
  await expect(page.getByTestId('register-result')).toContainText('Ready — user');
  const browserOwnerID = await page.getByTestId('owner-id').inputValue();
  const browserToken = await login(environment, browserCredentials);
  await page.getByTestId('access-token').fill(browserToken);
  await page.getByTestId('open-root').click();
  await expect(page.getByTestId('workspace-status')).toHaveText('Opened root');

  await openFolder(page, owner, ownerID, 'welcome');
  await expect(page.getByTestId('workspace-status')).toHaveText('Opened welcome');
  await expect(page.getByTestId('file-list')).toContainText('readme.txt');
  await expect(page.getByTestId('folder-list')).toContainText('projects');
  await page.getByTestId('refresh-access').click();
  await expect(page.getByTestId('access-list')).toContainText('demo-team');

  await openFolder(page, reader, ownerID, 'welcome');
  const readmeRow = page.getByTestId('file-list').getByRole('row').filter({ hasText: 'readme.txt' });
  const downloadPromise = page.waitForEvent('download');
  await readmeRow.getByRole('button', { name: 'Download' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('readme.txt');
  await expect(page.getByTestId('workspace-status')).toHaveText('Downloaded readme.txt');

  await openFolder(page, reader, ownerID, 'welcome/projects');
  await expect(page.getByTestId('workspace-status')).toHaveText('Opened welcome/projects');
  await expect(page.getByTestId('file-list')).toContainText('roadmap.txt');
  await page.getByTestId('file-input').setInputFiles({ name: 'reader-denied.txt', mimeType: 'text/plain', buffer: Buffer.from('no') });
  await page.getByTestId('upload-file').click();
  await expect(page.getByTestId('workspace-status')).toContainText('folder permission denied');
  await openFolder(page, reader, ownerID, '');
  await expect(page.getByTestId('workspace-status')).toContainText('folder permission denied');
  await openFolder(page, reader, ownerID, 'private');
  await expect(page.getByTestId('workspace-status')).toContainText('folder permission denied');

  await openFolder(page, writer, ownerID, 'welcome');
  await page.getByTestId('file-input').setInputFiles({ name: 'writer.txt', mimeType: 'text/plain', buffer: Buffer.from('writer bytes') });
  await page.getByTestId('upload-file').click();
  await expect(page.getByTestId('workspace-status')).toHaveText('Opened welcome');
  await expect(page.getByTestId('file-list')).toContainText('writer.txt');

  await openFolder(page, taggedAdmin, ownerID, 'welcome');
  await page.getByTestId('folder-name').fill('admin-child');
  await page.getByTestId('create-folder').click();
  await expect(page.getByTestId('folder-list')).toContainText('admin-child');

  await openFolder(page, owner, ownerID, 'welcome/projects');
  await page.getByTestId('folder-name').fill('review-area');
  await page.getByTestId('create-folder').click();
  await expect(page.getByTestId('folder-list')).toContainText('review-area');
  await page.getByTestId('share-group').fill('project-reviewers');
  await page.getByTestId('share-folder').click();
  await expect(page.getByTestId('workspace-status')).toHaveText('Shared welcome/projects with project-reviewers');
  await expect(page.getByTestId('access-list')).toContainText('project-reviewers');

  await openFolder(page, stranger, ownerID, 'welcome');
  await expect(page.getByTestId('workspace-status')).toContainText('folder permission denied');
  await openFolder(page, stranger, ownerID, 'welcome/projects');
  await expect(page.getByTestId('workspace-status')).toHaveText('Opened welcome/projects');
  await openFolder(page, stranger, ownerID, 'welcome/projects/review-area');
  await expect(page.getByTestId('workspace-status')).toHaveText('Opened welcome/projects/review-area');
  await openFolder(page, stranger, ownerID, 'private');
  await expect(page.getByTestId('workspace-status')).toContainText('folder permission denied');
  await openFolder(page, reader, strangerID, '');
  await expect(page.getByTestId('workspace-status')).toContainText('folder permission denied');
  expect(browserOwnerID).not.toBe(ownerID);
});
