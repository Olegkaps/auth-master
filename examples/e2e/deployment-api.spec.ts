import { expect, test, type Page } from '@playwright/test';

import {
  login,
  type AuthEnvironment,
} from './auth';
import { expectResponsiveExampleLayout } from './layout';

const environment: AuthEnvironment = {
  authBase: `http://127.0.0.1:${process.env.DEPLOYMENT_AUTH_PORT ?? '8292'}`,
  mailpitBase: `http://127.0.0.1:${process.env.DEPLOYMENT_MAILPIT_PORT ?? '8392'}`,
};

type Operation = 'deploy' | 'delete';

async function expectDecision(
  page: Page,
  token: string,
  slug: 'billing' | 'other',
  operation: Operation,
  expected: 'Allowed' | 'Denied',
): Promise<void> {
  await page.getByTestId('token').fill(token);
  await page.getByTestId('slug').fill(slug);
  await page.getByTestId(operation).click();
  await expect(page.getByTestId('result')).toHaveText(new RegExp(`^${expected}\\b`));
}

test('deployment UI enforces the complete role persona matrix', async ({ page }) => {
  test.setTimeout(120_000);

  const password = 'Example!Passw0rd9';
  const [globalAdmin, developer, billingAdmin, stranger] = await Promise.all([
    login(environment, { login: 'deploy-global', email: 'deploy-global@example.test', password }),
    login(environment, { login: 'deploy-developer', email: 'deploy-developer@example.test', password }),
    login(environment, { login: 'deploy-billing', email: 'deploy-billing@example.test', password }),
    login(environment, { login: 'deploy-stranger', email: 'deploy-stranger@example.test', password }),
  ]);

  const globalIdentity = await fetch(`${environment.authBase}/v1/me`, {
    headers: { Authorization: `Bearer ${globalAdmin}` },
  });
  expect(globalIdentity.status).toBe(200);
  expect((await globalIdentity.json() as { superuser: boolean }).superuser).toBe(false);

  await page.goto('/');
  await expectResponsiveExampleLayout(page, ['deployment-card'], ['token', 'slug']);
  await expect(page.getByRole('heading', { name: 'Deployment authorization' })).toBeVisible();

  const matrix = [
    {
      persona: 'non-superuser global admin',
      token: globalAdmin,
      decisions: [
        ['billing', 'deploy', 'Allowed'],
        ['billing', 'delete', 'Allowed'],
        ['other', 'deploy', 'Allowed'],
        ['other', 'delete', 'Allowed'],
      ],
    },
    {
      persona: 'developer',
      token: developer,
      decisions: [
        ['billing', 'deploy', 'Allowed'],
        ['billing', 'delete', 'Denied'],
        ['other', 'deploy', 'Allowed'],
        ['other', 'delete', 'Denied'],
      ],
    },
    {
      persona: 'billing application admin',
      token: billingAdmin,
      decisions: [
        ['billing', 'deploy', 'Allowed'],
        ['billing', 'delete', 'Allowed'],
        ['other', 'deploy', 'Denied'],
        ['other', 'delete', 'Denied'],
      ],
    },
    {
      persona: 'stranger',
      token: stranger,
      decisions: [
        ['billing', 'deploy', 'Denied'],
        ['billing', 'delete', 'Denied'],
        ['other', 'deploy', 'Denied'],
        ['other', 'delete', 'Denied'],
      ],
    },
  ] satisfies Array<{
    persona: string;
    token: string;
      decisions: Array<['billing' | 'other', Operation, 'Allowed' | 'Denied']>;
  }>;

  for (const { persona, token, decisions } of matrix) {
    await test.step(persona, async () => {
      for (const [slug, operation, status] of decisions) {
        await expectDecision(page, token, slug, operation, status);
      }
    });
  }

  await test.step('missing token', async () => {
    await page.getByTestId('token').fill('');
    await page.getByTestId('slug').fill('billing');
    await page.getByTestId('deploy').click();
    await expect(page.getByTestId('result')).toContainText('Session missing or expired');
    await page.getByTestId('delete').click();
    await expect(page.getByTestId('result')).toContainText('Session missing or expired');
  });
});
