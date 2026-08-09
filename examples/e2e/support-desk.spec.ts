import { expect, test, type Page } from '@playwright/test';
import { login } from './auth';
import { expectResponsiveExampleLayout } from './layout';

const environment = {
  authBase: `http://127.0.0.1:${process.env.SUPPORT_AUTH_PORT ?? '8293'}`,
  mailpitBase: `http://127.0.0.1:${process.env.SUPPORT_MAILPIT_PORT ?? '8393'}`,
};
const password = 'Example!Passw0rd9';

async function getTicket(page: Page, token: string, ticketID: string): Promise<void> {
  await page.getByTestId('token').fill(token);
  await page.getByTestId('ticket-id').fill(ticketID);
  await page.getByTestId('get').click();
}

function tamperJWTSignature(token: string): string {
  const parts = token.split('.');
  expect(parts).toHaveLength(3);
  expect(parts[2]).not.toBe('');
  parts[2] = `${parts[2][0] === 'A' ? 'B' : 'A'}${parts[2].slice(1)}`;
  return parts.join('.');
}

test('owner, stranger, agent, and admin traverse the real HTTP-to-gRPC authorization path', async ({ page }) => {
  test.setTimeout(90_000);
  const [owner, stranger, agent, supportAdmin] = await Promise.all([
    login(environment, { login: 'support-owner', email: 'support-owner@example.test', password }),
    login(environment, { login: 'support-stranger', email: 'support-stranger@example.test', password }),
    login(environment, { login: 'support-agent', email: 'support-agent@example.test', password }),
    login(environment, { login: 'support-admin', email: 'support-admin@example.test', password }),
  ]);

  await page.goto('/');
  await expectResponsiveExampleLayout(page, ['support-card'], ['token', 'ticket-id']);
  await expect(page.getByRole('heading', { name: 'Support desk authorization' })).toBeVisible();
  await expect(page.getByTestId('ticket-id')).not.toHaveValue('');
  const seededTicketID = await page.getByTestId('ticket-id').inputValue();
  await getTicket(page, owner, seededTicketID);
  await expect(page.getByTestId('result')).toContainText('Allowed — Seeded ticket');
  await getTicket(page, stranger, seededTicketID);
  await expect(page.getByTestId('result')).toContainText('Denied —');
  await getTicket(page, agent, seededTicketID);
  await expect(page.getByTestId('result')).toContainText('Allowed — Seeded ticket');
  await getTicket(page, supportAdmin, seededTicketID);
  await expect(page.getByTestId('result')).toContainText('Allowed — Seeded ticket');

  await page.getByTestId('token').fill(owner);
  await page.getByTestId('body').fill('exact ticket body');
  await page.getByTestId('create').click();
  await expect(page.getByTestId('result')).toContainText(/^Created ticket /);
  const createdID = await page.getByTestId('ticket-id').inputValue();
  expect(createdID).not.toBe(seededTicketID);

  await getTicket(page, owner, createdID);
  await expect(page.getByTestId('result')).toContainText(/^Allowed —/);
  await expect(page.getByTestId('result')).toContainText('exact ticket body');

  await getTicket(page, stranger, createdID);
  await expect(page.getByTestId('result')).toContainText(/^Denied —/);
  await getTicket(page, agent, createdID);
  await expect(page.getByTestId('result')).toContainText(/^Allowed —/);
  await expect(page.getByTestId('result')).toContainText('exact ticket body');
  await getTicket(page, supportAdmin, createdID);
  await expect(page.getByTestId('result')).toContainText(/^Allowed —/);
  await expect(page.getByTestId('result')).toContainText('exact ticket body');

  await getTicket(page, 'not-a-valid-access-token', createdID);
  await expect(page.getByTestId('result')).toContainText('Session missing or expired');
  const existingTicketFailure = await page.getByTestId('result').textContent();

  await getTicket(page, 'not-a-valid-access-token', 'd53eeb8e-f14f-4642-b62e-c5183174d322');
  await expect(page.getByTestId('result')).toContainText('Session missing or expired');
  expect(await page.getByTestId('result').textContent()).toBe(existingTicketFailure);

  await getTicket(page, '', createdID);
  await expect(page.getByTestId('result')).toContainText('Session missing or expired');
  const blankExistingTicketFailure = await page.getByTestId('result').textContent();

  await getTicket(page, '', 'd53eeb8e-f14f-4642-b62e-c5183174d322');
  await expect(page.getByTestId('result')).toContainText('Session missing or expired');
  expect(await page.getByTestId('result').textContent()).toBe(blankExistingTicketFailure);

  const tamperedOwnerToken = tamperJWTSignature(owner);
  await getTicket(page, tamperedOwnerToken, createdID);
  await expect(page.getByTestId('result')).toContainText('Authentication service unavailable');
  const tamperedExistingTicketFailure = await page.getByTestId('result').textContent();

  await getTicket(page, tamperedOwnerToken, 'd53eeb8e-f14f-4642-b62e-c5183174d322');
  await expect(page.getByTestId('result')).toContainText('Authentication service unavailable');
  expect(await page.getByTestId('result').textContent()).toBe(tamperedExistingTicketFailure);
});
