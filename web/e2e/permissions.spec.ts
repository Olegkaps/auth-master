import { expect, test } from '@playwright/test'
import { ADMIN, inviteAndRegister, nav, signIn, submitLogin, uniqueSuffix } from './helpers'

// A non-superuser cannot see or reach admin surfaces (invites/users), and cannot
// manage roles they aren't an admin of.
test('non-superuser cannot invite or manage roles', async ({ page, browser }) => {
  const sfx = uniqueSuffix()
  const role = `perm-role-${sfx}`
  const login = `perm${sfx}`
  const email = `perm${sfx}@localhost`
  const pass = 'Perm!User-9a'

  // Admin creates a role and a regular user.
  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await nav(page, '/roles')
  await page.getByTestId('create-role-btn').click()
  await page.getByTestId('role-name-input').fill(role)
  await page.getByTestId('role-create-submit').click()
  await expect(page.getByRole('cell', { name: role, exact: true })).toBeVisible()
  await inviteAndRegister(page, browser, login, email, pass)

  // The regular user signs in (own context).
  const ctx = await browser.newContext()
  const up = await ctx.newPage()
  await signIn(up, login, pass, email)

  // No admin navigation is shown.
  await expect(up.locator('a[data-path="/admin/users"]')).toHaveCount(0)
  await expect(up.locator('a[data-path="/admin/invites"]')).toHaveCount(0)

  // Directly visiting an admin route is guarded back to the dashboard.
  await up.goto('/#/admin/invites')
  await expect(up.getByTestId('dashboard')).toBeVisible()
  await expect(up.getByTestId('invite-email')).toHaveCount(0)

  // On the roles page they may Request but cannot Manage.
  await nav(up, '/roles')
  await expect(up.getByTestId(`request-${role}`)).toBeVisible()
  await expect(up.getByTestId(`manage-${role}`)).toHaveCount(0)

  await ctx.close()
})

// A non-manager's request is pending and needs approval; a superuser's request
// is auto-granted with no approval.
test('approval required for non-manager, auto-granted for manager', async ({ page, browser }) => {
  const sfx = uniqueSuffix()
  const role = `appr-role-${sfx}`
  const autoRole = `auto-role-${sfx}`
  const login = `appr${sfx}`
  const email = `appr${sfx}@localhost`
  const pass = 'Appr!User-9b'

  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await nav(page, '/roles')
  for (const r of [role, autoRole]) {
    await page.getByTestId('create-role-btn').click()
    await page.getByTestId('role-name-input').fill(r)
    await page.getByTestId('role-create-submit').click()
    await expect(page.getByRole('cell', { name: r, exact: true })).toBeVisible()
  }
  await inviteAndRegister(page, browser, login, email, pass)

  // Superuser requests autoRole → granted immediately (no approval).
  await nav(page, '/roles')
  await page.getByTestId(`request-${autoRole}`).click()
  await expect(page.getByText(/Granted membership/i)).toBeVisible()

  // Regular user requests `role` → pending (awaiting approval).
  const ctx = await browser.newContext()
  const up = await ctx.newPage()
  await signIn(up, login, pass, email)
  await nav(up, '/roles')
  await up.getByTestId(`request-${role}`).click()
  await expect(up.getByText(/awaiting approval/i)).toBeVisible()

  // Admin approves the pending request; the user becomes a member.
  await nav(page, '/roles')
  await page.getByTestId(`manage-${role}`).click()
  const approve = page.locator('[data-testid^="approve-"]').first()
  await expect(approve).toBeVisible()
  await approve.click()
  await expect(page.getByRole('cell', { name: login, exact: true })).toBeVisible()

  await ctx.close()
})

// Managing a role from the member list: add, change level, remove — and delete the role.
test('member list actions and role deletion', async ({ page, browser }) => {
  const sfx = uniqueSuffix()
  const role = `mgmt-role-${sfx}`
  const login = `mgmt${sfx}`
  const email = `mgmt${sfx}@localhost`
  const pass = 'Mgmt!User-9c'

  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await inviteAndRegister(page, browser, login, email, pass)

  // Find the new user's id from the Users page.
  await nav(page, '/admin/users')
  const row = page.getByRole('row', { name: new RegExp(login) })
  await expect(row).toBeVisible()

  await nav(page, '/roles')
  await page.getByTestId('create-role-btn').click()
  await page.getByTestId('role-name-input').fill(role)
  await page.getByTestId('role-create-submit').click()
  await expect(page.getByRole('cell', { name: role, exact: true })).toBeVisible()

  // Add the user via the Users page (Assign role) so we have a member to manage.
  await nav(page, '/admin/users')
  await page.getByRole('row', { name: new RegExp(login) }).getByRole('button', { name: 'Assign role' }).click()
  await page.locator('.modal select').first().selectOption({ label: role })
  await page.getByRole('button', { name: 'Assign', exact: true }).click()
  await expect(page.getByText(/Assigned/i)).toBeVisible()

  // Manage the role: the member appears with Remove; removing drops them.
  await nav(page, '/roles')
  await page.getByTestId(`manage-${role}`).click()
  await expect(page.getByTestId(`remove-${login}`)).toBeVisible()
  await page.getByTestId(`remove-${login}`).click()
  await expect(page.getByText(new RegExp(`Removed ${login}`, 'i'))).toBeVisible()
  await expect(page.getByTestId(`remove-${login}`)).toHaveCount(0)

  // Delete the role.
  await page.getByTestId('delete-role-btn').click()
  await page.getByTestId('confirm-delete-role').click()
  await expect(page.getByText(/Role deleted/i)).toBeVisible()
  await expect(page.getByRole('cell', { name: role, exact: true })).toHaveCount(0)
})

test('role can be mounted under multiple parents', async ({ page }) => {
  const sfx = uniqueSuffix()
  const parents = [`mount-a-${sfx}`, `mount-b-${sfx}`]
  const child = `mount-child-${sfx}`
  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await nav(page, '/roles')
  for (const role of [...parents, child]) {
    await page.getByTestId('create-role-btn').click()
    await page.getByTestId('role-name-input').fill(role)
    await page.getByTestId('role-create-submit').click()
    await expect(page.getByRole('cell', { name: role, exact: true })).toBeVisible()
  }
  await page.getByTestId(`manage-${child}`).click()
  for (const parent of parents) {
    await page.getByTestId('mount-parent-select').selectOption({ label: parent })
    const responsePromise = page.waitForResponse((response) => response.url().includes('/mounts') && response.request().method() === 'POST')
    await page.getByTestId('mount-role-btn').click()
    expect((await responsePromise).status()).toBe(204)
    await page.getByRole('button', { name: 'Close', exact: true }).click()
    const row = page.getByRole('row', { name: new RegExp(child) })
    await expect(row).toContainText(parent)
    if (parent !== parents.at(-1)) await page.getByTestId(`manage-${child}`).click()
  }
  const row = page.getByRole('row', { name: new RegExp(child) })
  await expect(row).toContainText(parents[0])
  await expect(row).toContainText(parents[1])
})

// From the login screen you can jump straight into another already-signed-in account.
test('switch to an active account from the login form', async ({ page, browser }) => {
  const sfx = uniqueSuffix()
  const login = `sw${sfx}`
  const email = `sw${sfx}@localhost`
  const pass = 'Switch!User-9d'

  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await inviteAndRegister(page, browser, login, email, pass)

  // Add the second account in the same browser (admin is active, so it isn't
  // offered under "Continue as" here — you're already it).
  await page.getByTestId('account-chip').click()
  await page.getByRole('button', { name: '+ Add account' }).click()
  await expect(page.getByTestId('login-input')).toBeVisible()
  await submitLogin(page, login, pass, email)
  await expect(page.getByTestId('welcome')).toContainText(login)

  // Now the second account is active; the login form offers admin under
  // "Continue as" — jump straight back in without credentials.
  await page.goto('/#/login?add=1')
  await expect(page.getByTestId(`login-switch-${ADMIN.login}`)).toBeVisible()
  await page.getByTestId(`login-switch-${ADMIN.login}`).click()
  await expect(page.getByTestId('welcome')).toContainText(ADMIN.login)
})
