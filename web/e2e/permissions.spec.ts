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
	const root = `mount-root-${sfx}`
  const parents = [`mount-a-${sfx}`, `mount-b-${sfx}`]
  const child = `mount-child-${sfx}`
	const grandchild = `mount-grandchild-${sfx}`
  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await nav(page, '/roles')
	for (const role of [root, ...parents, child, grandchild]) {
    await page.getByTestId('create-role-btn').click()
    await page.getByTestId('role-name-input').fill(role)
		if (role === grandchild) await page.locator('.modal select').selectOption({ label: child })
    await page.getByTestId('role-create-submit').click()
    await expect(page.getByRole('cell', { name: role, exact: true })).toBeVisible()
  }
	for (const parent of parents) {
		await page.getByTestId('roles-search').fill(parent)
		await page.getByTestId(`manage-${parent}`).click()
		await page.getByTestId('mount-parent-select').selectOption({ label: root })
		const response = page.waitForResponse((r) => r.url().includes('/mounts') && r.request().method() === 'POST')
		await page.getByTestId('mount-role-btn').click()
		expect((await response).status()).toBe(204)
		await page.getByRole('button', { name: 'Close', exact: true }).click()
	}
	await page.getByTestId('roles-search').fill(child)
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

	// A parent cannot be mounted below its own descendant.
	await page.getByTestId('roles-search').fill(parents[0])
	await page.getByTestId(`manage-${parents[0]}`).click()
	await page.getByTestId('mount-parent-select').selectOption({ label: child })
	const cycleResponse = page.waitForResponse((response) => response.url().includes('/mounts') && response.request().method() === 'POST')
	await page.getByTestId('mount-role-btn').click()
	expect((await cycleResponse).status()).toBe(400)
	await expect(page.getByText('mount would create a cycle', { exact: true })).toBeVisible()
	await page.getByRole('button', { name: 'Close', exact: true }).click()

	// Recursive traversal through the diamond returns every descendant once.
	const recursiveNames = await page.evaluate(async (rootName) => {
		const accounts = JSON.parse(localStorage.getItem('accounts_v1') || '[]') as Array<{ id: string; accessToken: string }>
		const activeID = localStorage.getItem('active_account') || ''
		const token = accounts.find((account) => account.id === activeID)?.accessToken || ''
		const headers = { Authorization: `Bearer ${token}` }
		const search = await fetch(`/v1/roles?search=${encodeURIComponent(rootName)}&limit=25`, { headers })
		const found = await search.json() as { roles: Array<{ ID: string; Name: string }> }
		const rootRole = found.roles.find((role) => role.Name === rootName)
		if (!rootRole) throw new Error(`missing root ${rootName}`)
		const response = await fetch(`/v1/roles/${rootRole.ID}/subgroups?recursive=true`, { headers })
		const result = await response.json() as { roles: Array<{ Name: string }> }
		return result.roles.map((role) => role.Name)
	}, root)
	for (const expected of [...parents, child, grandchild]) {
		expect(recursiveNames.filter((name) => name === expected)).toHaveLength(1)
	}

	// Deleting the middle role atomically reconnects its child to both parents.
	await page.getByTestId('roles-search').fill(child)
	await page.getByTestId(`manage-${child}`).click()
	await page.getByTestId('delete-role-btn').click()
	await page.getByTestId('confirm-delete-role').click()
	await page.getByTestId('roles-search').fill(grandchild)
	const grandchildRow = page.getByRole('row').filter({ hasText: grandchild })
	await expect(grandchildRow).toContainText(parents[0])
	await expect(grandchildRow).toContainText(parents[1])
})

test('role administrators inherit management through a parent role', async ({ page, browser }) => {
  const sfx = uniqueSuffix()
  const parent = `inherit-parent-${sfx}`
  const child = `inherit-child-${sfx}`
  const login = `inherit${sfx}`
  const email = `${login}@localhost`
  const pass = 'Inherit!Admin-9e'
	const directLogin = `direct${sfx}`
	const directEmail = `${directLogin}@localhost`
	const directPass = 'Direct!Member-9f'

  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await nav(page, '/roles')
  for (const role of [parent, child]) {
    await page.getByTestId('create-role-btn').click()
    await page.getByTestId('role-name-input').fill(role)
    if (role === child) await page.locator('.modal select').selectOption({ label: parent })
    await page.getByTestId('role-create-submit').click()
    await expect(page.getByTestId('roles-search')).toHaveValue(role)
    await expect(page.getByRole('cell', { name: role, exact: true })).toBeVisible()
  }
  await inviteAndRegister(page, browser, login, email, pass)
	await inviteAndRegister(page, browser, directLogin, directEmail, directPass)

  await nav(page, '/admin/users')
  await page.getByTestId('users-search').fill(login)
  await page.getByRole('row').filter({ hasText: login }).getByRole('button', { name: 'Assign role' }).click()
  await page.getByTestId('assign-role-select').selectOption({ label: parent })
  await page.locator('.modal select').nth(1).selectOption('role_admin')
  await page.getByTestId('assign-role-submit').click()
	await page.getByTestId('users-search').fill(directLogin)
	await page.getByRole('row').filter({ hasText: directLogin }).getByRole('button', { name: 'Assign role' }).click()
	await page.getByTestId('assign-role-select').selectOption({ label: parent })
	await page.locator('.modal select').nth(1).selectOption('direct_member')
	await page.getByTestId('assign-role-submit').click()

  const context = await browser.newContext()
  const userPage = await context.newPage()
  await signIn(userPage, login, pass, email)
  await nav(userPage, '/roles')
  await userPage.getByTestId('roles-search').fill(child)
  const childRow = userPage.getByRole('row').filter({ hasText: child })
  await expect(childRow.getByText('role admin')).toBeVisible()
  await expect(userPage.getByTestId(`manage-${child}`)).toBeVisible()
  await expect(userPage.getByTestId(`request-${child}`)).toHaveCount(0)
  await context.close()

	// direct_member grants exactly the selected role: it never flows into a
	// descendant, so that user may still request the child and cannot manage it.
	const directContext = await browser.newContext()
	const directPage = await directContext.newPage()
	await signIn(directPage, directLogin, directPass, directEmail)
	await expect(directPage.getByText('direct member', { exact: true })).toBeVisible()
	await nav(directPage, '/roles')
	await directPage.getByTestId('roles-search').fill(child)
	await expect(directPage.getByTestId(`request-${child}`)).toBeVisible()
	await expect(directPage.getByTestId(`manage-${child}`)).toHaveCount(0)
	await expect(directPage.getByRole('row').filter({ hasText: child }).getByRole('cell').nth(3)).toHaveText('—')
	await directContext.close()
})

test('mounting roles requires management authority over both endpoints', async ({ page, browser }) => {
	const sfx = uniqueSuffix()
	const parent = `mount-authority-parent-${sfx}`
	const child = `mount-authority-child-${sfx}`
	const login = `mountmanager${sfx}`
	const email = `${login}@localhost`
	const pass = 'Mount!Manager-9g'

	await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
	await nav(page, '/roles')
	for (const role of [parent, child]) {
		await page.getByTestId('create-role-btn').click()
		await page.getByTestId('role-name-input').fill(role)
		await page.getByTestId('role-create-submit').click()
	}
	await inviteAndRegister(page, browser, login, email, pass)
	await nav(page, '/admin/users')
	await page.getByTestId('users-search').fill(login)
	const assign = async (role: string): Promise<void> => {
		await page.getByRole('row').filter({ hasText: login }).getByRole('button', { name: 'Assign role' }).click()
		await page.getByTestId('assign-role-select').selectOption({ label: role })
		await page.locator('.modal select').nth(1).selectOption('role_admin')
		await page.getByTestId('assign-role-submit').click()
	}
	await assign(child)

	const context = await browser.newContext()
	const manager = await context.newPage()
	await signIn(manager, login, pass, email)
	await nav(manager, '/roles')
	await manager.getByTestId('roles-search').fill(child)
	await manager.getByTestId(`manage-${child}`).click()
	await manager.getByTestId('mount-parent-select').selectOption({ label: parent })
	let mount = manager.waitForResponse((response) => response.url().includes('/mounts') && response.request().method() === 'POST')
	await manager.getByTestId('mount-role-btn').click()
	expect((await mount).status()).toBe(403)
	await manager.getByRole('button', { name: 'Close', exact: true }).click()

	await assign(parent)
	await manager.reload()
	await expect(manager.getByTestId('roles-page')).toBeVisible()
	await manager.getByTestId('roles-search').fill(child)
	await manager.getByTestId(`manage-${child}`).click()
	await manager.getByTestId('mount-parent-select').selectOption({ label: parent })
	mount = manager.waitForResponse((response) => response.url().includes('/mounts') && response.request().method() === 'POST')
	await manager.getByTestId('mount-role-btn').click()
	expect((await mount).status()).toBe(204)
	await context.close()
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

  // The refresh cookie belongs to the most recently signed-in account, while
  // the bearer token belongs to admin. Mutations must use the current
  // double-submit cookie instead of a stale per-account in-memory CSRF value.
  await nav(page, '/admin/users')
  await page.getByTestId('users-search').fill(login)
  await page.getByTestId(`ban-${login}`).click()
  await expect(page.getByText('User banned.')).toBeVisible()

  // Switching to the now-revoked saved session evicts it and restores admin.
  await page.getByTestId('account-chip').click()
  await page.getByTestId(`account-${login}`).locator('button').first().click()
  await expect(page.getByText(`Session for ${login} has expired`)).toBeVisible()
  await expect(page.getByTestId(`account-${login}`)).toHaveCount(0)
  await expect(page.getByTestId('account-chip')).toContainText(ADMIN.login)
})

test('transient refresh failures preserve saved accounts on switch and boot', async ({ page, browser }) => {
  const sfx = uniqueSuffix()
  const login = `retry${sfx}`
  const email = `${login}@localhost`
  const pass = 'Retry!User-9f'

  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await inviteAndRegister(page, browser, login, email, pass)
  await page.getByTestId('account-chip').click()
  await page.getByRole('button', { name: '+ Add account' }).click()
  await submitLogin(page, login, pass, email)
  const userRefresh = await page.evaluate((savedLogin) => {
    const accounts = JSON.parse(localStorage.getItem('accounts_v1') || '[]') as Array<{ login: string; refreshToken: string }>
    return accounts.find((account) => account.login === savedLogin)?.refreshToken || ''
  }, login)
  expect(userRefresh).not.toBe('')

  await page.goto('/#/login?add=1')
  await page.getByTestId(`login-switch-${ADMIN.login}`).click()
  await page.route('**/v1/auth/refresh', async (route) => {
    const body = route.request().postData() || ''
    if (body.includes(userRefresh)) {
      await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"temporary"}' })
    } else {
      await route.continue()
    }
  })
  await page.getByTestId('account-chip').click()
  await page.getByTestId(`account-${login}`).locator('button').first().click()
  await expect(page.getByText(`Session for ${login} is temporarily unavailable; retry the switch.`)).toBeVisible()
  await expect(page.getByTestId(`account-${login}`)).toHaveCount(1)
  await expect(page.getByTestId('account-chip')).toContainText(ADMIN.login)

  await page.unroute('**/v1/auth/refresh')
  await page.getByTestId('account-chip').click()
  await page.getByTestId(`account-${login}`).locator('button').first().click()
	await expect(page.getByTestId('welcome')).toContainText(login)
  await page.route('**/v1/auth/refresh', (route) => route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"temporary"}' }))
  await page.reload()
  await expect(page.getByTestId('account-chip')).toContainText(login)
  await page.getByTestId('account-chip').click()
  await expect(page.getByTestId(`account-${login}`)).toHaveCount(1)
  await expect(page.getByTestId(`account-${ADMIN.login}`)).toHaveCount(1)
})
