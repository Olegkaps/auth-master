import { expect, test } from '@playwright/test'
import { ADMIN, clearMail, inviteAndRegister, nav, signIn, uniqueSuffix, waitForMagicToken } from './helpers'

test('role autocomplete, tags, subgroups, and pagination controls are usable', async ({ page }) => {
  const suffix = uniqueSuffix()
  const roleName = `SearchableRole-${suffix}`
  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await nav(page, '/roles')
  await page.getByTestId('create-role-btn').click()
  await page.getByTestId('role-name-input').fill(roleName)
  await page.getByTestId('role-create-submit').click()

  await page.getByTestId('roles-search').fill(roleName.slice(3).toUpperCase())
  await expect(page.getByRole('cell', { name: roleName, exact: true })).toBeVisible()
  await expect(page.getByText(/Page 1 of \d+/)).toBeVisible()

  await page.getByTestId(`manage-${roleName}`).click()
  await expect(page.getByText('No direct subgroups.')).toBeVisible()
  await page.getByTestId('role-tags-input').fill('Read, write')
  await page.getByTestId('save-role-tags').click()
  await expect(page.getByText('Role tags updated.')).toBeVisible()

  await page.getByRole('button', { name: 'Close', exact: true }).click()
  await nav(page, '/admin/users')
  await page.getByTestId('users-search').fill(ADMIN.login.toUpperCase())
  await expect(page.getByRole('cell', { name: ADMIN.login, exact: true })).toBeVisible()
  await expect(page.getByText(/Page 1 of \d+/)).toBeVisible()
})

test('superuser can ban and unban a user and a ban blocks login', async ({ page, browser }) => {
  const suffix = uniqueSuffix()
  const login = `banned${suffix}`
  const email = `${login}@localhost`
  const password = 'Banned!User-9a'

  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await inviteAndRegister(page, browser, login, email, password)
	const magicContext = await browser.newContext()
	const magicPage = await magicContext.newPage()
	await clearMail()
	await magicPage.goto('/#/login')
	await magicPage.getByTestId('login-input').fill(login)
	await magicPage.getByTestId('magic-link-btn').click()
	const magicToken = await waitForMagicToken(email)
	await nav(page, '/admin/users')
  await page.getByTestId('users-search').fill(login.toUpperCase())
  await expect(page.getByRole('cell', { name: login, exact: true })).toBeVisible()
  await page.getByTestId(`ban-${login}`).click()
	await expect(page.getByText('User banned.')).toBeVisible()
	await magicPage.goto(`/#/magic?token=${encodeURIComponent(magicToken)}`)
	await expect(magicPage.getByTestId('magic-status')).toContainText(/banned|failed/i)
	await magicContext.close()

  const userContext = await browser.newContext()
  const userPage = await userContext.newPage()
  await userPage.goto('/#/login')
  await userPage.getByTestId('login-input').fill(login)
  await userPage.getByTestId('password-input').fill(password)
  await userPage.getByTestId('continue-btn').click()
  await expect(userPage.getByText(/account banned/i)).toBeVisible()
  await userContext.close()

  await page.getByRole('button', { name: 'Unban', exact: true }).click()
  await expect(page.getByText('User unbanned.')).toBeVisible()
})

test('a superuser cannot ban another superuser', async ({ page, browser }) => {
	const suffix = uniqueSuffix()
	const login = `superban${suffix}`
	const email = `${login}@localhost`

	await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
	await nav(page, '/admin/invites')
	await page.getByTestId('invite-email').fill(email)
	await page.getByTestId('invite-superuser').check()
	await page.getByTestId('invite-generate').click()
	const inviteToken = await page.getByTestId('invite-token-field').inputValue()

	const context = await browser.newContext()
	const registration = await context.newPage()
	await registration.goto(`/#/register?token=${encodeURIComponent(inviteToken)}`)
	await registration.getByTestId('reg-login').fill(login)
	await registration.getByTestId('reg-email').fill(email)
	await registration.getByTestId('reg-password').fill('Super!Ban-9a')
	await registration.getByTestId('reg-submit').click()
	await expect(registration.getByTestId('login-input')).toBeVisible()
	await context.close()

	await nav(page, '/admin/users')
	await page.getByTestId('users-search').fill(login)
	await page.getByTestId(`ban-${login}`).click()
	await expect(page.getByText('cannot ban a superuser')).toBeVisible()
	await expect(page.getByRole('row').filter({ hasText: login })).toContainText('superuser')
})

test('another service can check roles using an access token in the request body', async ({ page }) => {
	const suffix = uniqueSuffix()
	const roleName = `token-role-${suffix}`

	await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
	await nav(page, '/roles')
	await page.getByTestId('create-role-btn').click()
	await page.getByTestId('role-name-input').fill(roleName)
	await page.getByTestId('role-create-submit').click()
	await page.getByTestId(`manage-${roleName}`).click()
	await page.getByTestId('role-tags-input').fill('read')
	await page.getByTestId('save-role-tags').click()
	await expect(page.getByText('Role tags updated.')).toBeVisible()
	await page.getByRole('button', { name: 'Close', exact: true }).click()

	await nav(page, '/admin/users')
	await page.getByTestId('users-search').fill(ADMIN.login)
	const adminRow = page.getByRole('row').filter({ hasText: ADMIN.login })
	await adminRow.getByRole('button', { name: 'Assign role' }).click()
	await page.getByTestId('assign-role-select').selectOption({ label: roleName })
	await page.getByTestId('assign-role-tags').fill('read')
	await page.getByTestId('assign-role-submit').click()
	await expect(page.getByText(`Assigned ${ADMIN.login} to role.`)).toBeVisible()

	const accessToken = await page.evaluate((login) => {
		const accounts = JSON.parse(localStorage.getItem('accounts_v1') || '[]') as Array<{ login: string; accessToken: string }>
		return accounts.find((account) => account.login === login)?.accessToken || ''
	}, ADMIN.login)
	expect(accessToken).not.toBe('')
	const hasRole = await page.request.post('/v1/auth/has-role', { data: { token: accessToken, role_name: roleName } })
	expect(hasRole.status()).toBe(200)
	await expect(hasRole.json()).resolves.toEqual({ has_role: true })

	const hasTag = await page.request.post('/v1/auth/has-role-with-tag', { data: { token: accessToken, role_name: roleName, tag: 'READ' } })
	expect(hasTag.status()).toBe(200)
	await expect(hasTag.json()).resolves.toEqual({ has_role_with_tag: true })

	const invalid = await page.request.post('/v1/auth/has-role', { data: { token: 'invalid', role_name: roleName } })
	expect(invalid.status()).toBe(401)
})

test('role tags are assigned per user instead of granted automatically', async ({ page, browser }) => {
  const suffix = uniqueSuffix()
  const roleName = `tagged-${suffix}`
  const login = `taguser${suffix}`
  const email = `${login}@localhost`

  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await nav(page, '/roles')
  await page.getByTestId('create-role-btn').click()
  await page.getByTestId('role-name-input').fill(roleName)
  await page.getByTestId('role-create-submit').click()
  await page.getByTestId(`manage-${roleName}`).click()
  await page.getByTestId('role-tags-input').fill('read, write')
  await page.getByTestId('save-role-tags').click()
  await expect(page.getByText('Role tags updated.')).toBeVisible()
  await page.getByRole('button', { name: 'Close', exact: true }).click()

  await inviteAndRegister(page, browser, login, email, 'Tagged!User-9a')
  await nav(page, '/admin/users')
  await page.getByTestId('users-search').fill(login)
  const userRow = page.getByRole('row').filter({ hasText: login })
  await userRow.getByRole('button', { name: 'Assign role' }).click()
  await page.getByTestId('assign-role-select').selectOption({ label: roleName })

  // Initial tag grants and the membership are one transaction. A bad tag must
  // not leave a partially-created membership behind.
  await page.getByTestId('assign-role-tags').fill('read, missing')
  await page.getByTestId('assign-role-submit').click()
  await expect(page.getByText(/tags are not configured for role/i)).toBeVisible()
	await page.getByRole('button', { name: 'Cancel', exact: true }).click()
	await nav(page, '/roles')
	await page.getByTestId('roles-search').fill(roleName)
	await page.getByTestId(`manage-${roleName}`).click()
	await expect(page.getByRole('row').filter({ hasText: login })).toHaveCount(0)
	await page.getByRole('button', { name: 'Close', exact: true }).click()
	await nav(page, '/admin/users')
	await page.getByTestId('users-search').fill(login)
	await page.getByRole('row').filter({ hasText: login }).getByRole('button', { name: 'Assign role' }).click()
	await page.getByTestId('assign-role-select').selectOption({ label: roleName })

  await page.getByTestId('assign-role-tags').fill('read')
  await page.getByTestId('assign-role-submit').click()
  await expect(page.getByText(`Assigned ${login} to role.`)).toBeVisible()

  await nav(page, '/roles')
  await page.getByTestId('roles-search').fill(roleName)
  await page.getByTestId(`manage-${roleName}`).click()
  const memberRow = page.getByRole('row').filter({ hasText: login })
	const memberTags = memberRow.getByRole('cell').nth(4)
  await expect(memberTags.getByText('read', { exact: true })).toBeVisible()

	await page.getByTestId('rename-old-tag').fill('read')
	await page.getByTestId('rename-new-tag').fill('view')
	await page.getByTestId('rename-role-tag').click()
	await expect(page.getByText('Role tag renamed.')).toBeVisible()
	await expect(memberTags.getByText('view', { exact: true })).toBeVisible()

	// Removing and re-adding a role-tag definition must not destroy the user's
	// stored grant; the incremental pair operations preserve it.
	await page.getByTestId('role-tags-input').fill('write')
	await page.getByTestId('save-role-tags').click()
	await expect(memberTags.getByText('view', { exact: true })).toBeVisible()
	await page.getByTestId('role-tags-input').fill('view, write')
	await page.getByTestId('save-role-tags').click()
	await expect(memberTags.getByText('view', { exact: true })).toBeVisible()

	await page.getByTestId(`revoke-tag-${login}-view`).click()
	await expect(page.getByText(`Revoked view from ${login}.`)).toBeVisible()
	await expect(memberTags).toHaveText('—')
})

test('role pagination and selectors continue past one hundred roles', async ({ page }) => {
	const suffix = uniqueSuffix()
	const names = Array.from({ length: 105 }, (_, index) => `zz-bulk-${suffix}-${String(index).padStart(3, '0')}`)

	await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
	const failures = await page.evaluate(async (roleNames) => {
		const accounts = JSON.parse(localStorage.getItem('accounts_v1') || '[]') as Array<{ id: string; accessToken: string }>
		const activeID = localStorage.getItem('active_account') || ''
		const accessToken = accounts.find((account) => account.id === activeID)?.accessToken || ''
		const csrfToken = decodeURIComponent(document.cookie.match(/(?:^|; )csrf_token=([^;]*)/)?.[1] || '')
		const bad: number[] = []
		for (let start = 0; start < roleNames.length; start += 15) {
			const responses = await Promise.all(roleNames.slice(start, start + 15).map((name) => fetch('/v1/roles', {
				method: 'POST',
				credentials: 'include',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${accessToken}`,
					'X-CSRF-Token': csrfToken,
				},
				body: JSON.stringify({ name, description: 'pagination regression', parent_id: '' }),
			})))
			bad.push(...responses.filter((response) => !response.ok).map((response) => response.status))
		}
		return bad
	}, names)
	expect(failures).toEqual([])

	await nav(page, '/roles')
	await expect(page.getByText(/Page 1 of [2-9]\d*/)).toBeVisible()
	const pageOneNames = await page.locator('tbody tr td:first-child strong').allTextContents()
	await page.getByRole('button', { name: 'Next' }).click()
	await expect(page.getByText(/Page 2 of [2-9]\d*/)).toBeVisible()
	const pageTwoNames = await page.locator('tbody tr td:first-child strong').allTextContents()
	expect(pageOneNames).not.toEqual([])
	expect(pageTwoNames).not.toEqual([])
	expect(pageTwoNames.filter((name) => pageOneNames.includes(name))).toEqual([])
	await page.getByRole('button', { name: 'Previous' }).click()
	await expect(page.getByText(/Page 1 of [2-9]\d*/)).toBeVisible()
	expect(await page.locator('tbody tr td:first-child strong').allTextContents()).toEqual(pageOneNames)

	// A superseded response must not overwrite the latest search query.
	await page.getByTestId('roles-search').fill(`zz-bulk-${suffix}`)
	await page.getByTestId('roles-search').fill(names.at(-1)!)
	await expect(page.getByRole('cell', { name: names.at(-1)!, exact: true })).toBeVisible()
	await expect(page.locator('tbody tr')).toHaveCount(1)

	await nav(page, '/admin/users')
	await page.getByTestId('users-search').fill(ADMIN.login)
	await page.getByRole('row').filter({ hasText: ADMIN.login }).getByRole('button', { name: 'Assign role' }).click()
	await page.getByTestId('assign-role-select').selectOption({ label: names.at(-1)! })
	await expect(page.getByTestId('assign-role-select')).toHaveValue(/.+/)
})
