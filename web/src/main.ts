import './style.css'
import { api, isSignedIn, onSessionChange, session, setUnauthorizedHandler } from './api'
import { accounts, activeAccountId, bootRestore, onAccountsChange, signOutAccount, signOutAll, switchTo } from './accounts'
import { isSuperuser } from './store'
import { currentPath, initRouter, navigate } from './router'
import { button, h, mountToasts, run, toast } from './ui'
import { loginView } from './views/login'
import { registerView } from './views/register'
import { resetView } from './views/reset'
import { magicView } from './views/magic'
import { dashboardView } from './views/dashboard'
import { rolesView } from './views/roles'
import { sessionsView } from './views/sessions'
import { profileView } from './views/profile'
import { usersView } from './views/users'
import { invitesView } from './views/invites'
import { securityView } from './views/security'

const requireAuth = (): string | null => (isSignedIn() ? null : '/login')
const requireSuper = (): string | null => (!isSignedIn() ? '/login' : isSuperuser() ? null : '/')
// Allow /login while signed in only in "add account" mode.
const requireAnon = (): string | null => (isSignedIn() && !window.location.hash.includes('add=1') ? '/' : null)

interface NavItem {
  path: string
  label: string
  icon: string
  admin?: boolean
}
const NAV: NavItem[] = [
  { path: '/', label: 'Dashboard', icon: '▚' },
  { path: '/roles', label: 'Roles', icon: '◆' },
  { path: '/sessions', label: 'Sessions', icon: '⧉' },
  { path: '/profile', label: 'Profile', icon: '☺' },
  { path: '/admin/users', label: 'Users', icon: '⚇', admin: true },
  { path: '/admin/invites', label: 'Invites', icon: '✉', admin: true },
  { path: '/admin/security', label: 'Security', icon: '⚿', admin: true },
]

const outlet = h('div', { class: 'outlet' })
let navLinks: HTMLAnchorElement[] = []

function navLink(n: NavItem): HTMLAnchorElement {
  const a = h('a', { href: `#${n.path}`, class: 'nav-link', 'data-path': n.path }, h('span', { class: 'nav-icon' }, n.icon), n.label) as HTMLAnchorElement
  navLinks.push(a)
  return a
}

function sidebar(): HTMLElement {
  const su = isSuperuser()
  navLinks = []
  const general = NAV.filter((n) => !n.admin).map(navLink)
  const admin = NAV.filter((n) => n.admin).map(navLink)

  return h(
    'aside',
    { class: 'sidebar' },
    h('div', { class: 'brand' }, h('span', { class: 'brand-mark' }, '◈'), h('span', {}, 'auth-master')),
    h('nav', { class: 'nav' }, ...general, su ? h('div', { class: 'nav-section' }, 'Admin') : null, ...(su ? admin : [])),
    h('a', { class: 'nav-link subtle', href: '/swagger/index.html', target: '_blank' }, h('span', { class: 'nav-icon' }, '❯'), 'Swagger API'),
  )
}

function topbar(): HTMLElement {
  const u = session.user
  const menu = h('div', { class: 'account-menu', 'data-testid': 'account-menu' })
  menu.hidden = true

  const chip = h(
    'button',
    { class: 'user-chip', type: 'button', 'data-testid': 'account-chip', onclick: () => (menu.hidden = !menu.hidden) },
    h('div', { class: 'avatar' }, (u?.login ?? '?')[0].toUpperCase()),
    h('div', { class: 'user-meta' }, h('strong', {}, u?.login ?? '—'), h('span', { class: 'muted small' }, u?.superuser ? 'superuser' : u?.kind ?? '')),
    h('span', { class: 'chip-caret' }, '▾'),
  )

  const list = accounts()
  for (const a of list) {
    const isActive = a.id === activeAccountId()
    menu.append(
      h(
        'div',
        { class: 'account-row' + (isActive ? ' active' : ''), 'data-testid': `account-${a.login}` },
        h(
          'button',
          {
            class: 'account-pick',
            type: 'button',
            disabled: isActive,
            onclick: async () => {
              menu.hidden = true
              await run(switchTo(a.id))
              navigate('/')
            },
          },
          h('div', { class: 'avatar sm' }, a.login[0].toUpperCase()),
          h('div', { class: 'user-meta' }, h('strong', {}, a.login), h('span', { class: 'muted small' }, a.superuser ? 'superuser' : a.kind)),
          isActive ? h('span', { class: 'badge green' }, 'active') : null,
        ),
        h('button', { class: 'account-x', type: 'button', title: 'Sign out this account', onclick: () => void doSignOutOne(a.id) }, '✕'),
      ),
    )
  }
  menu.append(
    h('div', { class: 'account-actions' },
      button('+ Add account', () => { menu.hidden = true; navigate('/login?add=1') }, 'secondary', { class: 'btn secondary small' }),
      button('Sign out all', () => void doSignOutAll(), 'ghost', { class: 'btn ghost small' }),
    ),
  )

  return h(
    'header',
    { class: 'topbar' },
    h('div', { class: 'crumb' }, h('span', { class: 'muted small' }, 'Demo app · adapts to your permissions')),
    h('div', { class: 'account-wrap' }, chip, menu),
  )
}

async function doSignOutOne(id: string): Promise<void> {
  await signOutAccount(id, (t) => api.logout(t))
  if (!isSignedIn()) {
    toast('Signed out.', 'info')
    navigate('/login')
  } else {
    toast('Switched account.', 'info')
    navigate('/')
  }
}

async function doSignOutAll(): Promise<void> {
  await signOutAll((t) => api.logout(t))
  toast('Signed out of all accounts.', 'info')
  navigate('/login')
}

function paintChrome(): void {
  const root = document.querySelector<HTMLDivElement>('#app')!
  if (isSignedIn()) {
    root.replaceChildren(h('div', { class: 'app-shell' }, sidebar(), h('div', { class: 'main' }, topbar(), h('main', { class: 'content' }, outlet))))
  } else {
    root.replaceChildren(h('div', { class: 'auth-wrap' }, outlet))
  }
  updateActive()
}

function updateActive(): void {
  const path = currentPath()
  for (const a of navLinks) a.classList.toggle('active', a.dataset.path === path)
}

async function boot(): Promise<void> {
  const root = document.querySelector<HTMLDivElement>('#app')!
  const toastHost = h('div', { class: 'toast-host' })
  document.body.append(toastHost)
  mountToasts(toastHost)

  // Restore the cookie-owning account (and remember any others) on reload —
  // exactly what a real SPA would do.
  root.replaceChildren(h('div', { class: 'boot' }, 'Loading…'))
  await bootRestore()

  onSessionChange(paintChrome)
  onAccountsChange(paintChrome)
  window.addEventListener('hashchange', updateActive)
  document.addEventListener('click', (e) => {
    // Close the account menu when clicking outside it.
    const t = e.target as HTMLElement
    if (!t.closest('.account-wrap')) document.querySelectorAll('.account-menu').forEach((m) => ((m as HTMLElement).hidden = true))
  })
  // When even the refresh token is dead, bounce to the login screen.
  setUnauthorizedHandler(() => {
    if (currentPath() !== '/login') {
      toast('Session expired — please sign in again.', 'err')
      navigate('/login')
    }
  })
  paintChrome()

  initRouter(outlet, [
    { path: '/login', view: (q) => loginView(q), guard: requireAnon },
    // Register works whether or not you're signed in (invite link → add another account).
    { path: '/register', view: (q) => registerView(q) },
    { path: '/reset', view: (q) => resetView(q), guard: requireAnon },
    // Magic link works whether or not you're signed in (adds/switches account).
    { path: '/magic', view: (q) => magicView(q) },
    { path: '/', view: () => dashboardView(), guard: requireAuth },
    { path: '/roles', view: () => rolesView(), guard: requireAuth },
    { path: '/sessions', view: () => sessionsView(), guard: requireAuth },
    { path: '/profile', view: () => profileView(), guard: requireAuth },
    { path: '/admin/users', view: () => usersView(), guard: requireSuper },
    { path: '/admin/invites', view: () => invitesView(), guard: requireSuper },
    { path: '/admin/security', view: () => securityView(), guard: requireSuper },
  ], notFoundView)

  // Land somewhere sensible.
  if (!window.location.hash) navigate(isSignedIn() ? '/' : '/login')
}

function notFoundView(): HTMLElement {
  return h('div', { class: 'page' }, h('div', { class: 'empty' }, 'Page not found.'), button('Go home', () => navigate(isSignedIn() ? '/' : '/login'), 'secondary'))
}

void boot()
