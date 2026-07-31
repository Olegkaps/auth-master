// Minimal hash router. Views are async functions returning a DOM node; the
// router mounts the result into the outlet and re-runs on hash changes.

export interface Route {
  path: string
  view: (params: URLSearchParams) => HTMLElement | Promise<HTMLElement>
  /** Return a redirect path to block navigation, or null to allow. */
  guard?: () => string | null
}

let routes: Route[] = []
let outlet: HTMLElement
let notFound: () => HTMLElement

export function initRouter(el: HTMLElement, table: Route[], nf: () => HTMLElement): void {
  outlet = el
  routes = table
  notFound = nf
  window.addEventListener('hashchange', render)
  render()
}

export function navigate(path: string): void {
  if (currentPath() === path) render()
  else window.location.hash = path
}

export function currentPath(): string {
  const raw = window.location.hash.replace(/^#/, '') || '/'
  return raw.split('?')[0]
}

function currentQuery(): URLSearchParams {
  const raw = window.location.hash.replace(/^#/, '')
  const q = raw.split('?')[1] ?? ''
  return new URLSearchParams(q)
}

async function render(): Promise<void> {
  const path = currentPath()
  const route = routes.find((r) => r.path === path)
  if (!route) {
    swap(notFound())
    return
  }
  const redirect = route.guard?.()
  if (redirect) {
    navigate(redirect)
    return
  }
  swap(loading())
  try {
    const node = await route.view(currentQuery())
    swap(node)
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    const err = document.createElement('div')
    err.className = 'empty'
    err.textContent = `Failed to load: ${msg}`
    swap(err)
  }
}

function swap(node: HTMLElement): void {
  outlet.replaceChildren(node)
}

function loading(): HTMLElement {
  const d = document.createElement('div')
  d.className = 'loading'
  d.textContent = 'Loading…'
  return d
}
