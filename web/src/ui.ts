// A small vanilla component kit. No framework — just enough structure to build
// real screens (cards, tables, forms, modals, toasts) and show how the pieces
// fit together.

type Child = Node | string | number | null | undefined | false

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, unknown> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue
    if (k === 'class') node.className = String(v)
    else if (k === 'html') node.innerHTML = String(v)
    else if (k === 'value') (node as HTMLInputElement).value = String(v)
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v as EventListener)
    else node.setAttribute(k, String(v))
  }
  append(node, children)
  return node
}

export function append(node: ParentNode, children: Child[]): void {
  for (const c of children) {
    if (c == null || c === false) continue
    node.append(c instanceof Node ? c : document.createTextNode(String(c)))
  }
}

export function clear(node: Node): void {
  while (node.firstChild) node.removeChild(node.firstChild)
}

// ---- Primitives -------------------------------------------------------------

type BtnKind = 'primary' | 'secondary' | 'danger' | 'ghost'

export function button(label: string, onClick: () => void, kind: BtnKind = 'primary', opts: Record<string, unknown> = {}): HTMLButtonElement {
  return h('button', { type: 'button', class: `btn ${kind}`, onclick: onClick, ...opts }, label)
}

export function badge(text: string, tone: 'green' | 'blue' | 'gray' | 'yellow' | 'red' = 'gray'): HTMLElement {
  return h('span', { class: `badge ${tone}` }, text)
}

export function avatar(login: string, size?: 'sm'): HTMLElement {
  return h('div', { class: 'avatar' + (size === 'sm' ? ' sm' : '') }, (login || '?')[0].toUpperCase())
}

export function field(label: string, control: HTMLElement, hint?: string): HTMLElement {
  return h('label', { class: 'field' }, h('span', { class: 'field-label' }, label), control, hint ? h('span', { class: 'field-hint' }, hint) : null)
}

export function textInput(opts: Record<string, unknown> = {}): HTMLInputElement {
  return h('input', { class: 'input', ...opts })
}

export function select(options: Array<[string, string]>, opts: Record<string, unknown> = {}): HTMLSelectElement {
  return h('select', { class: 'input', ...opts }, ...options.map(([v, l]) => h('option', { value: v }, l)))
}

export function card(title: string | null, ...children: Child[]): HTMLElement {
  return h('section', { class: 'panel' }, title ? h('h3', { class: 'panel-title' }, title) : null, ...children)
}

export function empty(text: string): HTMLElement {
  return h('div', { class: 'empty' }, text)
}

// ---- Tables -----------------------------------------------------------------

export function table(headers: string[], rows: Child[][]): HTMLElement {
  if (rows.length === 0) return empty('Nothing here yet.')
  return h(
    'table',
    { class: 'table' },
    h('thead', {}, h('tr', {}, ...headers.map((x) => h('th', {}, x)))),
    h('tbody', {}, ...rows.map((r) => h('tr', {}, ...r.map((c) => h('td', {}, c instanceof Node ? c : String(c ?? '')))))),
  )
}

export function mono(text: string, full?: string): HTMLElement {
  return h('code', { class: 'mono', title: full ?? text }, text)
}

export function shortId(id: string): HTMLElement {
  return mono(id.slice(0, 8), id)
}

// ---- Toasts -----------------------------------------------------------------

let toastHost: HTMLElement

export function mountToasts(el: HTMLElement): void {
  toastHost = el
}

export function toast(message: string, tone: 'ok' | 'err' | 'info' = 'info'): void {
  if (!toastHost) return
  const t = h('div', { class: `toast ${tone}` }, message)
  toastHost.append(t)
  setTimeout(() => t.classList.add('show'), 10)
  setTimeout(() => {
    t.classList.remove('show')
    setTimeout(() => t.remove(), 250)
  }, 4200)
}

/**
 * Await a promise, toasting success or the backend error message.
 * Returns the resolved value on success (which may be `null` for 204 responses)
 * and `undefined` on failure — so callers can distinguish a successful empty
 * response from an error with `r === undefined`.
 */
export async function run<T>(p: Promise<T>, okMsg?: string): Promise<T | undefined> {
  try {
    const r = await p
    if (okMsg) toast(okMsg, 'ok')
    return r
  } catch (e) {
    toast(e instanceof Error ? e.message : String(e), 'err')
    return undefined
  }
}

// ---- Modal ------------------------------------------------------------------

export function modal(title: string, body: HTMLElement, actions: HTMLElement[]): () => void {
  const overlay = h(
    'div',
    { class: 'modal-overlay', onclick: (e: MouseEvent) => e.target === overlay && close() },
    h('div', { class: 'modal' }, h('div', { class: 'modal-head' }, h('h3', {}, title)), h('div', { class: 'modal-body' }, body), h('div', { class: 'modal-actions' }, ...actions)),
  )
  const close = (): void => overlay.remove()
  document.body.append(overlay)
  return close
}
