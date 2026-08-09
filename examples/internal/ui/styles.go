package ui

const Styles = `
:root {
  --control-neutral: #667085;
  --control-neutral-strong: #475467;
  color-scheme: light;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: #172033;
  background: #f4f6fb;
  font-synthesis: none;
}
* { box-sizing: border-box; }
html { min-width: 320px; background: #f4f6fb; }
body { margin: 0; min-height: 100vh; background: linear-gradient(180deg, #eef2ff 0, #f7f8fc 240px); }
button, input, textarea, select { font: inherit; }
.page-shell { width: min(calc(100% - 40px), 1100px); margin: 0 auto; padding: 56px 0 72px; }
.page-header { max-width: 760px; margin-bottom: 28px; }
.eyebrow { margin: 0 0 8px; color: #4f46e5; font-size: .78rem; font-weight: 800; letter-spacing: .1em; text-transform: uppercase; }
h1, h2, h3 { margin-top: 0; color: #111827; line-height: 1.15; }
h1 { margin-bottom: 12px; font-size: clamp(2rem, 5vw, 3.25rem); letter-spacing: -.04em; }
h2 { margin-bottom: 8px; font-size: 1.25rem; }
h3 { margin-bottom: 6px; font-size: 1rem; }
.page-description, .card-help { color: #596579; line-height: 1.65; }
.page-description { margin: 0; font-size: 1.05rem; }
.card-help { margin: 0 0 20px; }
.card-stack { display: grid; gap: 20px; }
.card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 310px), 1fr)); gap: 20px; align-items: start; }
.card { min-width: 0; padding: 24px; border: 1px solid #dfe3ee; border-radius: 16px; background: #fff; box-shadow: 0 12px 32px rgba(30, 41, 59, .08); }
.compact-card { max-width: 760px; }
.subsection + .subsection { margin-top: 24px; padding-top: 24px; border-top: 1px solid #e6e9f1; }
.field-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
.field-grid.three { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.field, label.field { display: grid; min-width: 0; gap: 7px; color: #344054; font-size: .9rem; font-weight: 700; }
.field.span-all { grid-column: 1 / -1; }
input, textarea, select { width: 100%; min-width: 0; border: 1px solid var(--control-neutral); border-radius: 9px; background: #fff; color: #111827; padding: 10px 12px; line-height: 1.4; box-shadow: 0 1px 2px rgba(16, 24, 40, .04); }
textarea { min-height: 112px; resize: vertical; }
input::placeholder, textarea::placeholder { color: var(--control-neutral); }
.token-field { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: .84rem; }
input:focus-visible, textarea:focus-visible, select:focus-visible, button:focus-visible { outline: 3px solid #4f46e5; outline-offset: 2px; border-color: #4f46e5; }
.actions { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 18px; }
button { min-height: 42px; border: 1px solid #4338ca; border-radius: 9px; padding: 9px 16px; background: #4f46e5; color: #fff; font-weight: 750; cursor: pointer; transition: background-color .16s ease, border-color .16s ease, transform .16s ease; }
button:not(:disabled):hover { background: #4338ca; }
button:not(:disabled):active { transform: translateY(1px); }
button.secondary { border-color: var(--control-neutral); background: #fff; color: #344054; }
button.secondary:not(:disabled):hover { border-color: var(--control-neutral-strong); background: #f8fafc; }
button:disabled { border-color: #cbd1dc; background: #d9dde6; color: #747f91; cursor: not-allowed; transform: none; }
.result-label { margin: 20px 0 7px; color: #596579; font-size: .78rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.result { display: block; width: 100%; min-height: 48px; padding: 12px 14px; overflow-wrap: anywhere; white-space: pre-wrap; border: 1px solid #d8ddea; border-radius: 9px; background: #f7f8fc; color: #263247; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: .82rem; line-height: 1.55; }
.storage-toolbar { display: grid; grid-template-columns: minmax(0, 1.6fr) minmax(220px, .8fr) auto; gap: 12px; align-items: end; }
.storage-toolbar .actions { margin-top: 0; }
.storage-layout { display: grid; grid-template-columns: minmax(190px, .7fr) minmax(0, 1.5fr) minmax(230px, .85fr); gap: 20px; align-items: start; margin-top: 20px; }
.storage-panel { min-width: 0; }
.breadcrumb { display: flex; flex-wrap: wrap; gap: 6px; margin: 18px 0 0; padding: 0; list-style: none; }
.breadcrumb button { min-height: 32px; padding: 5px 9px; font-size: .82rem; }
.entry-list, .access-list { display: grid; gap: 8px; margin: 0; padding: 0; list-style: none; }
.entry-button { width: 100%; min-height: 42px; border-color: transparent; background: transparent; color: #263247; text-align: left; }
.entry-button:not(:disabled):hover { border-color: #c7d2fe; background: #eef2ff; }
.file-table { width: 100%; border-collapse: collapse; margin-top: 12px; }
.file-table th, .file-table td { padding: 10px 8px; border-bottom: 1px solid #e6e9f1; text-align: left; vertical-align: middle; }
.file-table th { color: #596579; font-size: .75rem; letter-spacing: .06em; text-transform: uppercase; }
.file-name { overflow-wrap: anywhere; font-weight: 700; }
.file-actions { text-align: right !important; }
.file-actions button { min-height: 34px; padding: 5px 10px; font-size: .8rem; }
.empty-state { padding: 18px 10px !important; border: 1px dashed #98a2b3 !important; border-radius: 10px; color: #596579; text-align: center !important; }
.access-pill { padding: 8px 10px; border: 1px solid #c7d2fe; border-radius: 999px; background: #eef2ff; color: #3730a3; font-size: .82rem; font-weight: 750; overflow-wrap: anywhere; }
.muted { color: #667085; font-size: .86rem; line-height: 1.5; }
@media (max-width: 720px) {
  .page-shell { width: min(calc(100% - 28px), 1100px); padding: 32px 0 48px; }
  .field-grid, .field-grid.three { grid-template-columns: minmax(0, 1fr); }
  .card { padding: 20px; border-radius: 13px; }
  .actions { align-items: stretch; flex-direction: column; }
  button { width: 100%; }
	.storage-toolbar, .storage-layout { grid-template-columns: minmax(0, 1fr); }
	.storage-toolbar .actions { margin-top: 8px; }
	.file-table thead { display: none; }
	.file-table, .file-table tbody, .file-table tr, .file-table td { display: block; width: 100%; }
	.file-table tr { padding: 10px 0; border-bottom: 1px solid #e6e9f1; }
	.file-table td { padding: 5px 0; border: 0; }
	.file-actions { text-align: left !important; }
	.file-actions button { width: auto; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { scroll-behavior: auto !important; transition-duration: .01ms !important; }
}
`
