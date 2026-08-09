package main

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/olegkapshai/auth-master/examples/internal/authz"
	exampleui "github.com/olegkapshai/auth-master/examples/internal/ui"
)

var appSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type roleChecker interface {
	HasRole(context.Context, string, string) (bool, error)
}

type deploymentApp struct{ checker roleChecker }

func (a deploymentApp) routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(deploymentPage))
	})
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	r.Post("/apps/{slug}/deploy", a.deploy)
	r.Delete("/apps/{slug}", a.deleteApp)
	return r
}

var deploymentPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Deployment authorization example</title><style id="examples-ui">` + exampleui.Styles + `</style></head><body>
<main class="page-shell" data-ui="page-shell"><header class="page-header"><p class="eyebrow">HTTP role checks</p><h1>Deployment authorization</h1><p class="page-description">This is an authorization probe: it checks whether an action would be allowed; it does not deploy real software.</p></header>
<section class="card compact-card" data-ui="card" data-testid="personas-card"><h2>Ready-to-use personas</h2><p class="card-help">All accounts use <code>Example!Passw0rd9</code>. Print a fresh real human token with <code>make -C examples token EXAMPLE=deployment-api PERSONA=&lt;key&gt;</code>.</p>
<ul><li><strong>global</strong> — <code>deploy-global</code>: deploy/delete every application</li><li><strong>developer</strong> — <code>deploy-developer</code>: deploy any application; delete denied</li><li><strong>billing</strong> — <code>deploy-billing</code>: deploy/delete <code>billing</code> only</li><li><strong>stranger</strong> — <code>deploy-stranger</code>: every action denied</li></ul></section>
<section class="card compact-card" data-ui="card" data-testid="deployment-card"><h2>Check application permission</h2><p class="card-help">Try <code>billing</code> and <code>other</code> to compare global, occupational, and resource-scoped roles.</p>
<div class="field-grid"><label class="field">Access token <input class="token-field" data-testid="token" autocomplete="off"></label>
<label class="field">Application slug <input data-testid="slug" placeholder="billing"></label></div>
<div class="actions"><button data-testid="deploy">Check deploy permission</button><button class="secondary" data-testid="delete">Check delete permission</button></div>
<p class="result-label">Result</p><output class="result" data-testid="result" aria-live="polite"></output></section></main><script>
const q=s=>document.querySelector(s),result=q('[data-testid=result]'),buttons=[q('[data-testid=deploy]'),q('[data-testid=delete]')];async function act(method,suffix){const slug=q('[data-testid=slug]').value.trim(),action=method==='POST'?'deploy':'delete';result.textContent='Checking '+action+' permission…';buttons.forEach(b=>b.disabled=true);try{
const r=await fetch('/apps/'+encodeURIComponent(slug)+suffix,{method,headers:{Authorization:'Bearer '+q('[data-testid=token]').value}});const text=await r.text();
if(r.status===204)result.textContent='Allowed — this persona may '+action+' '+slug+'.';else if(r.status===403)result.textContent='Denied — this persona lacks a role that may '+action+' '+slug+'.';else if(r.status===401)result.textContent='Session missing or expired — print a fresh persona token.';else if(r.status===400)result.textContent='Invalid application slug — use lowercase letters, digits, and hyphens.';else if(r.status===503)result.textContent='Authorization service unavailable — retry after auth-master recovers.';else result.textContent='Request failed ('+r.status+'): '+text.trim()}catch(error){result.textContent='Network error — '+error.message}finally{buttons.forEach(b=>b.disabled=false)}}
q('[data-testid=deploy]').onclick=()=>act('POST','/deploy');q('[data-testid=delete]').onclick=()=>act('DELETE','');
</script></body></html>`

func (a deploymentApp) deploy(w http.ResponseWriter, r *http.Request) {
	slug, token, ok := request(r, w)
	if !ok {
		return
	}
	allowed, err := a.anyRole(r, token, "deploy.global-admin", "deploy.developer", appAdminRole(slug))
	respondDecision(w, allowed, err)
}

func (a deploymentApp) deleteApp(w http.ResponseWriter, r *http.Request) {
	slug, token, ok := request(r, w)
	if !ok {
		return
	}
	allowed, err := a.anyRole(r, token, "deploy.global-admin", appAdminRole(slug))
	respondDecision(w, allowed, err)
}

func (a deploymentApp) anyRole(r *http.Request, token string, roles ...string) (bool, error) {
	for _, role := range roles {
		allowed, err := a.checker.HasRole(r.Context(), token, role)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

func request(r *http.Request, w http.ResponseWriter) (string, string, bool) {
	slug := chi.URLParam(r, "slug")
	if !appSlugPattern.MatchString(slug) || slug != strings.ToLower(slug) {
		http.Error(w, "invalid app slug", http.StatusBadRequest)
		return "", "", false
	}
	token, err := authz.BearerToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return "", "", false
	}
	return slug, token, true
}

func respondDecision(w http.ResponseWriter, allowed bool, err error) {
	if err != nil {
		http.Error(w, "authorization service unavailable", http.StatusServiceUnavailable)
		return
	}
	if !allowed {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func appAdminRole(slug string) string { return "deploy.app." + slug + ".admin" }
