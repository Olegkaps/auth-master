package main

import (
	"encoding/json"
	"io"
	"net/http"

	exampleui "github.com/olegkapshai/auth-master/examples/internal/ui"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func supportHTTPHandler(connection grpc.ClientConnInterface, stores ...*ticketStore) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(supportPage))
	})
	mux.HandleFunc("POST /rpc", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var input struct{ Method, AccessToken, Body, TicketID, FixtureKey string }
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		fields := map[string]any{"access_token": input.AccessToken}
		method := input.Method
		switch method {
		case "CreateTicket":
			fields["body"] = input.Body
			if input.FixtureKey != "" {
				fields["fixture_key"] = input.FixtureKey
			}
		case "GetTicket":
			fields["ticket_id"] = input.TicketID
		default:
			http.Error(w, "invalid method", http.StatusBadRequest)
			return
		}
		message, err := structpb.NewStruct(fields)
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		output := new(structpb.Struct)
		err = connection.Invoke(r.Context(), "/"+supportServiceName+"/"+method, message, output)
		if err != nil {
			code := status.Code(err)
			httpStatus := http.StatusServiceUnavailable
			switch code {
			case codes.Unauthenticated:
				httpStatus = http.StatusUnauthorized
			case codes.PermissionDenied:
				httpStatus = http.StatusForbidden
			case codes.InvalidArgument:
				httpStatus = http.StatusBadRequest
			case codes.NotFound:
				httpStatus = http.StatusNotFound
			}
			http.Error(w, code.String(), httpStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(output.AsMap())
	})
	mux.HandleFunc("GET /demo/tickets", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		values := []ticket{}
		if len(stores) > 0 && stores[0] != nil {
			values = stores[0].seededTickets()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tickets": values})
	})
	return mux
}

var supportPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Support desk authorization example</title><style id="examples-ui">` + exampleui.Styles + `</style></head><body>
<main class="page-shell" data-ui="page-shell"><header class="page-header"><p class="eyebrow">gRPC plus local ownership</p><h1>Support desk authorization</h1><p class="page-description">Use the seeded personas to compare ticket ownership with agent and administrator access.</p></header>
<section class="card compact-card" data-ui="card" data-testid="personas-card"><h2>Ready-to-use personas</h2><p class="card-help">All accounts use <code>Example!Passw0rd9</code>. Print a fresh real human token with <code>make -C examples token EXAMPLE=support-desk PERSONA=&lt;key&gt;</code>.</p>
<ul><li><strong>owner</strong> — <code>support-owner</code>: create and read own tickets</li><li><strong>agent</strong> — <code>support-agent</code>: read every ticket</li><li><strong>admin</strong> — <code>support-admin</code>: read every ticket</li><li><strong>stranger</strong> — <code>support-stranger</code>: other users' tickets are denied</li></ul></section>
<section class="card compact-card" data-ui="card" data-testid="support-card"><h2>Ticket request</h2><p class="card-help">A seeded owner ticket is selected automatically. Creating a ticket also selects its UUID.</p>
<div class="field-grid"><label class="field span-all">Access token <input class="token-field" data-testid="token" autocomplete="off"></label>
<label class="field">Ticket description <textarea data-testid="body" placeholder="Describe the issue"></textarea></label>
<label class="field">Ticket UUID <input data-testid="ticket-id" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></label></div>
<div class="actions"><button data-testid="create">Create ticket</button><button class="secondary" data-testid="get">Get ticket</button></div>
<p class="result-label">Result</p><output class="result" data-testid="result" aria-live="polite"></output></section></main><script>
const q=s=>document.querySelector(s),result=q('[data-testid=result]'),buttons=[q('[data-testid=create]'),q('[data-testid=get]')];
function message(status,method,text){if(status===401)return'Session missing or expired — print a fresh persona token.';if(status===403)return'Denied — this persona does not own the ticket and lacks support.agent/support.admin.';if(status===404)return'Ticket not found.';if(status===503)return'Authentication service unavailable — retry after auth-master recovers.';return'Request failed ('+status+'): '+text.trim()}
async function call(method){result.textContent='Working…';buttons.forEach(b=>b.disabled=true);try{const r=await fetch('/rpc',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({Method:method,AccessToken:q('[data-testid=token]').value,Body:q('[data-testid=body]').value,TicketID:q('[data-testid=ticket-id]').value})});const text=await r.text();if(!r.ok){result.textContent=message(r.status,method,text);return}const value=JSON.parse(text);if(method==='CreateTicket'){q('[data-testid=ticket-id]').value=value.id;result.textContent='Created ticket '+value.id+' — it is now selected.'}else{result.textContent='Allowed — '+value.body+' (owner '+value.owner_id+').'}}catch(error){result.textContent='Network error — '+error.message}finally{buttons.forEach(b=>b.disabled=false)}}
q('[data-testid=create]').onclick=()=>call('CreateTicket');q('[data-testid=get]').onclick=()=>call('GetTicket');
fetch('/demo/tickets').then(r=>r.json()).then(v=>{if(v.tickets&&v.tickets[0])q('[data-testid=ticket-id]').value=v.tickets[0].id}).catch(()=>{});
</script></body></html>`
