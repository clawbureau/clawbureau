function esc(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function bountyUiDuelPage(params: {
  origin: string;
  environment: string;
  version: string;
  defaultWorkerDid: string;
}): string {
  const origin = esc(params.origin);
  const environment = esc(params.environment);
  const version = esc(params.version);
  const defaultWorkerDid = esc(params.defaultWorkerDid);

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Clawbounties Duel — Browse, Claim, Submit</title>
    <style>
      *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
      :root{
        color-scheme:dark;
        --c-bg:#090f1a;
        --c-surface:#0f1729;
        --c-surface-raised:#141e33;
        --c-surface-hover:#192640;
        --c-border:#1e2d4a;
        --c-border-active:#2d6cdf;
        --c-text:#e2e8f3;
        --c-text-muted:#8899b4;
        --c-text-dim:#5d6f8a;
        --c-accent:#3b82f6;
        --c-accent-soft:rgba(59,130,246,.12);
        --c-teal:#2dd4bf;
        --c-teal-soft:rgba(45,212,191,.10);
        --c-green:#34d399;
        --c-amber:#fbbf24;
        --c-red:#f87171;
        --c-purple:#a78bfa;
        --radius:10px;
        --radius-lg:14px;
        --font-mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;
        --transition:150ms ease;
      }
      html{-webkit-text-size-adjust:100%}
      body{
        font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
        background:var(--c-bg);
        color:var(--c-text);
        line-height:1.5;
        min-height:100vh;
      }
      a{color:var(--c-accent);text-decoration:none}
      a:hover{text-decoration:underline}
      .sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
      .layout{max-width:1280px;margin:0 auto;padding:24px 20px 48px}
      header{
        display:flex;align-items:center;gap:14px;
        padding:16px 20px;
        border-bottom:1px solid var(--c-border);
        background:var(--c-surface);
      }
      header .logo{
        display:flex;align-items:center;gap:10px;
        font-weight:700;font-size:1.1rem;letter-spacing:-.02em;
      }
      header .logo svg{flex-shrink:0}
      header nav{margin-left:auto;display:flex;gap:16px;font-size:.85rem}
      header nav a{color:var(--c-text-muted)}
      header nav a:hover{color:var(--c-text)}
      .env-badge{
        display:inline-flex;align-items:center;gap:4px;
        padding:2px 10px;border-radius:999px;
        font-size:.72rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;
        background:var(--c-accent-soft);color:var(--c-accent);border:1px solid rgba(59,130,246,.2);
      }
      .page-title{font-size:1.35rem;font-weight:700;letter-spacing:-.025em;margin:20px 0 4px}
      .page-desc{color:var(--c-text-muted);font-size:.88rem;margin-bottom:20px;max-width:680px}
      .grid-main{
        display:grid;
        grid-template-columns:340px 1fr;
        gap:16px;
        align-items:start;
      }
      @media(max-width:900px){.grid-main{grid-template-columns:1fr}}
      .card{
        background:var(--c-surface);
        border:1px solid var(--c-border);
        border-radius:var(--radius-lg);
        overflow:hidden;
      }
      .card-header{
        display:flex;align-items:center;justify-content:space-between;
        padding:14px 16px;border-bottom:1px solid var(--c-border);
      }
      .card-header h2{font-size:.88rem;font-weight:600;letter-spacing:-.01em}
      .card-body{padding:16px}
      .field{margin-bottom:14px}
      .field label{
        display:block;font-size:.75rem;font-weight:600;
        color:var(--c-text-muted);text-transform:uppercase;letter-spacing:.05em;
        margin-bottom:6px;
      }
      .field input{
        width:100%;padding:10px 12px;
        border:1px solid var(--c-border);border-radius:var(--radius);
        background:var(--c-surface-raised);color:var(--c-text);
        font-size:.88rem;font-family:inherit;
        transition:border-color var(--transition);
        outline:none;
      }
      .field input:focus{border-color:var(--c-accent);box-shadow:0 0 0 3px var(--c-accent-soft)}
      .field input::placeholder{color:var(--c-text-dim)}
      .btn-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px}
      button{
        cursor:pointer;border:1px solid var(--c-border);
        border-radius:var(--radius);padding:10px 14px;
        font-size:.82rem;font-weight:600;font-family:inherit;
        background:var(--c-surface-raised);color:var(--c-text);
        transition:background var(--transition),border-color var(--transition);
        outline:none;
      }
      button:hover{background:var(--c-surface-hover);border-color:var(--c-text-dim)}
      button:focus-visible{box-shadow:0 0 0 3px var(--c-accent-soft);border-color:var(--c-accent)}
      button:active{transform:scale(.98)}
      .btn-primary{background:var(--c-accent);color:#fff;border-color:var(--c-accent)}
      .btn-primary:hover{background:#2563eb;border-color:#2563eb}
      .status-box{
        min-height:52px;padding:10px 12px;
        border:1px solid var(--c-border);border-radius:var(--radius);
        background:var(--c-bg);
        font-family:var(--font-mono);font-size:.76rem;
        color:var(--c-text-muted);white-space:pre-wrap;word-break:break-word;
        overflow:auto;max-height:180px;
      }
      .bounty-list{display:flex;flex-direction:column;gap:6px;max-height:520px;overflow-y:auto;padding:2px}
      .bounty-list::-webkit-scrollbar{width:6px}
      .bounty-list::-webkit-scrollbar-track{background:transparent}
      .bounty-list::-webkit-scrollbar-thumb{background:var(--c-border);border-radius:3px}
      .bounty-row{
        display:block;width:100%;text-align:left;
        padding:12px 14px;
        border:1px solid var(--c-border);border-radius:var(--radius);
        background:var(--c-surface-raised);
        transition:border-color var(--transition),background var(--transition);
        cursor:pointer;
      }
      .bounty-row:hover{background:var(--c-surface-hover);border-color:var(--c-text-dim)}
      .bounty-row[aria-selected="true"]{
        border-color:var(--c-accent);
        background:var(--c-accent-soft);
        box-shadow:0 0 0 1px rgba(59,130,246,.2);
      }
      .bounty-row .title{font-size:.88rem;font-weight:600;margin-bottom:4px;line-height:1.3}
      .bounty-row .meta{display:flex;align-items:center;justify-content:space-between;gap:8px}
      .bounty-row .reward{font-size:.82rem;color:var(--c-teal);font-weight:600;font-family:var(--font-mono)}
      .pill{
        display:inline-flex;align-items:center;padding:2px 9px;
        border-radius:999px;font-size:.7rem;font-weight:600;letter-spacing:.03em;
        text-transform:uppercase;
      }
      .pill-open{background:rgba(52,211,153,.12);color:var(--c-green);border:1px solid rgba(52,211,153,.2)}
      .pill-accepted{background:rgba(59,130,246,.12);color:var(--c-accent);border:1px solid rgba(59,130,246,.2)}
      .pill-pending{background:rgba(251,191,36,.10);color:var(--c-amber);border:1px solid rgba(251,191,36,.2)}
      .pill-other{background:rgba(167,139,250,.10);color:var(--c-purple);border:1px solid rgba(167,139,250,.2)}
      .empty-state{
        text-align:center;padding:32px 16px;
        color:var(--c-text-dim);font-size:.88rem;
      }
      .detail-section{margin-top:16px}
      .detail-section .card-body{padding:0}
      .detail-grid{
        display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));
        gap:1px;background:var(--c-border);
      }
      .detail-cell{background:var(--c-surface);padding:14px 16px}
      .detail-cell .label{
        font-size:.72rem;font-weight:600;text-transform:uppercase;
        letter-spacing:.05em;color:var(--c-text-dim);margin-bottom:4px;
      }
      .detail-cell .value{
        font-size:.88rem;font-family:var(--font-mono);
        word-break:break-all;color:var(--c-text);
      }
      .detail-placeholder{
        padding:40px 16px;text-align:center;color:var(--c-text-dim);font-size:.88rem;
      }
    </style>
  </head>
  <body>
    <header>
      <div class="logo" aria-label="Clawbounties">
        <svg width="26" height="26" viewBox="0 0 26 26" fill="none" aria-hidden="true">
          <rect width="26" height="26" rx="6" fill="#3b82f6" fill-opacity=".15"/>
          <path d="M8 13.5L11.5 17L18 9.5" stroke="#3b82f6" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <span>Clawbounties</span>
      </div>
      <span class="env-badge">${environment}</span>
      <nav aria-label="Service links">
        <a href="${origin}/docs">Docs</a>
        <a href="${origin}/health">Health</a>
      </nav>
    </header>
    <main class="layout">
      <h1 class="page-title">Duel Workbench</h1>
      <p class="page-desc">Operator surface for the UI duel contract. Browse open bounties, inspect details, claim and submit against live APIs. Version ${version}.</p>

      <div class="grid-main">
        <aside>
          <div class="card">
            <div class="card-header"><h2>Control Plane</h2></div>
            <div class="card-body">
              <div class="field">
                <label for="adminKey">Admin Key</label>
                <input id="adminKey" type="password" autocomplete="off" placeholder="BOUNTIES_ADMIN_KEY" />
              </div>
              <div class="field">
                <label for="workerDid">Worker DID</label>
                <input id="workerDid" type="text" value="${defaultWorkerDid}" autocomplete="off" />
              </div>
              <div class="btn-grid">
                <button id="loadBounties" class="btn-primary" type="button">Load Bounties</button>
                <button id="seedBounties" type="button">Seed if Empty</button>
                <button id="claimBounty" class="btn-primary" type="button">Claim Selected</button>
                <button id="submitBounty" class="btn-primary" type="button">Submit Selected</button>
              </div>
              <div id="actionStatus" class="status-box" role="status" aria-live="polite">Ready.</div>
            </div>
          </div>
        </aside>

        <section aria-label="Bounty browser">
          <div class="card">
            <div class="card-header">
              <h2>Open Bounties</h2>
              <span id="bountyCount" class="pill pill-other" hidden>0</span>
            </div>
            <div class="card-body">
              <div id="bountyList" class="bounty-list" role="listbox" aria-label="Bounties"></div>
              <p id="bountyListEmpty" class="empty-state" hidden>No open bounties found. Use <strong>Seed if Empty</strong> to create some.</p>
            </div>
          </div>
        </section>
      </div>

      <section class="detail-section" aria-label="Bounty details">
        <div class="card">
          <div class="card-header"><h2>Selected Bounty Details</h2></div>
          <div id="bountyDetails" class="detail-placeholder">Select a bounty above to view its details.</div>
        </div>
      </section>
    </main>

    <script>
      (function(){
        "use strict";
        var state={selectedBountyId:null,bounties:[]};

        var els={
          adminKey:document.getElementById("adminKey"),
          workerDid:document.getElementById("workerDid"),
          loadBounties:document.getElementById("loadBounties"),
          seedBounties:document.getElementById("seedBounties"),
          claimBounty:document.getElementById("claimBounty"),
          submitBounty:document.getElementById("submitBounty"),
          bountyList:document.getElementById("bountyList"),
          bountyListEmpty:document.getElementById("bountyListEmpty"),
          bountyDetails:document.getElementById("bountyDetails"),
          actionStatus:document.getElementById("actionStatus"),
          bountyCount:document.getElementById("bountyCount")
        };

        function stableStringify(v){
          if(v===null||typeof v!=="object")return JSON.stringify(v);
          if(Array.isArray(v))return "["+v.map(stableStringify).join(",")+"]";
          var keys=Object.keys(v).sort();
          return "{"+keys.map(function(k){return JSON.stringify(k)+":"+stableStringify(v[k])}).join(",")+"}";
        }

        function setStatus(msg,payload){
          var text=typeof payload==="undefined"?String(msg):String(msg)+"\\n"+JSON.stringify(payload,null,2);
          if(els.actionStatus)els.actionStatus.textContent=text;
        }

        function adminKey(){
          return(els.adminKey&&typeof els.adminKey.value==="string")?els.adminKey.value.trim():"";
        }

        function api(path,init){
          var key=adminKey();
          if(!key)return Promise.reject(new Error("Admin key is required."));
          init=init||{};
          var h=new Headers(init.headers||{});
          h.set("x-admin-key",key);
          if(!h.has("content-type")&&init.body)h.set("content-type","application/json");
          return fetch(path,Object.assign({},init,{headers:h})).then(function(res){
            return res.text().then(function(text){
              var json;
              try{json=JSON.parse(text)}catch(e){json={raw:text}}
              if(!res.ok)throw new Error("HTTP "+res.status+": "+JSON.stringify(json));
              return json;
            });
          });
        }

        function pillClass(status){
          if(status==="open")return "pill-open";
          if(status==="accepted")return "pill-accepted";
          if(status==="pending_review")return "pill-pending";
          return "pill-other";
        }

        function formatMinor(amount,currency){
          if(!amount)return "-";
          var n=parseInt(amount,10);
          if(isNaN(n))return amount+" "+(currency||"");
          return "$"+(n/100).toFixed(2);
        }

        function renderBountyList(){
          if(!els.bountyList||!els.bountyListEmpty)return;
          els.bountyList.innerHTML="";

          if(!Array.isArray(state.bounties)||state.bounties.length===0){
            els.bountyListEmpty.hidden=false;
            if(els.bountyCount)els.bountyCount.hidden=true;
            return;
          }

          els.bountyListEmpty.hidden=true;
          if(els.bountyCount){
            els.bountyCount.textContent=String(state.bounties.length);
            els.bountyCount.hidden=false;
          }

          state.bounties.forEach(function(b){
            var row=document.createElement("button");
            row.type="button";
            row.className="bounty-row";
            row.setAttribute("role","option");
            row.setAttribute("data-testid","bounty-row");
            row.dataset.testid="bounty-row";
            row.dataset.bountyId=b.bounty_id;
            row.setAttribute("aria-selected",state.selectedBountyId===b.bounty_id?"true":"false");

            var title=document.createElement("div");
            title.className="title";
            title.textContent=b.title||b.bounty_id;
            row.appendChild(title);

            var meta=document.createElement("div");
            meta.className="meta";

            var reward=document.createElement("span");
            reward.className="reward";
            reward.textContent=formatMinor(b.reward&&b.reward.amount_minor,b.reward&&b.reward.currency);
            meta.appendChild(reward);

            var pill=document.createElement("span");
            pill.className="pill "+pillClass(b.status||"");
            pill.textContent=b.status||"unknown";
            meta.appendChild(pill);

            row.appendChild(meta);

            row.addEventListener("click",function(){
              state.selectedBountyId=b.bounty_id;
              renderBountyList();
              loadDetails();
            });

            els.bountyList.appendChild(row);
          });
        }

        function renderDetails(detail){
          if(!els.bountyDetails)return;
          if(!detail){
            els.bountyDetails.className="detail-placeholder";
            els.bountyDetails.textContent="Select a bounty above to view its details.";
            return;
          }
          els.bountyDetails.className="";
          var tags=Array.isArray(detail.tags)?detail.tags.join(", "):"";
          var data=[
            ["Bounty ID",detail.bounty_id],
            ["Status",detail.status],
            ["Requester DID",detail.requester_did],
            ["Worker DID",detail.worker_did||"(unassigned)"],
            ["Reward",formatMinor(detail.reward&&detail.reward.amount_minor,detail.reward&&detail.reward.currency)],
            ["Closure Type",detail.closure_type],
            ["Min Proof Tier",detail.min_proof_tier],
            ["Tags",tags||"(none)"]
          ];
          var html='<div class="detail-grid">';
          for(var i=0;i<data.length;i++){
            html+='<div class="detail-cell"><div class="label">'+data[i][0]+'</div><div class="value">'+(data[i][1]||"-")+"</div></div>";
          }
          html+="</div>";
          els.bountyDetails.innerHTML=html;
        }

        function loadOpenBounties(){
          setStatus("Loading open bounties...");
          return api("/v1/bounties?status=open&is_code_bounty=false&limit=50").then(function(payload){
            state.bounties=Array.isArray(payload.bounties)?payload.bounties:[];
            if(state.selectedBountyId&&!state.bounties.some(function(b){return b.bounty_id===state.selectedBountyId})){
              state.selectedBountyId=null;
            }
            if(!state.selectedBountyId&&state.bounties.length>0){
              state.selectedBountyId=state.bounties[0].bounty_id;
            }
            renderBountyList();
            return loadDetails().then(function(){
              setStatus("Loaded "+state.bounties.length+" open bounties.",{count:state.bounties.length,selected_bounty_id:state.selectedBountyId});
            });
          });
        }

        function loadDetails(){
          if(!state.selectedBountyId){renderDetails(null);return Promise.resolve()}
          return api("/v1/bounties/"+encodeURIComponent(state.selectedBountyId)).then(function(d){renderDetails(d)});
        }

        function seedIfEmpty(){
          setStatus("Seeding bounties if below target...");
          return api("/v1/arena/desk/discover-loop",{
            method:"POST",
            body:stableStringify({target_open_bounties:4,seed_limit:4,seed_reward_minor:"25",dry_run:false})
          }).then(function(payload){
            setStatus("Discovery loop completed.",payload.totals||payload);
            return loadOpenBounties();
          });
        }

        function selectedBountyIds(){
          if(!state.selectedBountyId)throw new Error("Select a bounty first.");
          return[state.selectedBountyId];
        }

        function claimSelected(){
          var did=(els.workerDid&&typeof els.workerDid.value==="string")?els.workerDid.value.trim():"";
          if(!did.startsWith("did:"))throw new Error("Worker DID must start with did:");
          return api("/v1/arena/desk/claim-loop",{
            method:"POST",
            body:stableStringify({limit:12,target_claims:1,budget_minor:"1000000",bounty_ids:selectedBountyIds(),requested_worker_did:did,max_fleet_cost_tier:"high",max_fleet_risk_tier:"high",allow_route_fallback:true,include_code_bounties:false,dry_run:false})
          }).then(function(payload){
            setStatus("Claim loop completed.",payload.totals||payload);
            return loadDetails().then(function(){return loadOpenBounties()});
          });
        }

        function submitSelected(){
          var did=(els.workerDid&&typeof els.workerDid.value==="string")?els.workerDid.value.trim():"";
          if(!did.startsWith("did:"))throw new Error("Worker DID must start with did:");
          return api("/v1/arena/desk/submit-loop",{
            method:"POST",
            body:stableStringify({worker_did:did,target_submissions:1,limit:10,bounty_ids:selectedBountyIds(),dry_run:false})
          }).then(function(payload){
            setStatus("Submit loop completed.",payload.totals||payload);
            return loadDetails();
          });
        }

        function withGuard(label,fn){
          try{
            setStatus(label+"...");
            var result=fn();
            if(result&&typeof result.then==="function"){
              result.catch(function(err){
                setStatus(label+" failed.",{error:err instanceof Error?err.message:String(err)});
              });
            }
          }catch(err){
            setStatus(label+" failed.",{error:err instanceof Error?err.message:String(err)});
          }
        }

        if(els.loadBounties)els.loadBounties.addEventListener("click",function(){withGuard("Load bounties",loadOpenBounties)});
        if(els.seedBounties)els.seedBounties.addEventListener("click",function(){withGuard("Seed bounties",seedIfEmpty)});
        if(els.claimBounty)els.claimBounty.addEventListener("click",function(){withGuard("Claim bounty",claimSelected)});
        if(els.submitBounty)els.submitBounty.addEventListener("click",function(){withGuard("Submit bounty",submitSelected)});
      })();
    </script>
  </body>
</html>`;
}
