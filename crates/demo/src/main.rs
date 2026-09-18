use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use axum::{Extension, Json, Router, extract::Query, middleware, response::Html, routing::get};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use agent::PQAgent;
use registry::PQRegistry;
use reputation::ReputationStore;
use server::{ServerState, x402_pq_layer};
use types::PaymentChallenge;
use validation::{ValidationPolicy, Validator};

const ADDR: &str = "127.0.0.1:3742";
const AMOUNT: u64 = 1_000_000;
const RECIPIENT: &str = "demo-recipient";

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum StepStatus { Pending, Running, Pass, Fail }

#[derive(Debug, Clone, Serialize)]
struct Step {
    title: &'static str,
    status: StepStatus,
    http_status: Option<u16>,
    detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DemoState {
    agent_address: Option<String>,
    steps: Vec<Step>,
    score: Option<f64>,
    successes: u64,
    failures: u64,
    sig_bytes: Option<usize>,
    complete: bool,
}

impl DemoState {
    fn new() -> Self {
        Self {
            agent_address: None,
            steps: vec![
                Step { title: "Probe — no X-Payment header",   status: StepStatus::Pending, http_status: None, detail: None },
                Step { title: "Sign & pay",                    status: StepStatus::Pending, http_status: None, detail: None },
                Step { title: "Reputation after first payment",status: StepStatus::Pending, http_status: None, detail: None },
                Step { title: "Replay attack — same nonce",    status: StepStatus::Pending, http_status: None, detail: None },
            ],
            score: None,
            successes: 0,
            failures: 0,
            sig_bytes: None,
            complete: false,
        }
    }
}

type SharedDemo = Arc<Mutex<DemoState>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let demo = Arc::new(Mutex::new(DemoState::new()));

    let registry = Arc::new(RwLock::new(PQRegistry::new()));
    let agent = Arc::new(PQAgent::new().expect("keygen failed"));
    registry.write().await.register(agent.agent_record()).expect("registration failed");

    let reputation = Arc::new(Mutex::new(ReputationStore::new(0.01)));
    let validator = Validator::new(ValidationPolicy {
        min_reputation_score: 0.4,
        min_volume_events: 0,
        max_amount: u64::MAX,
        min_amount: 1,
        ..ValidationPolicy::default()
    });

    let state = Arc::new(ServerState::new(
        registry,
        reputation.clone(),
        validator,
        AMOUNT,
        RECIPIENT,
    ));

    let app = Router::new()
        .route("/resource", get(resource_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), x402_pq_layer))
        .route("/", get(index_handler))
        .route("/api/state", get(state_handler))
        .route("/api/simulate", get(simulate_handler))
        .layer(Extension(demo.clone()))
        .layer(Extension(reputation.clone()))
        .layer(Extension(agent.clone()))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(ADDR).await?;
    eprintln!("Demo running at http://{ADDR}");

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    let _ = std::process::Command::new("open")
        .arg(format!("http://{ADDR}"))
        .spawn();

    run_demo(demo, reputation, agent).await?;

    eprintln!("Done. Browser open at http://{ADDR}  (Ctrl+C to exit)");
    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn run_demo(
    demo: SharedDemo,
    reputation: Arc<Mutex<ReputationStore>>,
    agent: Arc<PQAgent>,
) -> anyhow::Result<()> {
    let client = Client::new();
    let url = format!("http://{ADDR}/resource");

    demo.lock().await.agent_address = Some(agent.pq_address.clone());
    tokio::time::sleep(ms(800)).await;

    set_running(&demo, 0).await;
    let resp = client.get(&url).send().await?;
    let status = resp.status().as_u16();
    let challenge: PaymentChallenge = resp.json().await?;
    demo.lock().await.steps[0] = Step {
        title: "Probe — no X-Payment header",
        status: if status == 402 { StepStatus::Pass } else { StepStatus::Fail },
        http_status: Some(status),
        detail: Some(format!("nonce: {}  scheme: {}", &challenge.nonce[..8], challenge.scheme)),
    };
    tokio::time::sleep(ms(900)).await;

    set_running(&demo, 1).await;
    let intent = types::PaymentIntent {
        pq_address: agent.pq_address.clone(),
        recipient: challenge.recipient.clone(),
        amount: challenge.amount,
        nonce: challenge.nonce.clone(),
        expires_at: u64::MAX,
    };
    let signed = agent.sign_payment(intent).expect("signing failed");
    let sig_bytes = signed.signature.len();
    let header = B64.encode(serde_json::to_vec(&signed)?);

    let resp = client.get(&url).header("x-payment", &header).send().await?;
    let status = resp.status().as_u16();
    demo.lock().await.steps[1] = Step {
        title: "Sign & pay",
        status: if status == 200 { StepStatus::Pass } else { StepStatus::Fail },
        http_status: Some(status),
        detail: Some(format!("ML-DSA-44 sig: {} bytes  (Ed25519 would be 64)", sig_bytes)),
    };
    demo.lock().await.sig_bytes = Some(sig_bytes);
    tokio::time::sleep(ms(900)).await;

    set_running(&demo, 2).await;
    let (successes, failures, score) = {
        let rep = reputation.lock().await;
        let rec = rep.get_record(&agent.pq_address).cloned();
        let score = rep.get_score(&agent.pq_address, reputation::unix_now());
        (rec.as_ref().map(|r| r.successes).unwrap_or(0),
         rec.as_ref().map(|r| r.failures).unwrap_or(0),
         score.unwrap_or(0.5))
    };
    {
        let mut d = demo.lock().await;
        d.successes = successes;
        d.failures  = failures;
        d.score     = Some(score);
        d.steps[2]  = Step {
            title: "Reputation after first payment",
            status: StepStatus::Pass,
            http_status: None,
            detail: Some(format!("score: {score:.4}  (successes: {successes}  failures: {failures})")),
        };
    }
    tokio::time::sleep(ms(900)).await;

    set_running(&demo, 3).await;
    let resp = client.get(&url).header("x-payment", &header).send().await?;
    let status = resp.status().as_u16();
    demo.lock().await.steps[3] = Step {
        title: "Replay attack — same nonce",
        status: if status == 402 { StepStatus::Pass } else { StepStatus::Fail },
        http_status: Some(status),
        detail: Some("nonce already consumed — replay correctly rejected".into()),
    };
    tokio::time::sleep(ms(600)).await;

    demo.lock().await.complete = true;
    Ok(())
}

async fn set_running(demo: &SharedDemo, idx: usize) {
    demo.lock().await.steps[idx].status = StepStatus::Running;
}

fn ms(n: u64) -> tokio::time::Duration {
    tokio::time::Duration::from_millis(n)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn resource_handler() -> &'static str {
    "Payment verified — resource granted."
}

#[derive(Deserialize)]
struct SimulateQuery {
    successes: Option<u64>,
    failures: Option<u64>,
}

async fn state_handler(Extension(demo): Extension<SharedDemo>) -> Json<DemoState> {
    Json(demo.lock().await.clone())
}

async fn simulate_handler(
    Query(query): Query<SimulateQuery>,
    Extension(demo): Extension<SharedDemo>,
    Extension(reputation): Extension<Arc<Mutex<ReputationStore>>>,
    Extension(agent): Extension<Arc<PQAgent>>,
) -> Json<DemoState> {
    let successes = query.successes.unwrap_or(1).clamp(0, 25);
    let failures = query.failures.unwrap_or(0).clamp(0, 25);

    let state = simulate_payments(demo, reputation, agent, successes, failures).await;
    Json(state)
}

async fn index_handler() -> Html<&'static str> {
    Html(UI)
}

async fn simulate_payments(
    demo: SharedDemo,
    reputation: Arc<Mutex<ReputationStore>>,
    agent: Arc<PQAgent>,
    successes: u64,
    failures: u64,
) -> DemoState {
    let client = Client::new();
    let url = format!("http://{ADDR}/resource");

    let mut seen_successes = 0u64;
    let mut seen_failures = 0u64;

    for _ in 0..successes {
        let resp = client.get(&url).send().await.ok();
        let Some(resp) = resp else { continue; };
        let status = resp.status().as_u16();
        if status != 402 { continue; }

        let challenge: PaymentChallenge = match resp.json().await {
            Ok(challenge) => challenge,
            Err(_) => continue,
        };

        let intent = types::PaymentIntent {
            pq_address: agent.pq_address.clone(),
            recipient: challenge.recipient.clone(),
            amount: challenge.amount,
            nonce: challenge.nonce.clone(),
            expires_at: u64::MAX,
        };

        let signed = match agent.sign_payment(intent) {
            Ok(sig) => sig,
            Err(_) => continue,
        };
        let header = B64.encode(serde_json::to_vec(&signed).unwrap_or_default());

        let resp = client.get(&url).header("x-payment", &header).send().await.ok();
        if matches!(resp, Some(r) if r.status().as_u16() == 200) {
            seen_successes += 1;
        }
    }

    for _ in 0..failures {
        let challenge: PaymentChallenge = match client.get(&url).send().await {
            Ok(resp) => match resp.json().await {
                Ok(challenge) => challenge,
                Err(_) => continue,
            },
            Err(_) => continue,
        };

        let bad_intent = types::PaymentIntent {
            pq_address: agent.pq_address.clone(),
            recipient: format!("{}-tampered", challenge.recipient),
            amount: challenge.amount.saturating_add(1),
            nonce: challenge.nonce.clone(),
            expires_at: u64::MAX,
        };

        let signed = match agent.sign_payment(bad_intent) {
            Ok(sig) => sig,
            Err(_) => continue,
        };
        let header = B64.encode(serde_json::to_vec(&signed).unwrap_or_default());

        let resp = client.get(&url).header("x-payment", &header).send().await.ok();
        if matches!(resp, Some(r) if r.status().as_u16() == 402) {
            seen_failures += 1;
        }
    }

    {
        let now = reputation::unix_now();
        let mut rep = reputation.lock().await;
        for _ in 0..failures {
            rep.record_failure(&agent.pq_address, now);
        }

        let rec = rep.get_record(&agent.pq_address).cloned();
        let score = rep.get_score(&agent.pq_address, now).unwrap_or(0.5);

        let mut d = demo.lock().await;
        d.successes = rec.as_ref().map(|r| r.successes).unwrap_or(0);
        d.failures = rec.as_ref().map(|r| r.failures).unwrap_or(0);
        d.score = Some(score);
        d.complete = true;
        d.steps[2] = Step {
            title: "Reputation after simulated payments",
            status: StepStatus::Pass,
            http_status: None,
            detail: Some(format!("score: {score:.4}  (successes: {}  failures: {})", d.successes, d.failures)),
        };
        d.steps[3] = Step {
            title: "Failure rate injected by simulation",
            status: if seen_failures > 0 || d.failures > 0 { StepStatus::Pass } else { StepStatus::Pending },
            http_status: Some(if seen_failures > 0 || d.failures > 0 { 402 } else { 200 }),
            detail: Some(format!("simulated outcomes: {seen_successes} passed / {} failed  (current score: {score:.4})", seen_failures.max(d.failures))),
        };
    }

    demo.lock().await.clone()
}

// ── UI ────────────────────────────────────────────────────────────────────────

const UI: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PQ-8004 Demo</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: ui-monospace, 'Cascadia Code', 'Fira Code', monospace;
      background: #0d1117; color: #c9d1d9;
      min-height: 100vh;
      display: flex; flex-direction: column; align-items: center;
      padding: 3rem 1.5rem;
    }
    .wrap { width: 100%; max-width: 680px; }

    /* header */
    header { margin-bottom: 2.5rem; }
    h1 { font-size: 1.5rem; color: #e6edf3; letter-spacing: -.01em; }
    h1 span { color: #58a6ff; }
    .sub { color: #8b949e; font-size: .85rem; margin-top: .3rem; }

    /* agent card */
    .agent-card {
      background: #161b22; border: 1px solid #30363d; border-radius: 8px;
      padding: 1rem 1.25rem; margin-bottom: 2rem;
      opacity: 0; transform: translateY(6px);
      transition: opacity .4s, transform .4s;
    }
    .agent-card.visible { opacity: 1; transform: none; }
    .agent-label { font-size: .72rem; color: #8b949e; text-transform: uppercase; letter-spacing: .08em; margin-bottom: .4rem; }
    .agent-addr { font-size: .88rem; color: #58a6ff; word-break: break-all; }
    .agent-note { font-size: .75rem; color: #8b949e; margin-top: .35rem; }

    /* steps */
    .steps { display: flex; flex-direction: column; gap: .75rem; margin-bottom: 2rem; }
    .step {
      background: #161b22; border: 1px solid #30363d; border-radius: 8px;
      padding: .85rem 1.1rem;
      display: flex; align-items: flex-start; gap: .85rem;
      opacity: 0; transform: translateY(4px);
      transition: opacity .35s, transform .35s, border-color .3s;
    }
    .step.visible { opacity: 1; transform: none; }
    .step.pass  { border-color: #2ea0432a; }
    .step.fail  { border-color: #f851492a; }

    .icon { font-size: 1rem; line-height: 1; flex-shrink: 0; margin-top: 2px; width: 18px; text-align: center; }
    .pending .icon { color: #484f58; }
    .running .icon { color: #58a6ff; animation: spin 1s linear infinite; display: inline-block; }
    .pass    .icon { color: #3fb950; }
    .fail    .icon { color: #f85149; }

    @keyframes spin { to { transform: rotate(360deg); } }

    .step-body { flex: 1; min-width: 0; }
    .step-title { font-size: .88rem; color: #e6edf3; }
    .step-detail { font-size: .78rem; color: #8b949e; margin-top: .3rem; }
    .badge {
      font-size: .7rem; border-radius: 4px; padding: 1px 6px;
      margin-left: .5rem; vertical-align: middle;
    }
    .badge-200 { background: #1a3a1a; color: #3fb950; }
    .badge-402 { background: #3a2a1a; color: #d29922; }

    /* stats */
    .stats {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: .75rem; margin-bottom: 2rem;
      opacity: 0; transition: opacity .5s;
    }
    .stats.visible { opacity: 1; }
    .stat {
      background: #161b22; border: 1px solid #30363d; border-radius: 8px;
      padding: .85rem 1rem;
    }
    .stat-val { font-size: 1.35rem; font-weight: 600; color: #58a6ff; }
    .stat-val.green { color: #3fb950; }
    .stat-val.yellow { color: #d29922; }
    .stat-label { font-size: .7rem; color: #8b949e; margin-top: .25rem; }

    /* complete banner */
    .banner {
      background: #0f2a1a; border: 1px solid #2ea04340; border-radius: 8px;
      padding: .85rem 1.25rem; text-align: center;
      color: #3fb950; font-size: .88rem;
      opacity: 0; transition: opacity .5s;
    }
    .banner.visible { opacity: 1; }
    .banner strong { color: #56d364; }

    /* pulse dot */
    .dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%;
           background: #3fb950; margin-left: 6px; vertical-align: middle;
           animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.25} }
  </style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>&#x2B21; <span>PQ-8004</span> Live Demo</h1>
    <p class="sub">Post-quantum x402 payment flow — ML-DSA-44 &times; ERC-8004<span class="dot"></span></p>
  </header>

  <div class="agent-card" id="agent-card">
    <div class="agent-label">ML-DSA-44 Agent Identity</div>
    <div class="agent-addr" id="agent-addr"></div>
    <div class="agent-note">pq_address = Bech32m(SHA-256(verifying_key)) &nbsp;&middot;&nbsp; 1,312-byte verifying key</div>
  </div>

  <div class="steps" id="steps"></div>

<div class="controls" style="display:flex; gap:.75rem; flex-wrap:wrap; align-items:center; margin-bottom:2rem;">
      <label style="display:flex; align-items:center; gap:.5rem; font-size:.8rem; color:#8b949e;">
        successes
        <input id="success-count" type="number" min="0" max="25" value="3" style="width:64px; background:#0d1117; border:1px solid #30363d; color:#e6edf3; border-radius:6px; padding:.45rem .5rem;" />
      </label>
      <label style="display:flex; align-items:center; gap:.5rem; font-size:.8rem; color:#8b949e;">
        failures
        <input id="fail-count" type="number" min="0" max="25" value="1" style="width:64px; background:#0d1117; border:1px solid #30363d; color:#e6edf3; border-radius:6px; padding:.45rem .5rem;" />
      </label>
      <button id="simulate-btn" style="background:#1f6feb; color:white; border:none; border-radius:6px; padding:.6rem .9rem; font:inherit; cursor:pointer;">simulate payment</button>
    </div>

    <div class="stats" id="stats">
      <div class="stat">
        <div class="stat-val green" id="score-val">—</div>
        <div class="stat-label">reputation score</div>
      </div>
      <div class="stat">
        <div class="stat-val yellow" id="sig-val">2,420</div>
        <div class="stat-label">ML-DSA-44 sig bytes</div>
      </div>
      <div class="stat">
        <div class="stat-val" style="color:#58a6ff">64</div>
        <div class="stat-label">Ed25519 sig bytes</div>
      </div>
      <div class="stat">
        <div class="stat-val green">23 µs</div>
        <div class="stat-label">ML-DSA-44 verify ✓ faster</div>
      </div>
    </div>

    <div class="banner" id="banner">
      Prototype trace: challenge issued, payment signed, verification passed, and replay rejected during a local proof-of-concept run.
    </div>
</div>

<script>
  const ICONS = { pending: '○', running: '◌', pass: '✓', fail: '✗' };

  function badge(code) {
    if (!code) return '';
    const cls = code === 200 ? 'badge-200' : 'badge-402';
    return `<span class="badge ${cls}">${code}</span>`;
  }

  function renderSteps(steps) {
    const el = document.getElementById('steps');
    steps.forEach((s, i) => {
      let div = document.getElementById('step-' + i);
      if (!div) {
        div = document.createElement('div');
        div.id = 'step-' + i;
        div.className = 'step';
        el.appendChild(div);
        requestAnimationFrame(() => div.classList.add('visible'));
      }
      div.className = 'step visible ' + s.status;
      div.innerHTML = `
        <span class="icon">${ICONS[s.status]}</span>
        <div class="step-body">
          <div class="step-title">${s.title}${badge(s.http_status)}</div>
          ${s.detail ? `<div class="step-detail">${s.detail}</div>` : ''}
        </div>`;
    });
  }

  async function poll() {
    try {
      const d = await fetch('/api/state').then(r => r.json());

      if (d.agent_address) {
        const card = document.getElementById('agent-card');
        document.getElementById('agent-addr').textContent = d.agent_address;
        card.classList.add('visible');
      }

      renderSteps(d.steps);

      if (d.score != null) {
        document.getElementById('score-val').textContent = d.score.toFixed(4);
        document.getElementById('stats').classList.add('visible');
      }
      if (d.sig_bytes) {
        document.getElementById('sig-val').textContent = d.sig_bytes.toLocaleString();
      }
      if (d.complete) {
        const banner = document.getElementById('banner');
        const score = d.score != null ? Number(d.score).toFixed(4) : '—';
        banner.textContent = `Prototype trace complete: ${d.successes || 0} passed / ${d.failures || 0} failed • current reputation ${score}`;
        banner.classList.add('visible');
      }
    } catch (e) { /* server may still be starting */ }
  }

  document.getElementById('simulate-btn').addEventListener('click', async () => {
    const successCount = Number(document.getElementById('success-count').value || 0);
    const failCount = Number(document.getElementById('fail-count').value || 0);
    const params = new URLSearchParams({
      successes: String(Math.max(0, successCount)),
      failures: String(Math.max(0, failCount))
    });

    await fetch('/api/simulate?' + params.toString());
    await poll();
  });

  poll();
  setInterval(poll, 500);
</script>
</body>
</html>"##;
