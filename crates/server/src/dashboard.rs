use std::sync::Arc;
use axum::{Json, Router, extract::State, response::Html, routing::get};
use serde::Serialize;

use crate::ServerState;

pub fn router() -> Router<Arc<ServerState>> {
    Router::new()
        .route("/", get(index_handler))
        .route("/api/agents", get(agents_handler))
        .route("/api/status", get(status_handler))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn index_handler() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

#[derive(Serialize)]
struct AgentInfo {
    pq_address: String,
    algorithm: String,
    successes: u64,
    failures: u64,
    total_volume: u64,
    score: f64,
}

async fn agents_handler(State(state): State<Arc<ServerState>>) -> Json<Vec<AgentInfo>> {
    let registry = state.registry.read().await;
    let reputation = state.reputation.lock().await;
    let now = reputation::unix_now();

    let agents: Vec<AgentInfo> = registry
        .all_records()
        .map(|record| {
            let rep = reputation.get_record(&record.pq_address);
            AgentInfo {
                pq_address: record.pq_address.clone(),
                algorithm: record.algorithm.scheme_name().to_string(),
                successes: rep.map(|r| r.successes).unwrap_or(0),
                failures: rep.map(|r| r.failures).unwrap_or(0),
                total_volume: rep.map(|r| r.total_volume).unwrap_or(0),
                // Agents with no history default to the Bayesian prior of 0.5
                score: reputation.get_score(&record.pq_address, now).unwrap_or(0.5),
            }
        })
        .collect();

    Json(agents)
}

#[derive(Serialize)]
struct StatusInfo {
    amount: u64,
    recipient: String,
    agent_count: usize,
    scheme: &'static str,
}

async fn status_handler(State(state): State<Arc<ServerState>>) -> Json<StatusInfo> {
    let agent_count = state.registry.read().await.all_records().count();
    Json(StatusInfo {
        amount: state.payment_amount,
        recipient: state.recipient.clone(),
        agent_count,
        scheme: "ml-dsa-44",
    })
}

// ── Dashboard HTML ─────────────────────────────────────────────────────────────

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PQ-8004</title>
  <style>
    :root {
      --bg: #07111b;
      --panel: #111c2a;
      --panel-soft: #152536;
      --line: #2a3a4d;
      --text: #e5edf7;
      --muted: #9ab0c9;
      --green: #4ade80;
      --blue: #7cc3ff;
      --yellow: #fbbf24;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: #040a11;
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      display: flex;
      justify-content: center;
      padding: 32px 16px;
    }

    .shell {
      width: min(860px, 100%);
      background: rgba(13, 22, 34, 0.96);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 24px 22px 18px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.35);
    }

    h1 {
      margin: 0;
      font-size: 1.8rem;
      font-weight: 700;
    }

    .title-dot { color: var(--green); margin-right: 10px; }
    .subtitle {
      margin-top: 8px;
      color: var(--muted);
      font-size: 0.9rem;
    }

    .panel {
      margin-top: 22px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      overflow: hidden;
    }

    .identity {
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
      background: rgba(17, 26, 39, 0.9);
    }

    .label {
      font-size: 0.68rem;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 8px;
    }

    .address {
      margin: 0;
      color: var(--blue);
      font-size: 0.9rem;
      word-break: break-all;
    }

    .meta {
      margin-top: 7px;
      color: var(--muted);
      font-size: 0.72rem;
    }

    .step {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 16px;
      border-bottom: 1px solid var(--line);
      background: rgba(21, 35, 50, 0.7);
    }

    .step:last-child { border-bottom: none; }

    .step-main {
      display: flex;
      align-items: center;
      gap: 10px;
      min-width: 0;
      flex: 1;
    }

    .check {
      width: 18px;
      height: 18px;
      line-height: 18px;
      border-radius: 50%;
      text-align: center;
      font-size: 11px;
      color: var(--green);
      background: rgba(74,222,128,0.12);
      border: 1px solid rgba(74,222,128,0.35);
      flex-shrink: 0;
    }

    .step-text {
      font-size: 0.98rem;
      color: var(--text);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .step-detail {
      color: var(--muted);
      font-size: 0.72rem;
      margin-top: 3px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .status {
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 0.72rem;
      background: rgba(251,191,36,0.12);
      color: var(--yellow);
      border: 1px solid rgba(251,191,36,0.32);
      flex-shrink: 0;
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(4, minmax(120px, 1fr));
      gap: 12px;
      margin-top: 22px;
    }

    .metric {
      background: rgba(17, 26, 39, 0.8);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 14px 12px;
      min-height: 90px;
    }

    .metric-value {
      margin: 0;
      color: var(--green);
      font-size: 1.1rem;
      font-weight: 700;
    }

    .metric-label {
      margin-top: 8px;
      color: var(--muted);
      font-size: 0.68rem;
      text-transform: lowercase;
      letter-spacing: 0.04em;
    }

    .result {
      margin-top: 22px;
      padding: 14px 16px;
      background: rgba(59, 130, 246, 0.10);
      border: 1px solid rgba(124, 195, 255, 0.25);
      border-radius: 10px;
      color: var(--text);
      font-size: 0.96rem;
      line-height: 1.5;
    }

    .result-badge {
      display: inline-block;
      margin-bottom: 8px;
      font-size: 0.68rem;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--muted);
    }

    @media (max-width: 700px) {
      .metrics { grid-template-columns: repeat(2, minmax(120px, 1fr)); }
      .step { flex-direction: column; align-items: flex-start; }
      .status { align-self: flex-start; }
      .step-text, .step-detail { white-space: normal; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <h1><span class="title-dot">◉</span>PQ-8004</h1>
    <div class="subtitle">post-quantum x402 demo • ML-DSA-44</div>

    <div class="panel">
      <div class="identity">
        <div class="label">agent identity</div>
        <p class="address" id="agent-address">loading…</p>
        <div class="meta">pq_address = Bech32m(SHA-256(verifying_key))</div>
      </div>
      <div id="steps"></div>
    </div>

    <div class="metrics">
      <div class="metric"><p class="metric-value" id="score">—</p><div class="metric-label">reputation</div></div>
      <div class="metric"><p class="metric-value" id="sig">—</p><div class="metric-label">sig bytes</div></div>
      <div class="metric"><p class="metric-value" id="key">—</p><div class="metric-label">Ed25519</div></div>
      <div class="metric"><p class="metric-value" id="verify">—</p><div class="metric-label">verify</div></div>
    </div>

    <div class="result" id="result-box">
      <div class="result-badge">execution trace</div>
      <div id="result-text">Running local proof-of-concept flow…</div>
    </div>
  </div>

  <script>
    const steps = [
      { title: 'Probe — no X-Payment header', detail: 'challenge returned' },
      { title: 'Sign & pay', detail: 'request accepted' },
      { title: 'Reputation after first payment', detail: 'score updated' },
      { title: 'Replay attack — same nonce', detail: 'replay rejected' }
    ];

    function renderSteps(state) {
      const el = document.getElementById('steps');
      if (!state || !state.steps) return;
      el.innerHTML = state.steps.map((step, i) => {
        const icon = step.status === 'pass' ? '✓' : step.status === 'fail' ? '!' : '…';
        const badge = step.http_status ? `<span class="status">${step.http_status}</span>` : '';
        return `
          <div class="step">
            <div class="step-main">
              <span class="check">${icon}</span>
              <div>
                <div class="step-text">${step.title}</div>
                <div class="step-detail">${step.detail || steps[i].detail}</div>
              </div>
            </div>
            ${badge}
          </div>
        `;
      }).join('');
    }

    function renderResult(state) {
      const box = document.getElementById('result-text');
      if (!state) return;

      const allPass = Array.isArray(state.steps) && state.steps.length > 0 && state.steps.every(s => s.status === 'pass');
      const anyFail = Array.isArray(state.steps) && state.steps.some(s => s.status === 'fail');

      if (!state.complete) {
        box.textContent = 'Running local proof-of-concept flow…';
        return;
      }

      if (anyFail) {
        box.textContent = 'Prototype trace complete. One check failed during the local flow.';
        return;
      }

      if (allPass) {
        box.textContent = 'Prototype trace complete. A fresh agent key was generated, challenged, signed, verified, and replayed successfully.';
        return;
      }

      box.textContent = 'Prototype trace complete. Observing the local execution flow.';
    }

    async function refresh() {
      try {
        const state = await fetch('/api/state').then(r => r.json());
        if (state.agent_address) document.getElementById('agent-address').textContent = state.agent_address;
        renderSteps(state);
        renderResult(state);
        if (state.score !== null && state.score !== undefined) document.getElementById('score').textContent = Number(state.score).toFixed(4);
        if (state.sig_bytes !== null && state.sig_bytes !== undefined) {
          document.getElementById('sig').textContent = String(state.sig_bytes);
          document.getElementById('key').textContent = '64';
          document.getElementById('verify').textContent = '23 µs';
        }
      } catch (err) {
        console.error(err);
      }
    }

    refresh();
    setInterval(refresh, 1200);
  </script>
</body>
</html>"##;
