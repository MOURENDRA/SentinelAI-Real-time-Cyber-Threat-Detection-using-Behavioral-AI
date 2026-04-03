const LOG_TEMPLATES = [
  {
    title: "Suspicious login detected",
    detail: "A finance user signed in from a new location outside the usual behavioral baseline.",
    severity: "warning",
    source: "Identity Engine",
    action: "Trigger MFA challenge and review session trust.",
    threatDelta: 1,
    healthImpact: -1,
  },
  {
    title: "Unusual activity detected",
    detail: "A workstation showed a sudden spike in file access and process launches during an unusual time window.",
    severity: "warning",
    source: "Behavioral AI",
    action: "Inspect user behavior drift and verify endpoint integrity.",
    threatDelta: 1,
    healthImpact: -1,
  },
  {
    title: "Brute force attack blocked",
    detail: "Rate-limited login attempts were detected on the admin gateway and the attacking source was blocked.",
    severity: "critical",
    source: "Network Shield",
    action: "Keep source blocked and escalate to the analyst queue.",
    threatDelta: 2,
    healthImpact: -2,
  },
  {
    title: "Privilege escalation attempt flagged",
    detail: "A service account requested access outside its normal permission pattern across a protected database zone.",
    severity: "critical",
    source: "Access Monitor",
    action: "Freeze elevated permissions and audit recent access requests.",
    threatDelta: 2,
    healthImpact: -2,
  },
  {
    title: "Behavior returned to baseline",
    detail: "A previously risky session now matches expected login and access patterns after revalidation.",
    severity: "normal",
    source: "Behavioral AI",
    action: "Keep monitoring with no extra analyst action required.",
    threatDelta: 0,
    healthImpact: 1,
  },
];

const AI_STEPS = [
  {
    id: "collect",
    stage: "Step 1",
    title: "Collect Data",
    description:
      "SentinelAI gathers login events, device activity, and network behavior in one stream so the system can understand what normal usage looks like.",
  },
  {
    id: "analyze",
    stage: "Step 2",
    title: "Analyze Behavior",
    description:
      "The AI compares current actions with normal patterns to score unusual timing, device drift, access spikes, and risky session changes.",
  },
  {
    id: "detect",
    stage: "Step 3",
    title: "Detect Anomalies",
    description:
      "When multiple abnormal behaviors line up, SentinelAI raises an alert and suggests what the operator should do next.",
  },
];

const MODULES = [
  {
    id: "realtime",
    status: "Module Live",
    title: "Real-time Detection Engine",
    description:
      "Continuously monitors incoming events and updates the dashboard within seconds so the product feels active and responsive.",
  },
  {
    id: "behavioral",
    status: "AI Engine",
    title: "Behavioral Analysis Engine",
    description:
      "Builds expected behavior baselines and scores unusual login patterns, suspicious access, and risky endpoint actions.",
  },
  {
    id: "response",
    status: "Response Module",
    title: "Alert & Response System",
    description:
      "Routes alerts by severity and gives the operator clean next-step guidance for faster demo-ready decisions.",
  },
];

const TIMELINE = [
  {
    title: "Day 1 — Online Round",
    description:
      "The focus was on joining the platform, shaping the core idea, and building the first working prototype.",
    events: ["Join platform", "Start development", "Submit prototype"],
  },
  {
    title: "Day 2 — Offline Round",
    description:
      "The final round focused on polish, full integration, and delivering the finished experience to the judges.",
    events: ["Final development", "Project submission", "Presentation to judges"],
  },
];

const SIGNAL_NODES = [
  "Identity Mesh",
  "Endpoint Grid",
  "Admin Gateway",
  "API Shield",
  "Cloud Workloads",
  "Privilege Monitor",
  "Session Graph",
  "Response Queue",
];

const state = {
  monitoring: true,
  totalThreats: 24,
  health: 97,
  endpoints: 128,
  logs: [],
  activeStep: AI_STEPS[0].id,
  activeModule: MODULES[0].id,
  signalStates: SIGNAL_NODES.map((label) => ({ label, state: "normal", detail: "Stable traffic" })),
  intervalId: null,
};

const ui = {};

document.addEventListener("DOMContentLoaded", () => {
  cacheDom();
  bindEvents();
  seedLogs();
  renderAll();
  startMonitoring();
});

function cacheDom() {
  [
    "systemStatusPill",
    "systemStatusText",
    "threatCount",
    "alertCount",
    "healthCount",
    "endpointCount",
    "controlState",
    "controlStateMeta",
    "confidenceValue",
    "latencyValue",
    "signalGrid",
    "startMonitoringButton",
    "stopMonitoringButton",
    "clearLogsButton",
    "suspiciousCount",
    "activityCount",
    "criticalCount",
    "logFeed",
    "incidentCard",
    "queueList",
    "stepGrid",
    "stepStageLabel",
    "stepTitle",
    "stepDescription",
    "moduleGrid",
    "moduleStatus",
    "moduleTitle",
    "moduleDescription",
    "timelineGrid",
  ].forEach((id) => {
    ui[id] = document.getElementById(id);
  });

  ui.navLinks = Array.from(document.querySelectorAll("[data-scroll-target]"));
  ui.statusDot = document.querySelector(".status-dot");
}

function bindEvents() {
  ui.navLinks.forEach((button) => {
    button.addEventListener("click", () => {
      const section = document.getElementById(button.dataset.scrollTarget);
      if (section) {
        section.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  });

  ui.startMonitoringButton.addEventListener("click", startMonitoring);
  ui.stopMonitoringButton.addEventListener("click", stopMonitoring);
  ui.clearLogsButton.addEventListener("click", clearLogs);

  ui.stepGrid.addEventListener("click", (event) => {
    const button = event.target.closest("[data-step-id]");
    if (!button) {
      return;
    }
    state.activeStep = button.dataset.stepId;
    renderSteps();
  });

  ui.moduleGrid.addEventListener("click", (event) => {
    const button = event.target.closest("[data-module-id]");
    if (!button) {
      return;
    }
    state.activeModule = button.dataset.moduleId;
    renderModules();
  });
}

function seedLogs() {
  addLog(LOG_TEMPLATES[0], true);
  addLog(LOG_TEMPLATES[1], true);
  addLog(LOG_TEMPLATES[2], true);
  addLog(LOG_TEMPLATES[4], true);
}

function startMonitoring() {
  if (state.intervalId) {
    return;
  }

  state.monitoring = true;
  state.intervalId = window.setInterval(() => {
    const template = LOG_TEMPLATES[randomInt(0, LOG_TEMPLATES.length - 1)];
    addLog(template, false);
    renderAll();
  }, 2300);

  renderStatus();
}

function stopMonitoring() {
  if (state.intervalId) {
    window.clearInterval(state.intervalId);
    state.intervalId = null;
  }

  state.monitoring = false;
  renderStatus();
}

function clearLogs() {
  state.logs = [];
  state.signalStates = state.signalStates.map((item) => ({
    ...item,
    state: "normal",
    detail: "Stable traffic",
  }));
  renderAll();
}

function addLog(template, isSeed) {
  const entry = {
    id: `${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    time: new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }),
    title: template.title,
    detail: template.detail,
    severity: template.severity,
    source: template.source,
    action: template.action,
  };

  state.logs = [entry, ...state.logs].slice(0, 10);

  if (!isSeed) {
    state.totalThreats += template.threatDelta;
  }

  state.health = clamp(state.health + template.healthImpact, 88, 99);
  rotateSignals(template.severity, template.title);
}

function rotateSignals(severity, title) {
  const first = randomInt(0, state.signalStates.length - 1);
  const second = randomInt(0, state.signalStates.length - 1);

  state.signalStates = state.signalStates.map((item, index) => {
    if (index !== first && index !== second) {
      const nextState =
        item.state === "critical" ? "warning" : item.state === "warning" ? "normal" : "normal";
      return {
        ...item,
        state: Math.random() > 0.84 ? nextState : item.state,
      };
    }

    return {
      ...item,
      state: severity,
      detail: title,
    };
  });
}

function renderAll() {
  renderStatus();
  renderOverview();
  renderSignals();
  renderMonitoring();
  renderSteps();
  renderModules();
  renderTimeline();
}

function renderStatus() {
  const responseLatency = (0.31 + Math.random() * 0.24).toFixed(2);
  const confidence = randomInt(91, 97);

  ui.systemStatusText.textContent = state.monitoring ? "System Active" : "System Paused";
  ui.systemStatusPill.style.background = state.monitoring
    ? "rgba(102, 227, 255, 0.08)"
    : "rgba(255, 95, 116, 0.1)";
  ui.systemStatusPill.style.borderColor = state.monitoring
    ? "rgba(102, 227, 255, 0.18)"
    : "rgba(255, 95, 116, 0.24)";
  ui.statusDot.style.background = state.monitoring ? "var(--normal)" : "var(--critical)";
  ui.statusDot.style.boxShadow = state.monitoring
    ? "0 0 14px rgba(125, 227, 161, 0.9)"
    : "0 0 14px rgba(255, 95, 116, 0.85)";
  ui.controlState.textContent = state.monitoring ? "Monitoring Live" : "Monitoring Stopped";
  ui.controlStateMeta.textContent = state.monitoring
    ? "Behavioral models are actively scoring events."
    : "Start monitoring to resume the live simulation.";
  ui.confidenceValue.textContent = `${confidence}%`;
  ui.latencyValue.textContent = `${responseLatency}s`;
  ui.startMonitoringButton.disabled = state.monitoring;
  ui.stopMonitoringButton.disabled = !state.monitoring;
}

function renderOverview() {
  ui.threatCount.textContent = state.totalThreats;
  ui.alertCount.textContent = state.logs.filter((log) => log.severity !== "normal").length;
  ui.healthCount.textContent = `${state.health}%`;
  ui.endpointCount.textContent = state.endpoints;
}

function renderSignals() {
  ui.signalGrid.innerHTML = state.signalStates
    .map(
      (item) => `
        <article class="signal-node state-${item.state}">
          <p>${item.label}</p>
          <strong>${formatSignalState(item.state)}</strong>
          <span>${item.detail}</span>
        </article>
      `
    )
    .join("");
}

function renderMonitoring() {
  ui.suspiciousCount.textContent = state.logs.filter((log) =>
    log.title.toLowerCase().includes("login")
  ).length;
  ui.activityCount.textContent = state.logs.filter((log) =>
    log.title.toLowerCase().includes("activity")
  ).length;
  ui.criticalCount.textContent = state.logs.filter((log) => log.severity === "critical").length;

  if (!state.logs.length) {
    ui.logFeed.innerHTML =
      '<article class="log-entry severity-normal"><strong>Log feed cleared</strong><p>Press Start Monitoring to simulate new cyber threat events.</p></article>';
    ui.incidentCard.innerHTML =
      "<strong>No active incident</strong><p>The queue is clear until new events are generated.</p>";
    ui.queueList.innerHTML =
      '<article class="queue-item severity-normal"><strong>No queued responses</strong><span>The system is waiting for new threats.</span></article>';
    return;
  }

  ui.logFeed.innerHTML = state.logs
    .map(
      (log) => `
        <article class="log-entry severity-${log.severity}">
          <div class="log-meta">
            <span>${log.time}</span>
            <span>${log.source}</span>
            <span>${formatSignalState(log.severity)}</span>
          </div>
          <strong>${log.title}</strong>
          <p>${log.detail}</p>
        </article>
      `
    )
    .join("");

  const activeIncident =
    state.logs.find((log) => log.severity === "critical") ||
    state.logs.find((log) => log.severity === "warning") ||
    state.logs[0];

  ui.incidentCard.innerHTML = `
    <div class="incident-meta">
      <span>${activeIncident.time}</span>
      <span>${activeIncident.source}</span>
      <span>${formatSignalState(activeIncident.severity)}</span>
    </div>
    <strong>${activeIncident.title}</strong>
    <p>${activeIncident.detail}</p>
    <span>${activeIncident.action}</span>
  `;

  const queueItems = state.logs.filter((log) => log.severity !== "normal").slice(0, 4);
  ui.queueList.innerHTML = queueItems.length
    ? queueItems
        .map(
          (log) => `
            <article class="queue-item severity-${log.severity}">
              <strong>${log.title}</strong>
              <span>${log.action}</span>
            </article>
          `
        )
        .join("")
    : '<article class="queue-item severity-normal"><strong>No queued responses</strong><span>Only normal activity is currently visible.</span></article>';
}

function renderSteps() {
  const activeStep = AI_STEPS.find((step) => step.id === state.activeStep) || AI_STEPS[0];

  ui.stepGrid.innerHTML = AI_STEPS.map(
    (step) => `
      <button class="step-card ${step.id === activeStep.id ? "is-active" : ""}" type="button" data-step-id="${step.id}">
        <p>${step.stage}</p>
        <strong>${step.title}</strong>
      </button>
    `
  ).join("");

  ui.stepStageLabel.textContent = activeStep.stage;
  ui.stepTitle.textContent = activeStep.title;
  ui.stepDescription.textContent = activeStep.description;
}

function renderModules() {
  const activeModule = MODULES.find((module) => module.id === state.activeModule) || MODULES[0];

  ui.moduleGrid.innerHTML = MODULES.map(
    (module) => `
      <button class="module-card ${module.id === activeModule.id ? "is-active" : ""}" type="button" data-module-id="${module.id}">
        <p>${module.status}</p>
        <strong>${module.title}</strong>
      </button>
    `
  ).join("");

  ui.moduleStatus.textContent = activeModule.status;
  ui.moduleTitle.textContent = activeModule.title;
  ui.moduleDescription.textContent = activeModule.description;
}

function renderTimeline() {
  ui.timelineGrid.innerHTML = TIMELINE.map(
    (day) => `
      <article class="timeline-day">
        <p class="panel-label">Hackathon Event Log</p>
        <h3>${day.title}</h3>
        <p>${day.description}</p>
        <ul>
          ${day.events.map((event) => `<li>${event}</li>`).join("")}
        </ul>
      </article>
    `
  ).join("");
}

function formatSignalState(value) {
  if (value === "normal") {
    return "Normal";
  }
  if (value === "warning") {
    return "Warning";
  }
  return "Critical";
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
