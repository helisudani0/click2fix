import { useEffect, useMemo, useRef, useState } from "react";
import "./styles/product-site.css";

const REPO_URL = "https://github.com/helisudani0/click2fix";
const RELEASES_URL = `${REPO_URL}/releases`;
const LATEST_RELEASE_URL = `${RELEASES_URL}/latest`;
const MINI_RELEASE_TAG = "min-v1.1.12";
const MINI_ZIP_URL =
  `${RELEASES_URL}/download/${MINI_RELEASE_TAG}/click2fix-patch-workbench-installer-min-v1.1.12.zip`;
const FULL_VERSION = "v1.1.10";
const ASSET_BASE = import.meta.env.BASE_URL || "/";
const COMMAND_MARK = `${ASSET_BASE.replace(/\/?$/, "/")}click2fix-command-mark.svg`;
const FULL_BOOTSTRAP_PS =
  `${REPO_URL.replace("github.com", "raw.githubusercontent.com")}/${FULL_VERSION}/deploy/appliance/bootstrap-from-github.ps1`;
const FULL_BOOTSTRAP_SH =
  `${REPO_URL.replace("github.com", "raw.githubusercontent.com")}/${FULL_VERSION}/deploy/appliance/bootstrap-from-github.sh`;

const navItems = [
  ["Platform", "#platform"],
  ["Architecture", "#architecture"],
  ["Workbench", "#workbench"],
  ["Deploy", "#deploy"],
  ["Docs", "#docs"],
  ["Roadmap", "#roadmap"],
];

const telemetry = [
  ["250K", "events normalized"],
  ["30s", "target P95 detection"],
  ["50+", "agent appliance lane"],
  ["100%", "execution evidence"],
];

const featureSystems = [
  {
    title: "Patch Workbench",
    label: "Remediation cockpit",
    body: "Centralized patch orchestration with target scope, vulnerability context, shell/action/playbook dispatch, live status, and history proof.",
    signal: "CVE -> target -> command -> evidence",
    stats: ["global execution", "per-agent output", "scheduler-ready"],
  },
  {
    title: "Vulnerability Remediation",
    label: "Risk-to-fix loop",
    body: "Pull vulnerability posture from Wazuh, prioritize impact, execute remediation, and reconcile endpoint-side outcomes without losing context.",
    signal: "CVE intelligence fused with response",
    stats: ["risk scoring", "patch state", "false-negative aware"],
  },
  {
    title: "Fleet Management",
    label: "Endpoint command layer",
    body: "Operate across fleets, groups, OS lanes, single agents, or multi-agent scopes with Windows and Linux execution pathways.",
    signal: "WinRM + SSH + Wazuh agent state",
    stats: ["groups", "OS targeting", "multi-agent"],
  },
  {
    title: "Live Command Execution",
    label: "Global shell",
    body: "PowerShell, CMD, Bash, and SH execution with reusable command patterns, guarded controls, and live output streams.",
    signal: "operator command streamed into endpoint proof",
    stats: ["PowerShell", "CMD", "Bash/SH"],
  },
  {
    title: "SOC Operations",
    label: "Analyst flow",
    body: "Actions, approvals, cases, playbooks, incident workflow, and audit trails aligned into one command surface for operators.",
    signal: "triage -> approval -> action -> audit",
    stats: ["actions", "playbooks", "approvals"],
  },
  {
    title: "Reporting and Analytics",
    label: "Executive proof",
    body: "Remediation analytics, compliance posture, report APIs, fleet health scoring, and exportable evidence for operations reviews.",
    signal: "evidence becomes governance",
    stats: ["PDF reports", "dashboards", "SLA posture"],
  },
  {
    title: "Security and Architecture",
    label: "Enterprise control",
    body: "Audit logging, RBAC/ABAC direction, signed command roadmap, encrypted channels, zero-trust service goals, and tenant-aware APIs.",
    signal: "security controls embedded in execution",
    stats: ["audit", "RBAC", "zero-trust path"],
  },
];

const oldFlow = [
  "Export CSV",
  "Open ticket",
  "Find owner",
  "Remote in",
  "Run script",
  "Hope it worked",
];

const newFlow = [
  "Detect",
  "Prioritize",
  "Scope",
  "Orchestrate",
  "Verify",
  "Prove",
];

const platformStory = [
  {
    title: "Why it exists",
    body: "Security teams can identify risk faster than most operations teams can safely remediate it. Click2Fix removes that dead zone between visibility and action by turning Wazuh signal into controlled endpoint execution.",
  },
  {
    title: "What it connects",
    body: "Wazuh agents, vulnerability posture, endpoint credentials, shell execution, action catalogs, playbooks, schedules, approvals, reports, and evidence history become one operating fabric.",
  },
  {
    title: "What changes",
    body: "The workflow stops being a manual scavenger hunt. Operators scope the fleet, choose the right remediation path, watch live endpoint output, classify endpoint-side outcomes, and keep proof for audit.",
  },
  {
    title: "Why it scales",
    body: "The same flow works for one endpoint, an OS lane, a group, or a fleet. Windows and Linux execution paths are handled through controlled WinRM and SSH channels with reusable automation layers.",
  },
  {
    title: "Who uses it",
    body: "SOC analysts, IT operations, MSP teams, compliance operators, and incident responders can all work from the same truth: what was vulnerable, what ran, where it ran, and what happened.",
  },
  {
    title: "What it becomes",
    body: "The v2 track evolves Click2Fix toward a Unified Enterprise Security Operations Platform: SIEM, EDR, XDR, SOAR, vulnerability, GRC, asset, risk, cloud, DevSecOps, and reporting surfaces.",
  },
];

const remediationIntelligence = [
  {
    label: "Signal intake",
    value: "Wazuh alerts, vulnerabilities, SCA, agents",
    width: "91%",
  },
  {
    label: "Decision fabric",
    value: "risk, OS, scope, approvals, blast radius",
    width: "76%",
  },
  {
    label: "Execution lane",
    value: "shell, actions, playbooks, scheduler",
    width: "84%",
  },
  {
    label: "Proof engine",
    value: "target output, steps, history, reports",
    width: "96%",
  },
];

const architectureLayers = [
  {
    name: "Experience Plane",
    detail: "SOC console, Patch Workbench, docs center, approvals, execution history, reporting.",
    nodes: ["React UI", "Operator console", "Docs"],
  },
  {
    name: "Control Plane",
    detail: "FastAPI backend, v2 domain APIs, tenant scoping, scheduler, playbook/action orchestration.",
    nodes: ["API gateway", "Scheduler", "SOAR"],
  },
  {
    name: "Data Plane",
    detail: "Wazuh Manager, Wazuh Indexer, event ingestion, normalization, alert and case services.",
    nodes: ["Wazuh API", "Indexer", "Event bus"],
  },
  {
    name: "Response Plane",
    detail: "WinRM, SSH, global shell, guarded actions, endpoint execution, evidence capture.",
    nodes: ["Windows", "Linux", "Evidence"],
  },
  {
    name: "Trust Plane",
    detail: "Audit chain, RBAC/ABAC roadmap, mTLS target, signed command envelopes, compliance exports.",
    nodes: ["Audit", "Policy", "Crypto"],
  },
];

const deployCommands = {
  powershell: {
    label: "Windows PowerShell",
    lines: [
      "$version = 'v1.1.10'",
      `Invoke-WebRequest "${FULL_BOOTSTRAP_PS}" -OutFile .\\bootstrap-from-github.ps1`,
      "powershell -ExecutionPolicy Bypass -File .\\bootstrap-from-github.ps1 -Owner helisudani0 -Repo click2fix -Version $version -InstallDir C:\\Click2Fix -PullImages",
    ],
  },
  bash: {
    label: "Linux Bash",
    lines: [
      "export VERSION=v1.1.10",
      `curl -fsSL "${FULL_BOOTSTRAP_SH}" -o ./bootstrap-from-github.sh`,
      "chmod +x ./bootstrap-from-github.sh",
      "OWNER=helisudani0 REPO=click2fix VERSION=${VERSION} INSTALL_DIR=/opt/click2fix PULL_IMAGES=true ./bootstrap-from-github.sh",
    ],
  },
  miniZip: {
    label: "Mini ZIP",
    lines: [
      `curl -fL -o click2fix-patch-workbench-installer-min-v1.1.12.zip "${MINI_ZIP_URL}"`,
      "unzip click2fix-patch-workbench-installer-min-v1.1.12.zip -d click2fix-patch-workbench",
      "cd click2fix-patch-workbench",
      "./install-patch-workbench.sh",
    ],
  },
};

const docs = [
  {
    title: "Prerequisites",
    items: [
      "Docker Engine and Docker Compose plugin",
      "Reachability to Wazuh Manager API and Wazuh Indexer API",
      "WinRM for Windows endpoints and SSH for Linux endpoints",
      "Persistent PostgreSQL volume and release-pinned images",
    ],
  },
  {
    title: "Ports and connections",
    items: [
      "Browser to UI: 5173 for lab, or 80/443 behind proxy",
      "Backend API: 8000 internally or behind gateway",
      "Wazuh Manager API: 55000",
      "Wazuh Indexer API: 9200",
      "Endpoint execution: 5985/5986 WinRM and 22 SSH",
    ],
  },
  {
    title: "Credentials",
    items: [
      "Initial Click2Fix admin account",
      "Wazuh Manager API username and password",
      "Wazuh Indexer username and password",
      "WinRM credentials for Windows admin execution",
      "SSH per-agent credentials such as C2F_SSH_USERNAME_004 and C2F_SSH_PASSWORD_004",
    ],
  },
  {
    title: "Sizing",
    items: [
      "Lab: 2 CPU and 4 GB RAM",
      "50+ agents: 4 CPU and 8 GB RAM recommended",
      "100+ agents or heavy playbooks: 8 CPU and 16 GB RAM recommended",
      "Use SSD-backed storage for database and index access",
    ],
  },
];

const documentationEntries = [
  {
    title: "API docs",
    summary: "Use the backend APIs to query agents, vulnerabilities, executions, approvals, cases, reports, and v2 domain surfaces.",
    detail: [
      "Start with authenticated requests against the backend gateway.",
      "Query agents and groups before launching fleet-wide execution.",
      "Read vulnerabilities, SCA posture, alerts, cases, and reports from their domain APIs.",
      "Use execution APIs to track command/action/playbook runs and per-target output.",
      "Use audit APIs to query, export, and verify immutable operational records.",
      "Use v2 APIs for the newer domain model: agents, alerts, cases, SOAR, audit, tenants, vuln, GRC, cloud, DevSecOps, and reports.",
    ],
  },
  {
    title: "Deployment docs",
    summary: "Install the full appliance with release-pinned bootstrap scripts or deploy the focused mini ZIP for remediation teams.",
    detail: [
      "Use Docker and Compose for the standard appliance path.",
      "Pin the install to a GitHub release tag before production rollout.",
      "Keep PostgreSQL storage persistent before running real endpoint operations.",
      "Configure Wazuh Manager, Wazuh Indexer, WinRM, and SSH credentials before first production run.",
      "Open browser, backend, Wazuh, WinRM, and SSH ports only between trusted networks.",
      "Start with the full platform for SOC operations; use the mini ZIP for a small patch-only lane.",
    ],
  },
  {
    title: "Remediation workflows",
    summary: "Move from CVE visibility to verified fixes using Patch Workbench, global shell, actions, and playbooks.",
    detail: [
      "Choose fleet, OS, group, multi-agent, or single-agent scope.",
      "Load vulnerabilities from the Wazuh-backed feed and attach selected rows as context.",
      "Select shell, action, playbook, or scheduled remediation depending on risk and maintenance window.",
      "Run a remediation command or action, then review endpoint-side status and evidence.",
      "Treat network errors, already-updated states, and reboot disconnects differently from tool logic failures.",
      "Use history rows to reopen full evidence when the live run is complete.",
    ],
  },
  {
    title: "Automation guides",
    summary: "Build repeatable maintenance flows with scheduler jobs, command presets, actions, and playbook templates.",
    detail: [
      "Schedule shell, action, or playbook jobs for maintenance windows.",
      "Use OS-aware targeting to keep Linux and Windows workflows clean.",
      "Use command matrices for common Windows Update and Linux package-management operations.",
      "Keep destructive commands guarded behind operator intent and explicit justification.",
      "Preserve justifications and history so repeatable automation stays auditable.",
      "Promote proven shell flows into actions or playbooks once they stabilize.",
    ],
  },
  {
    title: "Integration guides",
    summary: "Connect Wazuh, Windows endpoints, Linux endpoints, release assets, and enterprise infrastructure.",
    detail: [
      "Wazuh Manager API provides agent and security signal context.",
      "Wazuh Indexer provides searchable alert, vulnerability, and posture data.",
      "WinRM and SSH provide controlled response paths for endpoint remediation.",
      "GitHub releases and GHCR images provide repeatable appliance deployment assets.",
      "Future enterprise paths align with API gateway, event bus, service extraction, mTLS, and tenant-scoped control planes.",
      "Use environment-based credential configuration for per-agent Linux SSH and Windows WinRM lanes.",
    ],
  },
  {
    title: "Patch management docs",
    summary: "Understand package updates, Windows update workflows, Linux package managers, reboot states, and false-negative handling.",
    detail: [
      "Linux package workflows support apt, dnf, yum, pacman, zypper, and kernel checks.",
      "Windows workflows support native update commands and PSWindowsUpdate paths.",
      "Endpoint-side failures are classified separately from tool logic failures where possible.",
      "Patch Workbench links selected vulnerability rows to the exact remediation run.",
      "Scheduler jobs let teams repeat approved patch cycles on defined intervals.",
      "Execution history keeps target output, clean output, raw logs, target results, endpoint issues, and steps.",
    ],
  },
  {
    title: "Fleet operations",
    summary: "Operate across endpoint groups, OS lanes, selected agents, and LAN-wide remediation windows.",
    detail: [
      "Use fleet mode for broad maintenance and OS mode for platform-safe workflows.",
      "Use multi-agent mode for surgical remediation across selected machines.",
      "Review per-agent output when a run spans multiple endpoints.",
      "Scope Linux and Windows separately when commands are platform-specific.",
      "Use groups for repeatable business-unit, environment, or maintenance-window targeting.",
      "Use scheduler jobs when the operation should run later, hourly, daily, weekly, monthly, or by cron.",
    ],
  },
  {
    title: "Reporting docs",
    summary: "Turn execution, vulnerability, SCA, remediation, and audit data into reports and operational proof.",
    detail: [
      "Use execution history as the base evidence source.",
      "Use analytics and report APIs to summarize fleet health and remediation posture.",
      "Keep finished runs linked to target output, endpoint issues, clean output, and raw logs.",
      "Use SCA rollups and recommendations to explain posture, not only command success.",
      "Track patch status, target health, CVE pressure, and compliance movement over time.",
      "Export reports for leadership, audits, incident closure, and operational reviews.",
    ],
  },
  {
    title: "Troubleshooting",
    summary: "Fix common install and runtime issues such as cookies, auth errors, firewalls, Wazuh connectivity, WinRM, and SSH.",
    detail: [
      "Clear browser cookies if login loops after a redeploy.",
      "Check ports 5173/80/443, 8000, 55000, 9200, 5985/5986, and 22.",
      "Confirm endpoint credentials and admin/root permissions before blaming the remediation workflow.",
      "If Wazuh data is empty, verify Manager and Indexer URLs, credentials, TLS settings, and network reachability.",
      "If Linux commands ask for a password, configure per-agent SSH credentials and run as root/admin where needed.",
      "If Windows execution fails, validate WinRM listener, firewall, TrustedHosts/certificates, and administrator rights.",
    ],
  },
];

const documentationRunbooks = {
  "API docs": {
    before: [
      "Create or reuse an authenticated operator session.",
      "Confirm tenant/org scope before querying multi-tenant v2 endpoints.",
      "Decide whether the workflow needs read-only posture data or write-path execution APIs.",
    ],
    steps: [
      "Call health/config endpoints first so the UI or integration can show dependency state.",
      "Query agents, groups, vulnerabilities, and SCA posture to build the target context.",
      "Submit shell/action/playbook execution only after target scope and justification are attached.",
      "Poll or stream execution status, then fetch per-target output and steps for evidence.",
      "Export audit/report data when the run must be attached to a case or compliance record.",
    ],
    outputs: [
      "Agent inventory and target eligibility",
      "Execution ID and run status",
      "Per-agent stdout/stderr, clean output, endpoint issues, and audit trail",
    ],
  },
  "Deployment docs": {
    before: [
      "Choose full platform for SOC operations or mini ZIP for a dedicated patch lane.",
      "Reserve CPU/RAM/storage before onboarding real endpoint execution.",
      "Collect Wazuh Manager, Wazuh Indexer, WinRM, and SSH credentials.",
    ],
    steps: [
      "Download from the pinned GitHub release or use the bootstrap command for your OS.",
      "Create the environment file and fill Wazuh/API/endpoint credentials before first launch.",
      "Start Docker Compose, verify containers, then open the UI through 5173, 80, or 443.",
      "Log in with the bootstrap admin and verify Wazuh agents populate.",
      "Run a harmless read-only command on one Windows and one Linux endpoint before patching.",
    ],
    outputs: [
      "Running frontend, backend, database, and supporting containers",
      "Connected Wazuh data plane",
      "Validated endpoint execution path",
    ],
  },
  "Remediation workflows": {
    before: [
      "Confirm the vulnerability source and affected agents.",
      "Separate Windows and Linux targets when command syntax differs.",
      "Decide if the fix is safe for now or needs a maintenance window.",
    ],
    steps: [
      "Select target scope: fleet, OS lane, group, multi-agent, or single endpoint.",
      "Filter vulnerabilities by CVE, package, title, or severity.",
      "Attach selected rows as context or run without vulnerability context for general maintenance.",
      "Choose shell, action, playbook, or scheduler depending on repeatability.",
      "Watch live status until complete, then open history for full evidence.",
    ],
    outputs: [
      "Target-level success, endpoint-side issue, retryable state, or tool failure",
      "Command used and evidence generated",
      "Operator-friendly remediation record",
    ],
  },
  "Automation guides": {
    before: [
      "Start with a command that has already passed on one endpoint.",
      "Convert repeated commands into actions or playbook steps.",
      "Use scheduler only after the workflow is safe and deterministic.",
    ],
    steps: [
      "Build a command/action/playbook payload with a clear justification.",
      "Choose target mode and OS filter so Windows-only commands never hit Linux endpoints.",
      "Set recurrence using hourly, daily, weekly, monthly, or custom cron timing.",
      "Keep approval enabled for sensitive workflows or destructive commands.",
      "Review scheduled job history after each run and tune the workflow if endpoint-side issues appear.",
    ],
    outputs: [
      "Recurring maintenance job",
      "Reusable remediation playbook",
      "Auditable command timeline",
    ],
  },
  "Integration guides": {
    before: [
      "Confirm Wazuh Manager API and Indexer API are reachable from the backend container.",
      "Decide how Windows and Linux credentials will be stored.",
      "Open only trusted network paths between Click2Fix, Wazuh, and endpoints.",
    ],
    steps: [
      "Connect Manager API for agents, groups, and operational metadata.",
      "Connect Indexer API for vulnerabilities, alerts, posture, and evidence lookup.",
      "Configure WinRM for Windows execution over 5985/5986.",
      "Configure SSH for Linux execution over port 22 with per-agent credentials where needed.",
      "Validate each integration with a read-only command before enabling remediation workflows.",
    ],
    outputs: [
      "Healthy Wazuh ingestion",
      "Endpoint execution readiness",
      "Clean separation of Windows and Linux remediation lanes",
    ],
  },
  "Patch management docs": {
    before: [
      "Check package manager availability and endpoint OS.",
      "Understand reboot behavior before running install commands.",
      "Confirm whether the command updates OS packages, third-party apps, or only lists state.",
    ],
    steps: [
      "Use apt/dnf/yum/pacman/zypper commands for Linux package workflows.",
      "Use UsoClient, wuauclt, PSWindowsUpdate, winget, choco, scoop, or DISM for Windows workflows.",
      "Run read-only checks like Get-Hotfix, apt list --upgradable, or uname -r before risky updates.",
      "Classify already-updated, reboot pending, package lock, or network failure as endpoint-side outcomes.",
      "Attach final history evidence to incident, compliance, or patch review records.",
    ],
    outputs: [
      "Patch state before and after remediation",
      "Endpoint issue classification",
      "Evidence trail for compliance",
    ],
  },
  "Fleet operations": {
    before: [
      "Decide target type: fleet, OS, group, multiple agents, or one endpoint.",
      "Make sure commands match every platform in the selected scope.",
      "Use smaller scopes when testing a new command or playbook.",
    ],
    steps: [
      "Load agent inventory and connected status.",
      "Select a target mode and confirm resolved target count.",
      "Run read-only validation on representative endpoints.",
      "Execute remediation across the approved scope.",
      "Switch target rows in execution detail to inspect per-agent output and steps.",
    ],
    outputs: [
      "Fleet-level summary",
      "Per-agent result matrix",
      "Evidence by endpoint",
    ],
  },
  "Reporting docs": {
    before: [
      "Decide the reporting audience: SOC, IT, leadership, compliance, or customer.",
      "Choose which evidence source matters: execution history, vulnerabilities, SCA, or alerts.",
      "Verify timestamps, target IDs, and operator justification are present.",
    ],
    steps: [
      "Open execution history and filter by module, status, target, or command.",
      "Review target results, endpoint issues, clean output, raw output, and execution steps.",
      "Use analytics and report APIs for posture summaries.",
      "Export or copy evidence into cases, tickets, compliance packets, or review decks.",
      "Track repeated endpoint-side failures as operational debt, not hidden tool failures.",
    ],
    outputs: [
      "Patch status report",
      "Compliance and audit proof",
      "Fleet health trend",
    ],
  },
  Troubleshooting: {
    before: [
      "Separate UI/auth problems from Wazuh problems and endpoint execution problems.",
      "Check container health before debugging application behavior.",
      "Collect the execution ID when a command/action/playbook has an issue.",
    ],
    steps: [
      "For login 401/404 loops, clear cookies for the host and restart the browser session.",
      "For empty Wazuh data, verify Manager and Indexer credentials, URLs, certificates, and firewall paths.",
      "For Linux sudo prompts, configure per-agent SSH credentials and use elevated execution where required.",
      "For Windows failures, validate WinRM listener, firewall, TrustedHosts/certificates, and admin rights.",
      "For package locks or network errors, treat the run as endpoint-side and retry during a clean maintenance window.",
    ],
    outputs: [
      "Root-cause lane: UI, Wazuh, network, credential, endpoint, or tool logic",
      "Next action for the operator",
      "Cleaner status labels in history",
    ],
  },
};

const useCases = [
  ["SOC teams", "Triage Wazuh signals, launch contained actions, and preserve analyst-grade execution proof."],
  ["Enterprise IT", "Patch Windows and Linux fleets from one controlled orchestration surface."],
  ["MSPs", "Operate multiple client fleets with repeatable maintenance workflows and release-pinned installers."],
  ["Incident response", "Run targeted containment, evidence collection, and post-action verification."],
  ["Compliance operations", "Turn remediation execution into audit-friendly evidence and reporting trails."],
  ["Infrastructure teams", "Schedule fleet hygiene, package maintenance, shell checks, and post-deploy validation."],
];

const trustControls = [
  "Encrypted transport channels",
  "Audit-friendly execution history",
  "Role-based access direction",
  "Tenant-scoped v2 API foundation",
  "Signed command envelope roadmap",
  "mTLS service identity roadmap",
];

const versions = [
  {
    version: "v1.1.10",
    title: "Current stable full platform",
    detail:
      "Wazuh-centric SOC console with Global Shell, actions, playbooks, scheduler parity, IOC enrichment, MITRE mapping, incident correlation, SCA rollups, and execution reconciliation.",
  },
  {
    version: "min-v1.1.12",
    title: "Focused Patch Workbench Mini",
    detail:
      "Small appliance for vulnerability remediation, global shell, action/playbook lanes, scheduler, Linux/Windows endpoint execution, and live history evidence.",
  },
  {
    version: "v2 foundation",
    title: "Native UESOP control plane",
    detail:
      "API-first v2 track with agents, alerts, cases, SOAR facade, audit query/export/verify, tenants, auth lifecycle, and service extraction foundations.",
  },
];

const roadmap = [
  {
    phase: "Phase 1",
    horizon: "0-6 months",
    title: "Security foundation and SOC core",
    points: ["100 endpoint soak", "tenant isolation", "audit export/verify", "P95 ingest-to-alert <=45s"],
  },
  {
    phase: "Phase 2",
    horizon: "6-14 months",
    title: "XDR correlation and HA scale",
    points: ["1000 endpoint throughput", "exposure management", "TIP expansion", "DR RPO/RTO validation"],
  },
  {
    phase: "Phase 3",
    horizon: "14-24 months",
    title: "Enterprise UESOP at 10K+ endpoints",
    points: ["GRC reporting", "cloud and DevSecOps", "UEBA/ML", "chaos and penetration gates"],
  },
];

const terminalLines = [
  "[00:00] ingest: wazuh vulnerability feed synchronized",
  "[00:04] scope: windows=002,003 linux=004",
  "[00:08] risk: 163 high CVEs prioritized",
  "[00:13] action: patch cycle queued with guarded execution",
  "[00:18] stream: endpoint output attached to execution history",
  "[00:25] verify: reboot pending normalized as endpoint-side state",
  "[00:31] evidence: audit packet ready for operator review",
];

function useReducedMotion() {
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  return reduced;
}

function CyberCanvas() {
  const canvasRef = useRef(null);
  const mouseRef = useRef({ x: 0.52, y: 0.42 });
  const reducedMotion = useReducedMotion();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;
    const ctx = canvas.getContext("2d");
    let frame = 0;
    let animationId = 0;
    let width = 0;
    let height = 0;
    let particles = [];

    const buildParticles = () => {
      const count = Math.min(92, Math.max(46, Math.floor(window.innerWidth / 20)));
      particles = Array.from({ length: count }, (_, index) => ({
        x: Math.random(),
        y: Math.random(),
        vx: (Math.random() - 0.5) * 0.0009,
        vy: (Math.random() - 0.5) * 0.0007,
        size: 0.6 + Math.random() * 1.7,
        phase: index * 0.33,
      }));
    };

    const resize = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      width = canvas.offsetWidth;
      height = canvas.offsetHeight;
      canvas.width = Math.floor(width * ratio);
      canvas.height = Math.floor(height * ratio);
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
      buildParticles();
    };

    const onPointerMove = (event) => {
      mouseRef.current = {
        x: event.clientX / Math.max(window.innerWidth, 1),
        y: event.clientY / Math.max(window.innerHeight, 1),
      };
    };

    const draw = () => {
      frame += 1;
      ctx.clearRect(0, 0, width, height);
      const mouse = mouseRef.current;
      const cx = width * mouse.x;
      const cy = height * mouse.y;

      const sky = ctx.createRadialGradient(cx, cy, 40, cx, cy, Math.max(width, height));
      sky.addColorStop(0, "rgba(127, 158, 170, 0.18)");
      sky.addColorStop(0.45, "rgba(20, 30, 43, 0.18)");
      sky.addColorStop(1, "rgba(3, 6, 13, 0.02)");
      ctx.fillStyle = sky;
      ctx.fillRect(0, 0, width, height);

      ctx.save();
      ctx.translate(width * 0.5, height * 0.58);
      ctx.rotate(-0.18);
      ctx.strokeStyle = "rgba(135, 160, 174, 0.08)";
      ctx.lineWidth = 1;
      for (let i = -14; i <= 14; i += 1) {
        ctx.beginPath();
        ctx.moveTo(i * 84, -height);
        ctx.lineTo(i * 116, height);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(-width, i * 64);
        ctx.lineTo(width, i * 64);
        ctx.stroke();
      }
      ctx.restore();

      particles.forEach((particle) => {
        if (!reducedMotion) {
          particle.x += particle.vx;
          particle.y += particle.vy;
          if (particle.x < -0.04) particle.x = 1.04;
          if (particle.x > 1.04) particle.x = -0.04;
          if (particle.y < -0.04) particle.y = 1.04;
          if (particle.y > 1.04) particle.y = -0.04;
        }
        const px = particle.x * width;
        const py = particle.y * height;
        const pulse = reducedMotion ? 0.8 : 0.55 + Math.sin(frame * 0.025 + particle.phase) * 0.35;
        ctx.fillStyle = `rgba(177, 198, 205, ${0.42 + pulse * 0.22})`;
        ctx.beginPath();
        ctx.arc(px, py, particle.size + pulse * 0.8, 0, Math.PI * 2);
        ctx.fill();
      });

      for (let i = 0; i < particles.length; i += 1) {
        for (let j = i + 1; j < particles.length; j += 1) {
          const a = particles[i];
          const b = particles[j];
          const ax = a.x * width;
          const ay = a.y * height;
          const bx = b.x * width;
          const by = b.y * height;
          const distance = Math.hypot(ax - bx, ay - by);
          if (distance < 138) {
            ctx.strokeStyle = `rgba(116, 142, 154, ${0.12 * (1 - distance / 138)})`;
            ctx.beginPath();
            ctx.moveTo(ax, ay);
            ctx.lineTo(bx, by);
            ctx.stroke();
          }
        }
      }

      const wave = reducedMotion ? 0 : Math.sin(frame * 0.018) * 28;
      ctx.strokeStyle = "rgba(198, 168, 107, 0.26)";
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.ellipse(width * 0.69, height * 0.5, 190 + wave, 64 + wave * 0.2, -0.25, 0, Math.PI * 2);
      ctx.stroke();

      if (!reducedMotion) {
        animationId = requestAnimationFrame(draw);
      }
    };

    resize();
    draw();
    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", onPointerMove);
    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", onPointerMove);
    };
  }, [reducedMotion]);

  return <canvas ref={canvasRef} className="cyber-canvas" aria-hidden="true" />;
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1300);
    } catch {
      setCopied(false);
    }
  };

  return (
    <button className="copy-button" type="button" onClick={copy}>
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function CommandBlock({ lines }) {
  const text = lines.join("\n");
  return (
    <div className="command-shell">
      <CopyButton text={text} />
      <div className="shell-bar">
        <span />
        <span />
        <span />
        <strong>install.session</strong>
      </div>
      <pre>{text}</pre>
    </div>
  );
}

function HoloStack() {
  return (
    <div className="holo-stack" aria-hidden="true">
      <div className="orbital-ring ring-one" />
      <div className="orbital-ring ring-two" />
      <div className="orbital-ring ring-three" />
      <div className="holo-core">
        <div className="core-face face-top">AI Orchestrator</div>
        <div className="core-face face-mid">Patch Engine</div>
        <div className="core-face face-low">Endpoint Mesh</div>
      </div>
      <div className="floating-panel panel-one">
        <span>004</span>
        <strong>Linux healed</strong>
      </div>
      <div className="floating-panel panel-two">
        <span>CVE wave</span>
        <strong>163 prioritized</strong>
      </div>
      <div className="floating-panel panel-three">
        <span>WinRM</span>
        <strong>2 endpoints ready</strong>
      </div>
      <div className="remediation-wave" />
    </div>
  );
}

function SectionHeading({ eyebrow, title, children }) {
  return (
    <div className="section-heading">
      <p className="eyebrow">{eyebrow}</p>
      <h2>{title}</h2>
      {children ? <p>{children}</p> : null}
    </div>
  );
}

function TerminalSimulation() {
  return (
    <div className="terminal-sim" aria-label="Live patch workbench simulation">
      <div className="terminal-top">
        <div>
          <span className="terminal-dot" />
          <span className="terminal-dot" />
          <span className="terminal-dot" />
        </div>
        <strong>click2fix://patch-workbench/live</strong>
      </div>
      <div className="terminal-grid">
        <div className="terminal-pane vulnerability-pane">
          <span>Vulnerability feed</span>
          {["CVE-2025-59506", "CVE-2025-59507", "QEMU package drift", "Kernel reboot check"].map((item, index) => (
            <div className="vuln-row" key={item}>
              <b>{item}</b>
              <em style={{ width: `${86 - index * 12}%` }} />
            </div>
          ))}
        </div>
        <div className="terminal-pane execution-pane">
          <span>Execution stream</span>
          {terminalLines.map((line) => (
            <code key={line}>{line}</code>
          ))}
        </div>
        <div className="terminal-pane health-pane">
          <span>Fleet state</span>
          <div className="radar">
            <i />
            <i />
            <i />
            <b />
          </div>
        </div>
      </div>
    </div>
  );
}

function ArchitectureMap() {
  return (
    <div className="architecture-map">
      <div className="map-core">
        <span>Click2Fix</span>
        <strong>orchestration core</strong>
      </div>
      {architectureLayers.map((layer, index) => (
        <article className={`architecture-node node-${index + 1}`} key={layer.name}>
          <h3>{layer.name}</h3>
          <p>{layer.detail}</p>
          <div>
            {layer.nodes.map((node) => (
              <span key={node}>{node}</span>
            ))}
          </div>
        </article>
      ))}
    </div>
  );
}

function AppWebsite() {
  const [deployMode, setDeployMode] = useState("powershell");
  const [docQuery, setDocQuery] = useState("");
  const [selectedDocTitle, setSelectedDocTitle] = useState(documentationEntries[0].title);

  const filteredDocs = useMemo(() => {
    const query = docQuery.trim().toLowerCase();
    if (!query) return documentationEntries;
    return documentationEntries.filter((item) => {
      const blob = [item.title, item.summary, ...item.detail].join(" ").toLowerCase();
      return blob.includes(query);
    });
  }, [docQuery]);

  const selectedDoc = useMemo(
    () => documentationEntries.find((item) => item.title === selectedDocTitle) || documentationEntries[0],
    [selectedDocTitle]
  );
  const selectedRunbook = documentationRunbooks[selectedDoc.title] || documentationRunbooks["Deployment docs"];

  useEffect(() => {
    document.title = "Click2Fix | Automated Patch Management and Cyber Operations Platform";
    const description =
      "Click2Fix is an automated patch management, vulnerability remediation, endpoint orchestration, and cyber operations platform for Wazuh-managed fleets.";
    let meta = document.querySelector('meta[name="description"]');
    if (!meta) {
      meta = document.createElement("meta");
      meta.setAttribute("name", "description");
      document.head.appendChild(meta);
    }
    meta.setAttribute("content", description);

    let icon = document.querySelector('link[rel="icon"]');
    if (!icon) {
      icon = document.createElement("link");
      icon.setAttribute("rel", "icon");
      document.head.appendChild(icon);
    }
    icon.setAttribute("type", "image/svg+xml");
    icon.setAttribute("href", COMMAND_MARK);
  }, []);

  return (
    <main id="top" className="product-site">
      <CyberCanvas />
      <nav className="site-nav" aria-label="Primary navigation">
        <a className="site-brand" href="#top" aria-label="Click2Fix home">
          <img src={COMMAND_MARK} alt="" />
          <span>
            Click2Fix
            <small>Cyber Ops Platform</small>
          </span>
        </a>
        <div className="site-nav-links">
          {navItems.map(([label, href]) => (
            <a key={label} href={href}>
              {label}
            </a>
          ))}
        </div>
        <a className="nav-cta" href={LATEST_RELEASE_URL}>
          Download
        </a>
      </nav>

      <section className="hero-section">
        <div className="hero-copy">
          <p className="eyebrow">Automated patch management and cyber operations</p>
          <h1>Patch. Secure. Automate. Scale.</h1>
          <p className="hero-subtitle">
            Next-generation vulnerability remediation and endpoint orchestration built for modern
            SOC, IT, and infrastructure teams operating Wazuh-managed fleets.
          </p>
          <div className="hero-actions">
            <a className="primary-link" href="/login">
              Launch Console
            </a>
            <a className="secondary-link" href="#architecture">
              Explore Architecture
            </a>
            <a className="secondary-link" href="#workbench">
              Live Demo
            </a>
            <a className="ghost-link" href="#workbench">
              View Patch Workbench
            </a>
          </div>
          <div className="hero-telemetry" aria-label="Platform telemetry">
            {telemetry.map(([value, label]) => (
              <div key={label}>
                <strong>{value}</strong>
                <span>{label}</span>
              </div>
            ))}
          </div>
        </div>
        <HoloStack />
      </section>

      <section className="signal-ribbon" aria-label="Capability ribbon">
        {[
          "Wazuh-aware",
          "WinRM and SSH",
          "Actions and playbooks",
          "Global shell",
          "Scheduler",
          "Audit evidence",
          "v2 UESOP foundation",
        ].map((item) => (
          <span key={item}>{item}</span>
        ))}
      </section>

      <section id="platform" className="site-section split-section">
        <SectionHeading eyebrow="What is Click2Fix?" title="A cyber operations layer that closes the gap between finding risk and proving the fix.">
          Traditional remediation breaks down because every step lives somewhere else: scanners
          find CVEs, ticketing systems hold ownership, scripts live in folders, remote sessions
          disappear after they close, and evidence is reconstructed later from fragments. Click2Fix
          collapses that workflow into one operating layer. It reads Wazuh context, scopes the right
          endpoints, executes the correct remediation path, watches live target output, separates
          tool failures from endpoint-side conditions, and preserves the full proof trail.
        </SectionHeading>
        <div className="platform-story-grid">
          {platformStory.map((item) => (
            <article key={item.title}>
              <h3>{item.title}</h3>
              <p>{item.body}</p>
            </article>
          ))}
        </div>
        <div className="flow-comparison">
          <article>
            <span>Old remediation</span>
            {oldFlow.map((step) => (
              <p key={step}>{step}</p>
            ))}
          </article>
          <article className="modern-flow">
            <span>Click2Fix remediation</span>
            {newFlow.map((step) => (
              <p key={step}>{step}</p>
            ))}
          </article>
        </div>
        <aside className="remediation-intelligence" aria-label="Click2Fix remediation intelligence model">
          <div>
            <p className="eyebrow">Remediation intelligence</p>
            <h3>Not just remote execution. A closed-loop operating model.</h3>
            <p>
              Click2Fix does not stop at running a command. It binds security signal, target scope,
              execution intent, endpoint output, and final evidence into one traceable lifecycle.
            </p>
          </div>
          <div className="intelligence-bars">
            {remediationIntelligence.map((item) => (
              <div key={item.label}>
                <span>{item.label}</span>
                <strong>{item.value}</strong>
                <em>
                  <i style={{ width: item.width }} />
                </em>
              </div>
            ))}
          </div>
          <div className="intelligence-footer">
            <span>operator decision</span>
            <span>endpoint truth</span>
            <span>audit proof</span>
          </div>
        </aside>
      </section>

      <section className="site-section features-section">
        <SectionHeading eyebrow="Core systems" title="Every subsystem feels like a live operations console.">
          These are not static admin screens. They are connected execution surfaces designed for
          endpoint scale, remediation speed, and audit-grade operational clarity.
        </SectionHeading>
        <div className="feature-grid">
          {featureSystems.map((feature, index) => (
            <article className="feature-card" key={feature.title}>
              <div className="feature-index">{String(index + 1).padStart(2, "0")}</div>
              <p className="feature-label">{feature.label}</p>
              <h3>{feature.title}</h3>
              <p>{feature.body}</p>
              <div className="feature-signal">{feature.signal}</div>
              <div className="feature-tags">
                {feature.stats.map((stat) => (
                  <span key={stat}>{stat}</span>
                ))}
              </div>
            </article>
          ))}
        </div>
      </section>

      <section id="architecture" className="site-section architecture-section">
        <SectionHeading eyebrow="Interactive architecture" title="A military-grade cyber operations map without the loud colors.">
          The target architecture separates experience, control, data, response, intelligence, and
          trust layers. The v2 foundation is already moving toward microservices, event pipelines,
          tenant-scoped APIs, and zero-trust service identity.
        </SectionHeading>
        <ArchitectureMap />
      </section>

      <section id="workbench" className="site-section workbench-section">
        <SectionHeading eyebrow="Patch Workbench experience" title="A living simulation of the remediation cockpit.">
          The mini workbench is a focused lane inside the broader product story: select scope,
          inspect vulnerabilities, run shell/action/playbook jobs, and review live evidence.
        </SectionHeading>
        <TerminalSimulation />
      </section>

      <section id="deploy" className="site-section deploy-section">
        <SectionHeading eyebrow="Installation and deployment" title="Deploy from release assets, command line, ZIP, Docker, or enterprise paths.">
          Start with the appliance installer for the full platform. Use Patch Workbench Mini when a
          team needs a small remediation-only console.
        </SectionHeading>
        <div className="deploy-layout">
          <div className="deploy-docs">
            {docs.map((doc) => (
              <article className="doc-card" key={doc.title}>
                <h3>{doc.title}</h3>
                <ul>
                  {doc.items.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </article>
            ))}
          </div>
          <div className="deploy-terminal">
            <div className="command-tabs" role="tablist" aria-label="Install command tabs">
              {Object.entries(deployCommands).map(([key, value]) => (
                <button
                  key={key}
                  className={deployMode === key ? "active" : ""}
                  type="button"
                  onClick={() => setDeployMode(key)}
                >
                  {value.label}
                </button>
              ))}
            </div>
            <CommandBlock lines={deployCommands[deployMode].lines} />
          </div>
        </div>
      </section>

      <section id="docs" className="site-section docs-center-section">
        <SectionHeading eyebrow="Documentation center" title="Detailed operator guides for deployment, remediation, automation, and troubleshooting.">
          Search the guide index, open a category, and review the exact operator notes without
          leaving the product website.
        </SectionHeading>
        <div className="docs-console">
          <div className="docs-search">
            <span>cmd+k</span>
            <input
              value={docQuery}
              onChange={(event) => setDocQuery(event.target.value)}
              placeholder="Search docs, workflows, integrations..."
              aria-label="Search documentation categories"
            />
          </div>
          <div className="docs-results">
            {filteredDocs.map((item) => (
              <button
                key={item.title}
                className={selectedDoc.title === item.title ? "active" : ""}
                type="button"
                onClick={() => setSelectedDocTitle(item.title)}
              >
                <span>{item.title}</span>
                <strong>Open guide</strong>
              </button>
            ))}
          </div>
          <article className="docs-detail">
            <p className="eyebrow">Selected guide</p>
            <h3>{selectedDoc.title}</h3>
            <p>{selectedDoc.summary}</p>
            <div className="docs-detail-grid">
              {selectedDoc.detail.map((line) => (
                <span key={line}>{line}</span>
              ))}
            </div>
            <div className="runbook-grid">
              <section>
                <h4>Before you start</h4>
                {selectedRunbook.before.map((line) => (
                  <p key={line}>{line}</p>
                ))}
              </section>
              <section>
                <h4>Operator flow</h4>
                {selectedRunbook.steps.map((line, index) => (
                  <p key={line}>
                    <b>{String(index + 1).padStart(2, "0")}</b>
                    {line}
                  </p>
                ))}
              </section>
              <section>
                <h4>Expected output</h4>
                {selectedRunbook.outputs.map((line) => (
                  <p key={line}>{line}</p>
                ))}
              </section>
            </div>
          </article>
        </div>
      </section>

      <section className="site-section use-cases-section">
        <SectionHeading eyebrow="Use cases" title="Built for the teams that cannot afford slow response.">
          Click2Fix speaks the language of SOC, IT, MSP, compliance, incident response, and
          infrastructure operations.
        </SectionHeading>
        <div className="use-case-grid">
          {useCases.map(([title, body]) => (
            <article key={title}>
              <h3>{title}</h3>
              <p>{body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="site-section trust-section">
        <SectionHeading eyebrow="Security and trust" title="Execution power wrapped in controls, evidence, and future zero-trust direction.">
          The product is designed around secure communications, visible execution, audit trails,
          and enterprise control surfaces that can mature into signed, tenant-aware, zero-trust
          response pipelines.
        </SectionHeading>
        <div className="trust-grid">
          {trustControls.map((item) => (
            <div key={item}>
              <span />
              <p>{item}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="roadmap" className="site-section roadmap-section">
        <SectionHeading eyebrow="Versions and roadmap" title="Stable appliance today. Native UESOP platform tomorrow.">
          Version history and roadmap are derived from the repository docs and tracker files.
        </SectionHeading>
        <div className="version-grid">
          {versions.map((item) => (
            <article key={item.version}>
              <span>{item.version}</span>
              <h3>{item.title}</h3>
              <p>{item.detail}</p>
            </article>
          ))}
        </div>
        <div className="roadmap-grid">
          {roadmap.map((item) => (
            <article key={item.phase}>
              <span>{item.phase} / {item.horizon}</span>
              <h3>{item.title}</h3>
              {item.points.map((point) => (
                <p key={point}>{point}</p>
              ))}
            </article>
          ))}
        </div>
      </section>

      <section className="site-section community-section">
        <SectionHeading eyebrow="Community and support" title="Release tracking, roadmap transparency, and operator feedback loops.">
          Follow GitHub releases, inspect changelogs, open issues, and download pinned packages
          from the public release channel.
        </SectionHeading>
        <div className="community-actions">
          <a className="primary-link" href={LATEST_RELEASE_URL}>Latest release</a>
          <a className="secondary-link" href={RELEASES_URL}>Version history</a>
          <a className="secondary-link" href={`${REPO_URL}/issues`}>Issue tracker</a>
          <a className="ghost-link" href={`${REPO_URL}/commits`}>Changelog</a>
        </div>
      </section>

      <footer className="site-footer">
        <a href="#top" className="site-brand" aria-label="Back to top">
          <img src={COMMAND_MARK} alt="" />
          <span>
            Click2Fix
            <small>Cyber Ops Platform</small>
          </span>
        </a>
        <p>
          Developed by{" "}
          <a href="https://helisudani0.github.io/Heli_Sudani-Portfolio/">
            Heli Sudani
          </a>
        </p>
      </footer>
    </main>
  );
}

export default AppWebsite;
