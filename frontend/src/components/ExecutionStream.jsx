import { useEffect, useMemo, useRef, useState } from "react";
import { executionSocket } from "../api/socket";
import api from "../api/client";
import { getAlerts } from "../api/wazuh";
import { formatWazuhTimestamp, nowUtcIso } from "../utils/time";
import { buildHumanReadableOutput, normalizeOutputText } from "../utils/output";

const UPDATE_ACTION_IDS = new Set([
  "patch-windows",
  "patch-linux",
  "windows-os-update",
  "fleet-software-update",
  "package-update",
  "software-install-upgrade",
]);
const SCAN_ACTION_IDS = new Set(["ioc-scan", "toc-scan", "yara-scan", "collect-forensics", "collect-memory", "malware-scan", "threat-hunt-persistence"]);

const resolveTargetStatus = (target, isUpdateAction) => {
  if (isUpdateAction) {
    const updateReport = collectUpdateReport(target?.stdout, target?.update_report);
    const outcome = String(updateReport?.metrics?.outcome || "").trim().toUpperCase();
    if (outcome === "WAITING_REBOOT") return { label: "WAITING_REBOOT", tone: "pending" };
    if (outcome === "PARTIAL") return { label: "PARTIAL", tone: "pending" };
    if (outcome === "FAILED") return { label: "FAILED", tone: "failed" };
    if (outcome === "SUCCESS") return { label: "SUCCESS", tone: "success" };
  }
  return target?.ok ? { label: "SUCCESS", tone: "success" } : { label: "FAILED", tone: "failed" };
};

const normalizeStep = (row) => {
  if (Array.isArray(row)) {
    return {
      step: row[0],
      stdout: row[1],
      stderr: row[2],
      status: row[3],
    };
  }
  return {
    step: row?.step || "step",
    stdout: row?.stdout || "",
    stderr: row?.stderr || "",
    status: row?.status || "UNKNOWN",
  };
};

const normalizeTarget = (row) => {
  if (!row || typeof row !== "object") {
    return {
      agent_id: "",
      agent_name: "",
      target_ip: "",
      platform: "",
      status: "",
      ok: false,
      status_code: 0,
      stdout: "",
      stderr: "",
      created_at: null,
      update_report: null,
      scan_report: null,
      scan_report_content: null,
    };
  }
  const rawStatus = String(row.status || "").trim();
  const normalizedStatus = rawStatus
    ? rawStatus.toUpperCase()
    : (row.ok === true ? "SUCCESS" : row.ok === false ? "FAILED" : "");
  return {
    agent_id: String(row.agent_id || row.agent || ""),
    agent_name: String(row.agent_name || ""),
    target_ip: String(row.target_ip || row.ip || ""),
    platform: String(row.platform || ""),
    status: normalizedStatus,
    ok: Boolean(row.ok),
    status_code: Number(row.status_code || 0),
    stdout: String(row.stdout || ""),
    stderr: String(row.stderr || ""),
    created_at: row.created_at || null,
    update_report: row.update_report && typeof row.update_report === "object" ? row.update_report : null,
    scan_report: row.scan_report && typeof row.scan_report === "object" ? row.scan_report : null,
    scan_report_content:
      row.scan_report_content && typeof row.scan_report_content === "object" ? row.scan_report_content : null,
  };
};

const normalizeEvidenceAlert = (alert) => {
  if (!alert || typeof alert !== "object") return null;
  const raw = alert.id ?? alert.alert_id;
  if (raw === null || raw === undefined || typeof raw === "object") return null;
  const id = String(raw).trim();
  if (!id) return null;
  const rule = alert.rule || {};
  const tsRaw = alert.timestamp || alert.time || alert["@timestamp"] || alert.date || "";
  return {
    id,
    rule: rule.description || rule.id || alert.message || "Alert",
    level: rule.level ?? alert.level ?? "n/a",
    timestampRaw: tsRaw,
    timestamp: formatWazuhTimestamp(tsRaw),
  };
};

const extractEvidenceLines = (stdout) => {
  if (!stdout) return [];
  return String(stdout)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => line.startsWith("C2F_LOG "))
    .map((line) => line.slice("C2F_LOG ".length));
};

const extractEvidenceSummary = (stdout) => {
  const lines = extractEvidenceLines(stdout);
  if (lines.length) {
    const evidence = lines.filter((line) => line.includes(" evidence="));
    if (evidence.length) return evidence[evidence.length - 1] || "";
    return lines[lines.length - 1] || "";
  }
  const clean = stripEvidenceFromStdout(stdout);
  const last = String(clean)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(-1)[0];
  return last || "";
};

const stripEvidenceFromStdout = (stdout) => {
  if (!stdout) return "";
  return String(stdout)
    .split(/\r?\n/)
    .filter((line) => !String(line).trim().startsWith("C2F_LOG "))
    .join("\n")
    .trim();
};

const parseHealthcheck = (stdout) => {
  const clean = stripEvidenceFromStdout(stdout);
  const info = {};
  String(clean)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .forEach((line) => {
      if (line.toLowerCase() === "healthcheck ok") {
        info.ok = true;
        return;
      }
      const idx = line.indexOf("=");
      if (idx <= 0) return;
      const key = line.slice(0, idx).trim();
      const value = line.slice(idx + 1).trim();
      if (key) info[key] = value;
    });
  return info;
};

const parseEvidencePairs = (stdout) => (
  extractEvidenceLines(stdout)
    .map((line) => {
      const marker = " evidence=";
      const idx = line.indexOf(marker);
      if (idx < 0) return null;
      const payload = line.slice(idx + marker.length).trim();
      const eq = payload.indexOf("=");
      if (eq <= 0) return null;
      return {
        key: payload.slice(0, eq).trim(),
        value: payload.slice(eq + 1).trim(),
      };
    })
    .filter(Boolean)
);

const parseIntMaybe = (value) => {
  const text = String(value ?? "").trim();
  if (!text) return null;
  if (!/^[+-]?\d+$/.test(text)) return null;
  return Number.parseInt(text, 10);
};

const summarizeIssueText = (value, limit = 4000) => {
  const text = String(value || "")
    .replace(/\r?\n/g, " | ")
    .replace(/\s{2,}/g, " ")
    .trim();
  if (!text) return "";
  if (text.length <= limit) return text;
  return `${text.slice(0, limit)}...`;
};

const parseSummaryMetrics = (stdout) => {
  const clean = stripEvidenceFromStdout(stdout);
  const lines = String(clean)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const summaryLine = lines.find((line) => line.includes("="));
  if (!summaryLine) return {};
  const out = {};
  const regex = /([a-zA-Z_]+)=([^\s]+)/g;
  let match = regex.exec(summaryLine);
  while (match) {
    const key = String(match[1] || "").trim();
    const value = String(match[2] || "").trim().replace(/[;,]$/, "");
    if (key) out[key] = value;
    match = regex.exec(summaryLine);
  }
  if (out.applicable !== undefined && out.updates_applicable === undefined) out.updates_applicable = out.applicable;
  if (out.installable !== undefined && out.updates_installable === undefined) out.updates_installable = out.installable;
  if (out.installed !== undefined && out.updates_installed === undefined) out.updates_installed = out.installed;
  if (out.failed !== undefined && out.updates_failed === undefined) out.updates_failed = out.failed;
  if (out.remaining !== undefined && out.updates_remaining === undefined) out.updates_remaining = out.remaining;
  if (out.skipped_interactive !== undefined && out.updates_skipped_interactive === undefined) out.updates_skipped_interactive = out.skipped_interactive;
  return out;
};

const parseUpdateEntry = (rawValue) => {
  const raw = String(rawValue || "").trim();
  const parts = raw.split("|").map((p) => p.trim());
  const entry = { raw };
  if (!parts.length) return entry;

  if (parts.length >= 4 && parseIntMaybe(parts[0]) !== null && parseIntMaybe(parts[1]) !== null) {
    entry.result_code = parseIntMaybe(parts[0]);
    entry.hresult = parseIntMaybe(parts[1]);
    entry.identifier = parts[2] || "";
    entry.title = parts.slice(3).join("|").trim();
    return entry;
  }

  if (["interactive", "manual", "not_installable"].includes((parts[0] || "").toLowerCase())) {
    entry.reason = (parts[0] || "").toLowerCase();
    entry.identifier = parts[1] || "";
    entry.title = parts.slice(2).join("|").trim();
    return entry;
  }

  entry.identifier = parts[0] || "";
  entry.title = parts[1] || "";
  parts.slice(2).forEach((segment) => {
    if (!segment.includes("=")) return;
    const [k, v] = segment.split("=", 2);
    const key = String(k || "").trim().toLowerCase();
    const value = String(v || "").trim();
    if (["rc", "result", "result_code"].includes(key)) {
      entry.result_code = parseIntMaybe(value) ?? value;
      return;
    }
    if (["hr", "hresult"].includes(key)) {
      entry.hresult = parseIntMaybe(value) ?? value;
      return;
    }
    entry[key] = value;
  });
  return entry;
};

const collectUpdateReport = (stdout, existingReport = null) => {
  const seed = existingReport && typeof existingReport === "object" ? existingReport : null;
  const pairs = parseEvidencePairs(stdout);
  if (!pairs.length && !seed) return null;

  const seedIndexed = (items) => (
    (Array.isArray(items) ? items : [])
      .map((entry, idx) => ({ idx, entry }))
  );

  const groups = {
    available: seedIndexed(seed?.available),
    installed: seedIndexed(seed?.installed),
    failed: seedIndexed(seed?.failed),
    remaining: seedIndexed(seed?.remaining),
    skipped: seedIndexed(seed?.skipped),
  };
  const fallback = {
    available: [],
    installed: [],
    failed: [],
  };
  const metrics = { ...(seed?.metrics || {}) };
  let sawUpdateEvidence = Boolean(
    (Array.isArray(seed?.available) && seed.available.length)
    || (Array.isArray(seed?.installed) && seed.installed.length)
    || (Array.isArray(seed?.failed) && seed.failed.length)
    || (Array.isArray(seed?.remaining) && seed.remaining.length)
    || (Array.isArray(seed?.skipped) && seed.skipped.length)
  );

  const pushIndexed = (bucket, prefix, key, value) => {
    const suffix = key.slice(prefix.length);
    const idx = /^\d+$/.test(suffix) ? Number.parseInt(suffix, 10) : Number.MAX_SAFE_INTEGER;
    bucket.push({ idx, entry: parseUpdateEntry(value) });
  };

  pairs.forEach(({ key, value }) => {
    if (!key) return;
    if (
      [
        "outcome",
        "updates_applicable",
        "updates_installable",
        "updates_discovered",
        "update_profile",
        "updates_skipped_interactive",
        "updates_skipped_non_target",
        "updates_skipped",
        "updates_unresolved",
        "updates_no_change",
        "updates_installed",
        "updates_failed",
        "updates_remaining",
        "updates_remaining_non_target",
        "updates_installed_estimate",
        "updates_failed_estimate",
        "download_result",
        "install_result",
        "reboot_required",
        "reboot_pending",
        "reboot_scheduled",
        "reboot_policy",
      ].includes(key)
    ) {
      sawUpdateEvidence = true;
      metrics[key] = value;
      return;
    }
    if (key.startsWith("available_update_")) {
      sawUpdateEvidence = true;
      pushIndexed(groups.available, "available_update_", key, value);
      return;
    }
    if (key.startsWith("installed_update_")) {
      sawUpdateEvidence = true;
      pushIndexed(groups.installed, "installed_update_", key, value);
      return;
    }
    if (key.startsWith("failed_update_")) {
      sawUpdateEvidence = true;
      pushIndexed(groups.failed, "failed_update_", key, value);
      return;
    }
    if (key.startsWith("remaining_update_")) {
      sawUpdateEvidence = true;
      pushIndexed(groups.remaining, "remaining_update_", key, value);
      return;
    }
    if (key.startsWith("skipped_update_")) {
      sawUpdateEvidence = true;
      pushIndexed(groups.skipped, "skipped_update_", key, value);
      return;
    }
    if (key.startsWith("update_skipped_")) {
      sawUpdateEvidence = true;
      pushIndexed(groups.skipped, "update_skipped_", key, value);
      return;
    }
    if (/^update_\d+$/.test(key)) {
      sawUpdateEvidence = true;
      pushIndexed(fallback.available, "update_", key, value);
      return;
    }
    if (key.startsWith("update_result_")) {
      sawUpdateEvidence = true;
      const suffix = key.slice("update_result_".length);
      const idx = /^\d+$/.test(suffix) ? Number.parseInt(suffix, 10) : Number.MAX_SAFE_INTEGER;
      const entry = parseUpdateEntry(value);
      const rc = parseIntMaybe(entry.result_code);
      if (rc === 2 || rc === 3) fallback.installed.push({ idx, entry });
      else fallback.failed.push({ idx, entry });
    }
  });

  const normalize = (items) => items
    .sort((a, b) => a.idx - b.idx)
    .map((item) => item.entry);

  const dedupeEntries = (items) => {
    const seen = new Set();
    return items.filter((entry) => {
      const key = [
        String(entry?.identifier || ""),
        String(entry?.title || ""),
        String(entry?.reason || ""),
        String(entry?.result_code ?? ""),
        String(entry?.hresult ?? ""),
        String(entry?.available || ""),
        String(entry?.version || ""),
      ].join("|");
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  };

  const available = dedupeEntries(groups.available.length ? normalize(groups.available) : normalize(fallback.available));
  const installed = dedupeEntries(groups.installed.length ? normalize(groups.installed) : normalize(fallback.installed));
  const failed = dedupeEntries(groups.failed.length ? normalize(groups.failed) : normalize(fallback.failed));
  const remaining = dedupeEntries(normalize(groups.remaining));
  const skipped = dedupeEntries(normalize(groups.skipped));

  if (sawUpdateEvidence) {
    const summaryMetrics = parseSummaryMetrics(stdout);
    const allowedSummary = new Set([
      "outcome",
      "updates_applicable",
      "updates_installable",
      "updates_discovered",
      "update_profile",
      "updates_skipped_interactive",
      "updates_skipped_non_target",
      "updates_skipped",
      "updates_unresolved",
      "updates_no_change",
      "updates_installed",
      "updates_failed",
      "updates_remaining",
      "updates_remaining_non_target",
      "updates_installed_estimate",
      "updates_failed_estimate",
      "download_result",
      "install_result",
      "reboot_required",
      "reboot_pending",
      "reboot_scheduled",
      "reboot_policy",
    ]);
    Object.entries(summaryMetrics).forEach(([k, v]) => {
      if (!allowedSummary.has(k)) return;
      if (metrics[k] === undefined) metrics[k] = v;
    });
  }
  if (metrics.updates_installed === undefined && installed.length) {
    metrics.updates_installed = String(installed.length);
  }
  if (metrics.updates_failed === undefined && failed.length) {
    metrics.updates_failed = String(failed.length);
  }
  if (metrics.updates_remaining === undefined) {
    if (remaining.length) {
      metrics.updates_remaining = String(remaining.length);
    } else {
      const applicable = parseIntMaybe(metrics.updates_applicable);
      const installedCount = parseIntMaybe(metrics.updates_installed);
      if (applicable !== null && installedCount !== null) {
        metrics.updates_remaining = String(Math.max(applicable - installedCount, 0));
      }
    }
  }

  const hasAny = Object.keys(metrics).length || available.length || installed.length || failed.length || remaining.length || skipped.length;
  if (!hasAny) return null;
  return {
    metrics,
    available,
    installed,
    failed,
    remaining,
    skipped,
  };
};

const parseScanEntry = (rawValue) => {
  const raw = String(rawValue || "").trim();
  const parts = raw.split("|").map((p) => p.trim());
  const entry = { raw };
  if (!parts.length) return entry;
  entry.category = parts[0] || "";
  if (parts.length > 1) entry.name = parts[1] || "";
  parts.slice(2).forEach((segment) => {
    if (!segment.includes("=")) return;
    const [k, v] = segment.split("=", 2);
    const key = String(k || "").trim().toLowerCase();
    const value = String(v || "").trim();
    if (key) entry[key] = value;
  });
  return entry;
};

const resolveScanRecommendation = (entry) => {
  const value = entry?.recommendation || entry?.remediation || entry?.solution || entry?.fix || "";
  return String(value || "").trim();
};

const formatScanDetail = (entry) => {
  const parts = [];
  if (entry?.process) parts.push(`process=${entry.process}`);
  if (entry?.pid) parts.push(`pid=${entry.pid}`);
  if (entry?.file) parts.push(`file=${entry.file}`);
  if (entry?.path) parts.push(`path=${entry.path}`);
  if (entry?.reason) parts.push(`reason=${entry.reason}`);
  if (entry?.detail) parts.push(String(entry.detail));
  if (!parts.length && entry?.raw) parts.push(String(entry.raw));
  return summarizeIssueText(parts.join(" | "), 1800);
};

const collectScanReport = (stdout, existingReport = null) => {
  const seed = existingReport && typeof existingReport === "object" ? existingReport : null;
  const pairs = parseEvidencePairs(stdout);
  if (!pairs.length && !seed) return null;

  const seedIndexed = (items) => (
    (Array.isArray(items) ? items : [])
      .map((entry, idx) => ({ idx, entry }))
  );
  const groups = {
    hits: seedIndexed(seed?.hits),
    artifacts: seedIndexed(seed?.artifacts),
  };
  const metrics = { ...(seed?.metrics || {}) };

  const pushIndexed = (bucket, prefix, key, value) => {
    const suffix = key.slice(prefix.length);
    const idx = /^\d+$/.test(suffix) ? Number.parseInt(suffix, 10) : Number.MAX_SAFE_INTEGER;
    bucket.push({ idx, entry: parseScanEntry(value) });
  };

  pairs.forEach(({ key, value }) => {
    if (!key) return;
    if (
      [
        "scan_type",
        "scan_scope",
        "scan_engine",
        "scan_report_path",
        "scan_total_examined",
        "scan_matches",
        "scan_status",
        "scan_summary",
      ].includes(key)
    ) {
      metrics[key] = value;
      return;
    }
    if (key.startsWith("scan_hit_")) {
      pushIndexed(groups.hits, "scan_hit_", key, value);
      return;
    }
    if (key.startsWith("artifact_")) {
      pushIndexed(groups.artifacts, "artifact_", key, value);
    }
  });

  const normalize = (items) => items
    .sort((a, b) => a.idx - b.idx)
    .map((item) => item.entry);
  const dedupe = (items) => {
    const seen = new Set();
    return items.filter((entry) => {
      const id = `${entry?.category || ""}|${entry?.name || ""}|${entry?.raw || ""}`;
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    });
  };

  const hits = dedupe(normalize(groups.hits));
  const artifacts = dedupe(normalize(groups.artifacts));
  const hasAny = Object.keys(metrics).length || hits.length || artifacts.length;
  if (!hasAny) return null;
  return { metrics, hits, artifacts };
};

const formatUpdateIdentifier = (value) => {
  const id = String(value || "").trim();
  if (!id) return "";
  if (/^\d+$/.test(id)) return `KB${id}`;
  return id;
};

const formatUpdatePrimary = (entry) => {
  const identifier = formatUpdateIdentifier(entry?.identifier);
  const title = String(entry?.title || "").trim();
  if (identifier && title) return `${identifier} - ${title}`;
  if (title) return title;
  if (identifier) return identifier;
  return String(entry?.raw || "-");
};

const formatUpdateDetail = (entry) => {
  const parts = [];
  if (entry?.reason) parts.push(`reason=${entry.reason}`);
  if (entry?.result_code !== undefined && entry?.result_code !== null && String(entry.result_code) !== "") {
    parts.push(`rc=${entry.result_code}`);
  }
  if (entry?.hresult !== undefined && entry?.hresult !== null && String(entry.hresult) !== "") {
    parts.push(`hresult=${entry.hresult}`);
  }
  // When actions emit before/after version evidence (e.g. winget upgrades), surface it here so
  // "installed" vs "upgraded/replaced" is obvious in the UI.
  const installedBefore = String(entry?.installed_before || "").trim();
  const installedAfter = String(entry?.installed_after || "").trim();
  const availableBefore = String(entry?.available_before || "").trim();
  const available = String(entry?.available || "").trim();
  if (installedBefore && installedAfter && installedBefore !== installedAfter) {
    parts.push(`version=${installedBefore} -> ${installedAfter}`);
  } else if (installedAfter) {
    parts.push(`version=${installedAfter}`);
  } else if (installedBefore && available) {
    parts.push(`version=${installedBefore} -> ${available}`);
  }
  if (availableBefore && installedAfter && availableBefore !== installedAfter) {
    parts.push(`expected=${availableBefore}`);
  }
  if (
    !parts.length
    && entry?.raw
    && entry.raw !== formatUpdatePrimary(entry)
    && !(String(entry.raw || "").startsWith("|") && String(entry?.title || "").trim())
  ) {
    parts.push(entry.raw);
  }
  return parts.join(" | ");
};

const formatDuration = (startedAt, finishedAt) => {
  const start = startedAt ? new Date(startedAt).getTime() : 0;
  const end = finishedAt ? new Date(finishedAt).getTime() : 0;
  if (!start || !end || end < start) return "-";
  const totalSeconds = Math.round((end - start) / 1000);
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}m ${seconds}s`;
};

const executionStatusTone = (status) => {
  const normalized = String(status || "").toUpperCase();
  if (normalized === "SUCCESS") return "success";
  if (["FAILED", "CANCELLED", "KILLED"].includes(normalized)) return "failed";
  if (normalized === "PAUSED") return "neutral";
  return "pending";
};

const parseExecutionArgs = (value) => {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string") return value;
  const text = value.trim();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

const extractExecutionCommand = (argsValue) => {
  const parsed = parseExecutionArgs(argsValue);
  if (Array.isArray(parsed)) {
    const first = parsed.find((item) => typeof item === "string" && item.trim());
    return first ? first.trim() : "";
  }
  if (parsed && typeof parsed === "object") {
    for (const key of ["command", "custom_command", "script", "cmd", "shell_command"]) {
      const candidate = parsed[key];
      if (typeof candidate === "string" && candidate.trim()) return candidate.trim();
    }
    const firstText = Object.values(parsed).find((item) => typeof item === "string" && item.trim());
    return typeof firstText === "string" ? firstText.trim() : "";
  }
  if (typeof parsed === "string") return parsed.trim();
  return "";
};

const resolveExecutionShellAndCommand = (actionId, argsValue) => {
  const commandUsed = extractExecutionCommand(argsValue);
  if (!commandUsed) return { shell: "", command: "", commandUsed: "" };
  const cmdMatch = commandUsed.match(/^cmd(?:\.exe)?\s+\/c\s+([\s\S]+)$/i);
  if (cmdMatch) {
    const command = String(cmdMatch[1] || "").trim();
    return { shell: "CMD", command: command || commandUsed, commandUsed };
  }
  const action = String(actionId || "").trim().toLowerCase();
  const shell = action === "global-shell" ? "PowerShell" : "";
  return { shell, command: commandUsed, commandUsed };
};

const normalizeCommandOutput = (value) => normalizeOutputText(value);

const extractScanReportIssueFromContent = (content) => {
  if (!content || typeof content !== "object") return "";
  const format = String(content.format || "").trim().toLowerCase();
  if (format === "json") {
    const payload = content.json;
    if (!payload || typeof payload !== "object") return "";
    const direct = [
      payload.error,
      payload.message,
      payload.summary?.error,
      payload.summary?.message,
      payload.result?.error,
      payload.result?.message,
    ].find((value) => typeof value === "string" && value.trim());
    if (direct) return summarizeIssueText(direct);
    const collections = [payload.errors, payload.failures, payload.issues];
    for (const collection of collections) {
      if (!Array.isArray(collection) || !collection.length) continue;
      const text = collection
        .slice(0, 8)
        .map((entry) => (typeof entry === "string" ? entry : JSON.stringify(entry)))
        .filter(Boolean)
        .join(" | ");
      if (text) return summarizeIssueText(text);
    }
    return "";
  }
  if (format === "text") {
    return summarizeIssueText(content.text || "");
  }
  return "";
};

const extractTargetIssue = (target, { isUpdateAction, isScanAction }) => {
  const stderr = summarizeIssueText(target?.stderr || "");
  if (stderr) return stderr;

  const pairs = parseEvidencePairs(target?.stdout || "");
  const explicitError = pairs
    .filter((pair) => String(pair?.key || "").toLowerCase() === "error")
    .map((pair) => summarizeIssueText(pair?.value || ""))
    .filter(Boolean)
    .pop();
  if (explicitError) return explicitError;

  if (isUpdateAction) {
    const report = collectUpdateReport(target?.stdout || "", target?.update_report || null);
    const failedEntry = Array.isArray(report?.failed) ? report.failed[0] : null;
    if (failedEntry) {
      const detail = formatUpdateDetail(failedEntry);
      return summarizeIssueText(`Update failed: ${formatUpdatePrimary(failedEntry)}${detail ? ` | ${detail}` : ""}`);
    }
    const pendingEntry = Array.isArray(report?.remaining) ? report.remaining[0] : null;
    const unresolvedEntry = Array.isArray(report?.skipped)
      ? report.skipped.find((entry) => String(entry?.reason || "").toLowerCase() !== "no_applicable_update")
      : null;
    if (unresolvedEntry) {
      const detail = formatUpdateDetail(unresolvedEntry);
      return summarizeIssueText(`Update unresolved: ${formatUpdatePrimary(unresolvedEntry)}${detail ? ` | ${detail}` : ""}`);
    }
    if (pendingEntry && !target?.ok) {
      const detail = formatUpdateDetail(pendingEntry);
      return summarizeIssueText(`Update pending: ${formatUpdatePrimary(pendingEntry)}${detail ? ` | ${detail}` : ""}`);
    }
  }

  if (isScanAction) {
    const report = collectScanReport(target?.stdout || "", target?.scan_report || null);
    const reportContentIssue = extractScanReportIssueFromContent(target?.scan_report_content || null);
    const scanStatus = String(report?.metrics?.scan_status || "").toUpperCase();
    if (scanStatus === "MATCH") {
      const firstHit = Array.isArray(report?.hits) ? report.hits[0] : null;
      if (firstHit) {
        const detail = formatScanDetail(firstHit);
        const recommendation = resolveScanRecommendation(firstHit);
        return summarizeIssueText(
          `Matched indicator: ${firstHit?.name || firstHit?.category || "unknown"}${detail ? ` | ${detail}` : ""}${recommendation ? ` | recommendation=${recommendation}` : ""}`
        );
      }
      const summary = summarizeIssueText(report?.metrics?.scan_summary || "");
      if (summary) return summary;
      return "Matched indicator(s) detected by scan.";
    }
    if (!target?.ok && reportContentIssue) return reportContentIssue;
    const scanSummary = summarizeIssueText(report?.metrics?.scan_summary || "");
    if (scanStatus && !["SUCCESS", "CLEAN", "OK", "MATCH"].includes(scanStatus)) {
      if (scanSummary) return scanSummary;
      return `scan_status=${scanStatus}`;
    }
    if (!target?.ok && scanSummary) return scanSummary;
  }

  const latest = summarizeIssueText(extractEvidenceSummary(target?.stdout || ""));
  if (!target?.ok && latest) return latest;
  if (!target?.ok) return "Execution failed without endpoint error details.";
  return "";
};

export default function ExecutionStream({ executionId }) {

  const [events, setEvents] = useState([]);
  const [targets, setTargets] = useState([]);
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [meta, setMeta] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [streamEnabled, setStreamEnabled] = useState(false);
  const [evidenceAlerts, setEvidenceAlerts] = useState([]);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState("");
  const [controlBusy, setControlBusy] = useState(false);
  const [controlError, setControlError] = useState("");
  const [controlMessage, setControlMessage] = useState("");
  const autoStreamRef = useRef(null);

  useEffect(() => {
    if (!executionId) return;
    setLoading(true);
    setError(null);
    setControlError("");
    setControlMessage("");
    autoStreamRef.current = null;
    api.get(`/executions/${executionId}`)
      .then((res) => {
        const payload = res.data || {};
        const items = Array.isArray(payload.steps) ? payload.steps : [];
        setEvents(items.map(normalizeStep));
        const rawTargets = Array.isArray(payload.targets) ? payload.targets : [];
        const normalizedTargets = rawTargets.map(normalizeTarget);
        setTargets(normalizedTargets);
        setSelectedTargetId((prev) => {
          if (prev && normalizedTargets.some((t) => t.agent_id === prev)) return prev;
          return normalizedTargets[0]?.agent_id || "";
        });
        setMeta(payload);
      })
      .catch((err) => {
        setError(err.response?.data?.detail || err.message || "Failed to load execution");
      })
      .finally(() => setLoading(false));
  }, [executionId]);

  useEffect(() => {
    const status = String(meta?.execution?.status || "").toUpperCase();
    if (!executionId) return;
    if (status !== "RUNNING") return;
    if (autoStreamRef.current === executionId) return;
    autoStreamRef.current = executionId;
    setStreamEnabled(true);
  }, [executionId, meta?.execution?.status]);

  useEffect(() => {
    setEvidenceAlerts([]);
    setEvidenceError("");
    if (!executionId) return;
    if (!selectedTargetId) return;
    const execution = meta?.execution || null;
    if (!execution?.started_at) return;

    const startedAt = new Date(execution.started_at);
    if (Number.isNaN(startedAt.getTime())) return;

    const endBase = execution.finished_at ? new Date(execution.finished_at) : new Date();
    const endAt = Number.isNaN(endBase.getTime()) ? new Date() : endBase;
    const windowEnd = new Date(endAt.getTime() + 10 * 60 * 1000);

    let cancelled = false;
    setEvidenceLoading(true);

    getAlerts("", 25, {
      agentId: selectedTargetId,
      agentOnly: true,
      start: startedAt.toISOString(),
      end: windowEnd.toISOString(),
    })
      .then((res) => {
        if (cancelled) return;
        const data = res?.data || [];
        const items = (Array.isArray(data) ? data : [])
          .map(normalizeEvidenceAlert)
          .filter(Boolean);
        setEvidenceAlerts(items);
      })
      .catch((err) => {
        if (cancelled) return;
        setEvidenceError(err.response?.data?.detail || err.message || "Failed to load related alerts");
      })
      .finally(() => {
        if (cancelled) return;
        setEvidenceLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [executionId, meta?.execution, selectedTargetId]);

  useEffect(() => {
    if (!executionId || !streamEnabled) return;

    let activeSocket = null;
    let closedByClient = false;
    let reconnectTimer = null;
    let reconnectAttempts = 0;

    const clearReconnectTimer = () => {
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
    };

    const connect = () => {
      clearReconnectTimer();
      activeSocket = executionSocket(executionId);

      activeSocket.onopen = () => {
        reconnectAttempts = 0;
      };

      activeSocket.onmessage = e => {
        try {
          const msg = JSON.parse(e.data);
          if (msg && typeof msg === "object" && msg.type === "heartbeat") return;
          setEvents((prev) => [...prev, normalizeStep(msg)]);
          if (
            msg
            && typeof msg === "object"
            && msg.type === "target_done"
            && typeof msg.step === "string"
            && msg.step.startsWith("endpoint:")
          ) {
            const agentId = msg.step.split(":", 2)[1] || "";
            if (!agentId) return;
            const ok = String(msg.status || "").toUpperCase() === "SUCCESS";
            setTargets((prev) => {
              const existing = prev.find((t) => t.agent_id === agentId);
              const updated = {
                ...(existing || {}),
                agent_id: agentId,
                ok,
                stdout: String(msg.stdout || ""),
                stderr: String(msg.stderr || ""),
              };
              if (!existing) return [updated, ...prev];
              return prev.map((t) => (t.agent_id === agentId ? updated : t));
            });
          }
          if (
            msg
            && typeof msg === "object"
            && msg.type === "target_log"
            && typeof msg.step === "string"
            && msg.step.startsWith("endpoint:")
          ) {
            const agentId = msg.step.split(":", 2)[1] || "";
            const chunk = String(msg.stdout || "");
            if (!agentId || !chunk) return;
            setTargets((prev) => {
              const existing = prev.find((t) => t.agent_id === agentId);
              const base = existing?.stdout ? `${existing.stdout}\n${chunk}` : chunk;
              const lines = base.split(/\r?\n/);
              const trimmed = lines.length > 800 ? lines.slice(-800).join("\n") : base;
              const updated = {
                ...(existing || {}),
                agent_id: agentId,
                stdout: trimmed,
              };
              if (!existing) return [updated, ...prev];
              return prev.map((t) => (t.agent_id === agentId ? updated : t));
            });
          }
        } catch {
          // Ignore malformed stream messages.
        }
      };

      activeSocket.onerror = () => {
        // Let onclose drive reconnect decisions.
      };

      activeSocket.onclose = (e) => {
        if (closedByClient) return;

        if (e.code === 1000 || e.code === 1001) {
          return;
        }

        if (e.code === 4401 || e.code === 4403) {
          return;
        }

        reconnectAttempts += 1;
        const delayMs = Math.min(15000, 1000 * (2 ** Math.min(reconnectAttempts, 4)));
        reconnectTimer = setTimeout(() => {
          if (!closedByClient) connect();
        }, delayMs);
      };
    };

    connect();

    return () => {
      closedByClient = true;
      clearReconnectTimer();
      if (activeSocket && activeSocket.readyState <= WebSocket.OPEN) {
        activeSocket.close(1000, "stream disabled");
      }
    };

  }, [executionId, streamEnabled]);

  const selectedTarget = targets.find((t) => t.agent_id === selectedTargetId) || null;
  const execution = meta?.execution || null;
  const executionStatus = String(execution?.status || "").toUpperCase();
  const canPauseExecution = executionStatus === "RUNNING";
  const canResumeExecution = executionStatus === "PAUSED";
  const canControlExecution = canPauseExecution || canResumeExecution;
  const canKillExecution = executionStatus === "RUNNING" || executionStatus === "PAUSED";
  const actionMeta = meta?.action || null;
  const playbookMeta = meta?.playbook || null;
  const displayTitle = actionMeta?.label
    ? actionMeta.label
    : playbookMeta?.name
      ? playbookMeta.name
      : execution?.action || execution?.playbook || "Execution";
  const displayDescription =
    actionMeta?.description || playbookMeta?.description || "";
  const actionId = execution?.action || "";
  const commandMeta = resolveExecutionShellAndCommand(actionId, execution?.args);
  const normalizedActionId = String(actionId || "").trim().toLowerCase();
  const isUpdateAction = UPDATE_ACTION_IDS.has(normalizedActionId);
  const isScanAction = SCAN_ACTION_IDS.has(normalizedActionId);
  const selectedUpdateReport = selectedTarget
    && isUpdateAction
    ? collectUpdateReport(selectedTarget.stdout, selectedTarget.update_report)
    : null;
  const updateRows = selectedUpdateReport
    ? [
        ...selectedUpdateReport.available.map((entry) => ({ state: "Available", tone: "neutral", entry })),
        ...selectedUpdateReport.installed.map((entry) => ({ state: "Updated", tone: "success", entry })),
        ...selectedUpdateReport.failed.map((entry) => ({ state: "Not Updated", tone: "failed", entry })),
        ...selectedUpdateReport.remaining.map((entry) => ({ state: "Not Updated (Pending)", tone: "pending", entry })),
        ...selectedUpdateReport.skipped.map((entry) => ({ state: "Not Updated (Skipped)", tone: "pending", entry })),
      ]
    : [];
  const showUpdateReport = Boolean(selectedTarget && isUpdateAction);
  const selectedScanReport = selectedTarget
    && isScanAction
    ? collectScanReport(selectedTarget.stdout, selectedTarget.scan_report)
    : null;
  const selectedScanReportIssue = selectedTarget
    && isScanAction
    ? extractScanReportIssueFromContent(selectedTarget.scan_report_content)
    : "";
  const showScanReport = Boolean(selectedTarget && isScanAction);
  const selectedTargetCleanOutput = useMemo(
    () => buildHumanReadableOutput(
      selectedTarget?.stdout || "",
      selectedTarget?.stderr || "",
      { status: selectedTarget?.status || "", ok: selectedTarget?.ok }
    ),
    [selectedTarget?.stdout, selectedTarget?.stderr, selectedTarget?.status, selectedTarget?.ok]
  );

  const endpointIssues = useMemo(
    () => (targets || [])
      .map((target) => {
        const issue = extractTargetIssue(target, { isUpdateAction, isScanAction });
        if (!issue) return null;
        const scanReport = isScanAction ? collectScanReport(target.stdout, target.scan_report) : null;
        const updateReport = isUpdateAction ? collectUpdateReport(target.stdout, target.update_report) : null;
        const context = [];
        if (isUpdateAction) {
          const outcome = String(updateReport?.metrics?.outcome || "").trim();
          if (outcome) context.push(`outcome=${outcome}`);
          const installed = String(updateReport?.metrics?.updates_installed ?? "").trim();
          if (installed) context.push(`installed=${installed}`);
          const failed = String(updateReport?.metrics?.updates_failed ?? "").trim();
          if (failed) context.push(`failed=${failed}`);
          const remaining = String(updateReport?.metrics?.updates_remaining ?? "").trim();
          if (remaining) context.push(`remaining=${remaining}`);
        }
        if (isScanAction) {
          const scanStatus = String(scanReport?.metrics?.scan_status || "").trim();
          if (scanStatus) context.push(`scan=${scanStatus}`);
          const matches = String(scanReport?.metrics?.scan_matches ?? "").trim();
          if (matches) context.push(`matches=${matches}`);
          const reportPath = String(scanReport?.metrics?.scan_report_path || "").trim();
          if (reportPath) context.push(`report=${reportPath}`);
          const firstHit = Array.isArray(scanReport?.hits) ? scanReport.hits[0] : null;
          const recommendation = resolveScanRecommendation(firstHit);
          if (recommendation) context.push(`recommendation=${recommendation}`);
          if (target?.scan_report_content?.truncated) context.push("report_truncated=true");
        }
        return {
          ...target,
          issue,
          context: context.join(" | "),
        };
      })
      .filter(Boolean),
    [targets, isScanAction, isUpdateAction]
  );

  const severityClass = (level) => {
    const num = Number(level);
    if (Number.isNaN(num)) return "neutral";
    if (num >= 12) return "failed";
    if (num >= 7) return "pending";
    return "success";
  };

  const handleExecutionControl = async (command) => {
    const normalized = String(command || "").trim().toLowerCase();
    if (!executionId || !["pause", "resume", "kill"].includes(normalized)) return;
    if (normalized === "kill") {
      const confirmed = window.confirm("Kill this execution now? This action cannot be undone.");
      if (!confirmed) return;
    }
    setControlBusy(true);
    setControlError("");
    setControlMessage("");
    try {
      const res = await api.post(`/executions/${executionId}/control`, { command: normalized });
      const payload = res?.data || {};
      const nextStatus = String(payload.status || "").toUpperCase();
      if (nextStatus) {
        setMeta((prev) => {
          if (!prev || typeof prev !== "object") return prev;
          const prevExecution = prev.execution && typeof prev.execution === "object" ? prev.execution : {};
          const updates = { status: nextStatus };
          if (["CANCELLED", "KILLED"].includes(nextStatus) && !prevExecution.finished_at) {
            updates.finished_at = nowUtcIso();
          }
          return {
            ...prev,
            execution: {
              ...prevExecution,
              ...updates,
            },
          };
        });
      }
      setEvents((prev) => [
        ...prev,
        normalizeStep({
          step: "execution_control",
          status: "SUCCESS",
          stdout: `operator command=${normalized}`,
          stderr: "",
        }),
      ]);
      setControlMessage(
        normalized === "kill"
          ? "Kill command sent."
          : normalized === "pause"
            ? "Pause command sent."
            : "Resume command sent."
      );
    } catch (err) {
      const message = err.response?.data?.detail || err.message || "Failed to control execution";
      setControlError(String(message));
      setEvents((prev) => [
        ...prev,
        normalizeStep({
          step: "execution_control",
          status: "FAILED",
          stdout: "",
          stderr: String(message),
        }),
      ]);
    } finally {
      setControlBusy(false);
    }
  };

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <h3>Live Execution</h3>
          <p className="muted">
            {execution?.id ? `Run #${execution.id}` : "Streaming execution steps for the selected run."}
            {displayTitle ? ` - ${displayTitle}` : ""}
            {execution?.agent ? ` - Target: ${execution.agent}` : ""}
          </p>
        </div>
        <div className="page-actions">
          <span className={`status-pill ${streamEnabled ? "success" : "neutral"}`}>
            {streamEnabled ? "Streaming On" : "Streaming Off"}
          </span>
          <button
            className="btn secondary"
            onClick={() => setStreamEnabled((prev) => !prev)}
          >
            {streamEnabled ? "Pause Stream" : "Enable Stream"}
          </button>
          <button
            className="btn secondary"
            onClick={() => handleExecutionControl(canResumeExecution ? "resume" : "pause")}
            disabled={controlBusy || !canControlExecution}
            title={
              canControlExecution
                ? (canResumeExecution ? "Resume paused execution" : "Pause running execution")
                : "Execution must be running or paused"
            }
          >
            {controlBusy && canControlExecution
              ? "Applying..."
              : (canResumeExecution ? "Resume Execution" : "Pause Execution")}
          </button>
          <button
            className="btn danger"
            onClick={() => handleExecutionControl("kill")}
            disabled={controlBusy || !canKillExecution}
            title={canKillExecution ? "Terminate execution now" : "Execution must be running or paused"}
          >
            {controlBusy && canKillExecution ? "Applying..." : "Kill Execution"}
          </button>
        </div>
      </div>
      {controlError ? (
        <div className="meta-line text-danger ws-normal">{controlError}</div>
      ) : controlMessage ? (
        <div className="meta-line ws-normal">{controlMessage}</div>
      ) : null}
      {loading ? (
        <div className="empty-state">Loading execution steps...</div>
      ) : error ? (
        <div className="empty-state">{error}</div>
      ) : null}

      {loading || error ? null : (
        <div className="grid-2">
          <div className="list-item readable">
            <div className="muted">Execution</div>
            <div className="mt-6">
              <strong>{displayTitle}</strong>
            </div>
            {displayDescription ? (
              <div className="meta-line ws-normal">{displayDescription}</div>
            ) : null}
            {execution?.agent ? (
              <div className="meta-line ws-normal">
                Target: {execution.agent}
              </div>
            ) : null}
            {execution?.approved_by ? (
              <div className="meta-line">Approved by: {execution.approved_by}</div>
            ) : null}
            {execution?.alert_id ? (
              <div className="meta-line">Alert: {execution.alert_id}</div>
            ) : null}
            {commandMeta.command ? (
              <>
                <div className="muted mt-10">Command</div>
                {commandMeta.shell ? (
                  <div className="meta-line">Shell: {commandMeta.shell}</div>
                ) : null}
                <pre className="code-block mt-10">{commandMeta.command}</pre>
                {commandMeta.commandUsed && commandMeta.commandUsed !== commandMeta.command ? (
                  <>
                    <div className="muted mt-10">Command Used</div>
                    <pre className="code-block mt-10">{commandMeta.commandUsed}</pre>
                  </>
                ) : null}
              </>
            ) : null}
          </div>

          <div className="list">
            {execution?.status ? (
              <div className="list-item split">
                <span className="muted">Status</span>
                <span className={`status-pill ${executionStatusTone(execution.status)}`}>
                  {execution.status}
                </span>
              </div>
            ) : null}
            {execution?.started_at ? (
              <div className="list-item split">
                <span className="muted">Started</span>
                <span>{formatWazuhTimestamp(execution.started_at)}</span>
              </div>
            ) : null}
            {execution?.finished_at ? (
              <div className="list-item split">
                <span className="muted">Ended</span>
                <span>{formatWazuhTimestamp(execution.finished_at)}</span>
              </div>
            ) : null}
            {execution?.started_at && execution?.finished_at ? (
              <div className="list-item split">
                <span className="muted">Duration</span>
                <span>{formatDuration(execution.started_at, execution.finished_at)}</span>
              </div>
            ) : null}
            {meta?.justification ? (
              <div className="list-item readable">
                <div className="muted">Justification</div>
                <div className="mt-6">{String(meta.justification)}</div>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {loading || error || targets.length === 0 ? null : (
        <>
          <div className="card-header mb-0">
            <div>
              <h3>Target Results</h3>
              <p className="muted">Per-endpoint output captured from the connector.</p>
            </div>
          </div>
          <div className="table-scroll">
            <table className="table compact readable">
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>IP</th>
                  <th>Platform</th>
                  <th>Status</th>
                  <th>Latest Evidence</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((t) => {
                  const targetStatus = resolveTargetStatus(t, isUpdateAction);
                  return (
                  <tr
                    key={`${executionId}-target-${t.agent_id}`}
                    className={`clickable ${selectedTargetId === t.agent_id ? "selected" : ""}`}
                    onClick={() => setSelectedTargetId(t.agent_id)}
                  >
                    <td>{t.agent_name ? `${t.agent_id} - ${t.agent_name}` : t.agent_id}</td>
                    <td>{t.target_ip || "-"}</td>
                    <td>{t.platform || "-"}</td>
                    <td>
                      <span className={`status-pill ${targetStatus.tone}`}>
                        {targetStatus.label}
                      </span>
                    </td>
                    <td>{extractEvidenceSummary(t.stdout) || "-"}</td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {endpointIssues.length ? (
            <div className="mt-12">
              <div className="muted">Endpoint Issues</div>
              <div className="meta-line ws-normal">
                Consolidated error/problem details across targets to speed up analyst triage.
              </div>
              <div className="table-scroll h-260 mt-8">
                <table className="table compact readable">
                  <thead>
                    <tr>
                      <th>Agent</th>
                      <th>Status</th>
                      <th>Issue</th>
                      <th>Context</th>
                    </tr>
                  </thead>
                  <tbody>
		                    {endpointIssues.map((t) => {
                            const targetStatus = resolveTargetStatus(t, isUpdateAction);
                            return (
		                      <tr key={`issue-${executionId}-${t.agent_id}`}>
		                        <td>{t.agent_name ? `${t.agent_id} - ${t.agent_name}` : t.agent_id}</td>
		                        <td>
		                          <span className={`status-pill ${targetStatus.tone}`}>
		                            {targetStatus.label}
		                          </span>
		                        </td>
		                        <td className="ws-normal">{t.issue || "-"}</td>
		                        <td className="ws-normal">{t.context || extractEvidenceSummary(t.stdout) || "-"}</td>
		                      </tr>
                            );
			                    })}
                  </tbody>
                </table>
              </div>
            </div>
          ) : null}
		          {selectedTarget ? (
		            <div className="grid-2 mt-12">
		              <div className="list-item readable">
		                <div className="muted">Endpoint Evidence</div>
		                <pre className="code-block">
		                  {extractEvidenceLines(selectedTarget.stdout).join("\n") || "-"}
		                </pre>
			                {actionId === "endpoint-healthcheck" ? (
			                  <div className="mt-10">
			                    <div className="muted">Healthcheck Result</div>
			                    <pre className="code-block">
			                      {JSON.stringify(parseHealthcheck(selectedTarget.stdout), null, 2)}
			                    </pre>
			                  </div>
			                ) : null}
			                {showUpdateReport ? (
			                  <div className="mt-12">
			                    <div className="muted">Software Update Breakdown</div>
			                    <div className="list mt-8">
			                      <div className="list-item split">
		                        <span className="muted">Outcome</span>
		                        <span>{selectedUpdateReport?.metrics?.outcome || "-"}</span>
		                      </div>
		                      <div className="list-item split">
		                        <span className="muted">Applicable</span>
		                        <span>{selectedUpdateReport?.metrics?.updates_applicable ?? "-"}</span>
		                      </div>
		                      <div className="list-item split">
		                        <span className="muted">Installed</span>
		                        <span>
		                          {selectedUpdateReport?.metrics?.updates_installed
		                            ?? selectedUpdateReport?.metrics?.updates_installed_estimate
		                            ?? "-"}
		                        </span>
		                      </div>
		                      <div className="list-item split">
		                        <span className="muted">Failed</span>
		                        <span>
		                          {selectedUpdateReport?.metrics?.updates_failed
		                            ?? selectedUpdateReport?.metrics?.updates_failed_estimate
		                            ?? "-"}
		                        </span>
		                      </div>
			                      <div className="list-item split">
			                        <span className="muted">Remaining</span>
			                        <span>{selectedUpdateReport?.metrics?.updates_remaining ?? "-"}</span>
			                      </div>
			                      <div className="list-item split">
			                        <span className="muted">Skipped</span>
			                        <span>{selectedUpdateReport?.metrics?.updates_skipped ?? "-"}</span>
			                      </div>
			                      <div className="list-item split">
			                        <span className="muted">Unresolved</span>
			                        <span>{selectedUpdateReport?.metrics?.updates_unresolved ?? "-"}</span>
			                      </div>
			                    </div>
				                    {updateRows.length ? (
				                      <div className="table-scroll h-240 mt-8">
				                        <table className="table compact readable">
		                          <thead>
		                            <tr>
		                              <th>State</th>
		                              <th>Update</th>
		                              <th>Details</th>
		                            </tr>
		                          </thead>
		                          <tbody>
		                            {updateRows.map((row, idx) => (
		                              <tr key={`upd-${executionId}-${selectedTarget.agent_id}-${row.state}-${idx}`}>
		                                <td>
		                                  <span className={`status-pill ${row.tone}`}>
		                                    {row.state}
		                                  </span>
		                                </td>
			                                <td className="ws-normal">{formatUpdatePrimary(row.entry)}</td>
			                                <td className="ws-normal">{formatUpdateDetail(row.entry) || "-"}</td>
			                              </tr>
			                            ))}
		                          </tbody>
		                        </table>
		                      </div>
				                    ) : (
				                      <div className="meta-line mt-8">No per-update entries reported.</div>
				                    )}
			                  </div>
			                ) : null}
			                {showScanReport ? (
			                  <div className="mt-12">
			                    <div className="muted">Scan / Forensics Report</div>
			                    <div className="list mt-8">
			                      <div className="list-item split">
		                        <span className="muted">Type</span>
		                        <span>{selectedScanReport?.metrics?.scan_type || "-"}</span>
		                      </div>
		                      <div className="list-item split">
		                        <span className="muted">Status</span>
		                        <span>{selectedScanReport?.metrics?.scan_status || "-"}</span>
		                      </div>
		                      <div className="list-item split">
		                        <span className="muted">Engine</span>
		                        <span>{selectedScanReport?.metrics?.scan_engine || "-"}</span>
		                      </div>
		                      <div className="list-item split">
		                        <span className="muted">Examined</span>
		                        <span>{selectedScanReport?.metrics?.scan_total_examined ?? "-"}</span>
		                      </div>
		                      <div className="list-item split">
		                        <span className="muted">Matches</span>
		                        <span>{selectedScanReport?.metrics?.scan_matches ?? "-"}</span>
		                      </div>
		                      <div className="list-item split">
		                        <span className="muted">Report</span>
			                        <span className="ws-normal text-right">
			                          {selectedScanReport?.metrics?.scan_report_path || "-"}
			                        </span>
			                      </div>
			                    </div>
				                    {selectedScanReport?.metrics?.scan_summary ? (
				                      <div className="meta-line mt-8 ws-normal">
				                        {selectedScanReport.metrics.scan_summary}
				                      </div>
				                    ) : null}
				                    {!selectedTarget?.ok && selectedScanReportIssue ? (
				                      <pre className="code-block mt-8 maxh-180">
				                        {selectedScanReportIssue}
				                      </pre>
				                    ) : null}
				                    {selectedScanReport?.hits?.length ? (
			                      <div className="table-scroll h-240 mt-8">
				                        <table className="table compact readable">
			                          <thead>
			                            <tr>
			                              <th>Category</th>
			                              <th>Name</th>
			                              <th>Detail</th>
			                              <th>Recommendation</th>
			                            </tr>
			                          </thead>
			                          <tbody>
			                            {selectedScanReport.hits.map((entry, idx) => (
			                              <tr key={`scan-hit-${executionId}-${selectedTarget.agent_id}-${idx}`}>
			                                <td>{entry.category || "-"}</td>
				                                <td className="ws-normal">{entry.name || "-"}</td>
				                                <td className="ws-normal">{formatScanDetail(entry) || "-"}</td>
				                                <td className="ws-normal">{resolveScanRecommendation(entry) || "-"}</td>
				                              </tr>
				                            ))}
			                          </tbody>
			                        </table>
		                      </div>
			                    ) : (
			                      <div className="meta-line mt-8">No scan hits reported.</div>
			                    )}
			                    {selectedScanReport?.artifacts?.length ? (
			                      <div className="table-scroll h-180 mt-8">
			                        <table className="table compact readable">
		                          <thead>
		                            <tr>
		                              <th>Artifact</th>
		                              <th>Path</th>
		                              <th>Details</th>
		                            </tr>
		                          </thead>
		                          <tbody>
		                            {selectedScanReport.artifacts.map((entry, idx) => (
		                              <tr key={`scan-artifact-${executionId}-${selectedTarget.agent_id}-${idx}`}>
		                                <td>{entry.category || "-"}</td>
			                                <td className="ws-normal">{entry.name || "-"}</td>
			                                <td className="ws-normal">{entry.detail || entry.raw || "-"}</td>
			                              </tr>
			                            ))}
		                          </tbody>
		                        </table>
		                      </div>
		                    ) : null}
		                  </div>
		                ) : null}
			                <div className="mt-12">
			                  <div className="muted">Related Alerts (Since Execution Start)</div>
	                  {evidenceLoading ? (
	                    <div className="empty-state">Loading alerts...</div>
	                  ) : evidenceError ? (
	                    <div className="empty-state">{evidenceError}</div>
	                  ) : evidenceAlerts.length === 0 ? (
	                    <div className="meta-line">No alerts observed in this window.</div>
		                  ) : (
		                    <div className="table-scroll h-240 mt-8">
		                      <table className="table compact readable">
	                        <thead>
	                          <tr>
	                            <th>ID</th>
	                            <th>Rule</th>
	                            <th>Sev</th>
	                            <th>Time</th>
	                          </tr>
	                        </thead>
	                        <tbody>
	                          {evidenceAlerts.map((a) => (
	                            <tr key={`ev-${executionId}-${selectedTarget.agent_id}-${a.id}`}>
	                              <td>{a.id}</td>
		                              <td className="ws-normal">{a.rule}</td>
		                              <td>
	                                <span className={`status-pill ${severityClass(a.level)}`}>
	                                  {a.level}
	                                </span>
	                              </td>
	                              <td>{a.timestamp}</td>
	                            </tr>
	                          ))}
	                        </tbody>
	                      </table>
	                    </div>
	                  )}
	                </div>
		              </div>
		              <div className="list-item readable">
		                <div className="muted">Clean Output (Human-readable)</div>
		                <pre className="code-block">{selectedTargetCleanOutput || "-"}</pre>
		                <div className="muted mt-10">Raw Output</div>
		                <div className="muted">stdout</div>
		                <pre className="code-block">{normalizeCommandOutput(stripEvidenceFromStdout(selectedTarget.stdout)) || "-"}</pre>
		                <div className="muted mt-10">stderr</div>
		                <pre className="code-block">{normalizeCommandOutput(selectedTarget.stderr) || "-"}</pre>
		              </div>
		            </div>
		          ) : null}
        </>
      )}

      {loading || error ? null : events.length === 0 ? (
        <div className="empty-state">No execution events yet.</div>
      ) : (
        <>
          <div className="card-header mb-0">
            <div>
              <h3>Execution Steps</h3>
              <p className="muted">Execution trace and connector output.</p>
            </div>
          </div>
          <div className="list-scroll tall">
            <div className="list">
              {events.map((e, i) => (
                <div key={`${executionId}-${e.step}-${i}`} className="list-item readable">
                  <div className="page-actions justify-between">
                    <strong>{e.step || "-"}</strong>
                    <span className={`status-pill ${String(e.status).toUpperCase() === "SUCCESS" ? "success" : String(e.status).toUpperCase() === "FAILED" ? "failed" : "pending"}`}>
                      {e.status || "-"}
                    </span>
                  </div>
                  {e.stdout ? (
                    <pre className="code-block mt-10">{String(e.stdout)}</pre>
                  ) : null}
                  {e.stderr ? (
                    <pre className="code-block mt-10">{String(e.stderr)}</pre>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
