const ANSI_ESCAPE_RE = /\x1B\[[0-9;]*[A-Za-z]/g;
const SPINNER_LINE_RE = /^[-\\|/\s]+$/;
const PROGRESS_BAR_RE = /^[\s\u2580-\u259F]+(?:\d{1,3}%|[\d.,]+\s*(KB|MB|GB)\s*\/\s*[\d.,]+\s*(KB|MB|GB))?$/i;

export const normalizeOutputText = (value) =>
  String(value || "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(ANSI_ESCAPE_RE, "")
    .trim();

const stripClixmlTail = (value) => {
  const text = normalizeOutputText(value);
  const marker = "#< CLIXML";
  const idx = text.indexOf(marker);
  if (idx < 0) return text;
  return text.slice(0, idx).trim();
};

const stripEvidenceLines = (value) =>
  String(value || "")
    .split(/\r?\n/)
    .filter((line) => !String(line).trim().startsWith("C2F_LOG "))
    .join("\n");

const isNoiseLine = (line) => {
  const trimmed = String(line || "").trim();
  if (!trimmed) return true;
  if (SPINNER_LINE_RE.test(trimmed)) return true;
  if (PROGRESS_BAR_RE.test(trimmed)) return true;
  return false;
};

export const extractReadableOutput = (value) => {
  const text = stripClixmlTail(stripEvidenceLines(value));
  if (!text) return "";
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => !isNoiseLine(line));
  return lines.join("\n").trim();
};

export const summarizeReadableOutput = (value, limit = 240) => {
  const text = extractReadableOutput(value);
  if (!text) return "";
  if (text.length <= limit) return text;
  return `${text.slice(0, limit)}...`;
};

const rcToHex = (raw) => {
  const n = Number(raw);
  if (!Number.isFinite(n)) return "";
  const normalized = n < 0 ? (0xFFFFFFFF + n + 1) : n;
  return `0x${Math.trunc(normalized).toString(16).toUpperCase()}`;
};

const explainError = (stderr, stdout) => {
  const source = `${normalizeOutputText(stderr)}\n${normalizeOutputText(stdout)}`;
  if (!source.trim()) return "";

  const rcMatch = source.match(/custom-os-command failed rc=([-+]?\d+)/i);
  const wingetInstallerMatch = source.match(/Installer failed with exit code:\s*(0x[0-9A-Fa-f]+)/i);

  if (/WinRM connection failed/i.test(source)) {
    return "Connection to the endpoint failed. Verify WinRM listener/network/credentials for that agent.";
  }
  if (/Access is denied/i.test(source)) {
    return "The endpoint rejected this command due to insufficient privileges for the current context.";
  }
  if (wingetInstallerMatch) {
    const code = String(wingetInstallerMatch[1] || "").toUpperCase();
    if (code === "0X80070002") {
      return "Package install failed because a required installer file was not found (0x80070002).";
    }
    return `Package install failed with installer exit code ${code}.`;
  }
  if (/The file cannot be accessed by the system/i.test(source) && /winget/i.test(source)) {
    return "Winget could not access required files in this run context. Try with Run as SYSTEM turned off.";
  }
  if (rcMatch) {
    const rc = String(rcMatch[1] || "").trim();
    const hex = rcToHex(rc);
    return `Command exited with error code ${rc}${hex ? ` (${hex})` : ""}.`;
  }
  return "";
};

export const buildHumanReadableOutput = (stdout, stderr, options = {}) => {
  const cleanStdout = extractReadableOutput(stdout);
  const cleanStderr = extractReadableOutput(stderr);
  const detail = cleanStderr || cleanStdout;
  if (!detail) {
    const normalizedStatus = String(options?.status || "").trim().toUpperCase();
    if (normalizedStatus === "SUCCESS") {
      return "Command completed successfully with no output. If this was a filter/query command, no matching results were returned.";
    }
    if (["FAILED", "ERROR", "KILLED"].includes(normalizedStatus)) {
      return "Command failed with no output. Check Endpoint Issues and Execution Steps for details.";
    }
    return "";
  }
  const explanation = explainError(stderr, stdout);
  if (!explanation) return detail;
  return `${explanation}\n\nDetails:\n${detail}`;
};
