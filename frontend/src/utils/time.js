const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

const pad = (n, width = 2) => String(n).padStart(width, "0");

export const APP_TIMEZONE = "Asia/Kolkata";
export const APP_TIMEZONE_LABEL = "IST";
export const DEFAULT_TIMEZONE = APP_TIMEZONE;

let serverClockSkewMs = 0;
const FORMATTER_CACHE = new Map();

const getFormatter = (timeZone) => {
  const key = timeZone || DEFAULT_TIMEZONE;
  if (!FORMATTER_CACHE.has(key)) {
    FORMATTER_CACHE.set(
      key,
      new Intl.DateTimeFormat("en-US", {
        timeZone: key,
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      }),
    );
  }
  return FORMATTER_CACHE.get(key);
};

const partsFor = (date, timeZone = DEFAULT_TIMEZONE) => {
  try {
    const parts = getFormatter(timeZone).formatToParts(date);
    const map = {};
    parts.forEach((part) => {
      if (part.type !== "literal") {
        map[part.type] = part.value;
      }
    });
    return {
      month: map.month,
      day: String(Number(map.day || "0")),
      year: map.year,
      hour: map.hour || "00",
      minute: map.minute || "00",
      second: map.second || "00",
    };
  } catch {
    return {
      month: MONTHS[date.getUTCMonth()],
      day: String(date.getUTCDate()),
      year: String(date.getUTCFullYear()),
      hour: pad(date.getUTCHours()),
      minute: pad(date.getUTCMinutes()),
      second: pad(date.getUTCSeconds()),
    };
  }
};

export const parseWazuhTimestamp = (value) => {
  if (!value) return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === "number") {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }

  const raw = String(value).trim();
  if (!raw) return null;

  let normalized = raw.replace(/\+0000$/, "Z");
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(normalized)) {
    normalized = `${normalized}Z`;
  }

  let date = new Date(normalized);
  if (!Number.isNaN(date.getTime())) return date;

  normalized = raw.replace(" ", "T");
  if (/^\d{4}-\d{2}-\d{2}T/.test(normalized) && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(normalized)) {
    normalized = `${normalized}Z`;
  }
  date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
};

export const syncServerClock = (timestampValue) => {
  const parsed = parseWazuhTimestamp(timestampValue);
  if (!parsed) return false;
  serverClockSkewMs = parsed.getTime() - Date.now();
  return true;
};

export const getServerClockSkewMs = () => serverClockSkewMs;

export const nowUtcDate = () => new Date(Date.now() + serverClockSkewMs);

export const nowUtcIso = () => nowUtcDate().toISOString();

export const formatWazuhTimestamp = (value, timeZone = DEFAULT_TIMEZONE) => {
  const date = parseWazuhTimestamp(value);
  if (!date) {
    if (value === null || value === undefined || value === "") return "-";
    return typeof value === "string" || typeof value === "number" ? String(value) : "-";
  }
  const parts = partsFor(date, timeZone);
  return `${parts.month} ${parts.day}, ${parts.year} @ ${parts.hour}:${parts.minute}:${parts.second}.${pad(date.getUTCMilliseconds(), 3)} ${APP_TIMEZONE_LABEL}`;
};

export const formatWazuhShort = (value, timeZone = DEFAULT_TIMEZONE) => {
  const date = parseWazuhTimestamp(value);
  if (!date) {
    if (value === null || value === undefined || value === "") return "-";
    return typeof value === "string" || typeof value === "number" ? String(value) : "-";
  }
  const parts = partsFor(date, timeZone);
  return `${parts.month} ${pad(parts.day)} ${parts.hour}:${parts.minute} ${APP_TIMEZONE_LABEL}`;
};
