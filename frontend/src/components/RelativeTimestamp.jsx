import { formatRelativeTime, formatTimestampTitle } from "../utils/time";

export default function RelativeTimestamp({ value, fallback = "-", timeZone, className = "" }) {
  const label = formatRelativeTime(value);
  const title = formatTimestampTitle(value, timeZone);
  return (
    <span className={`relative-time ${className}`.trim()} title={title}>
      {label || fallback}
    </span>
  );
}
