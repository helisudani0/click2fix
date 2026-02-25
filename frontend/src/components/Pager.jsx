const clamp = (value, min, max) => Math.min(Math.max(value, min), max);

export default function Pager({
  total = 0,
  page = 1,
  pageSize = 50,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = [25, 50, 100],
  label = "rows",
}) {
  const safeTotal = Math.max(0, Number(total) || 0);
  const safePageSize = Math.max(1, Number(pageSize) || 1);
  const totalPages = Math.max(1, Math.ceil(safeTotal / safePageSize));
  const safePage = clamp(Number(page) || 1, 1, totalPages);

  const start = safeTotal === 0 ? 0 : (safePage - 1) * safePageSize + 1;
  const end = safeTotal === 0 ? 0 : Math.min(safeTotal, safePage * safePageSize);

  return (
    <div className="pager">
      <div className="pager-range">
        Showing {start}-{end} of {safeTotal} {label}
      </div>
      <div className="pager-controls">
        <select
          className="input pager-size"
          value={safePageSize}
          onChange={(e) => onPageSizeChange?.(Math.max(1, Number(e.target.value) || safePageSize))}
        >
          {pageSizeOptions.map((size) => (
            <option key={size} value={size}>
              {size} / page
            </option>
          ))}
        </select>
        <button
          className="btn secondary"
          type="button"
          onClick={() => onPageChange?.(safePage - 1)}
          disabled={safePage <= 1}
        >
          Prev
        </button>
        <span className="pager-page">
          Page {safePage} / {totalPages}
        </span>
        <button
          className="btn secondary"
          type="button"
          onClick={() => onPageChange?.(safePage + 1)}
          disabled={safePage >= totalPages}
        >
          Next
        </button>
      </div>
    </div>
  );
}
