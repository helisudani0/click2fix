import { useEffect } from "react";

export default function SideDrawer({ open, onClose, title, subtitle = "", actions = null, children }) {
  useEffect(() => {
    if (!open) return undefined;

    const previousOverflow = document.body.style.overflow;
    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        onClose?.();
      }
    };

    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="drawer-shell" role="dialog" aria-modal="true" aria-label={title || "Details"}>
      <button type="button" className="drawer-backdrop" aria-label="Close details" onClick={onClose} />
      <aside className="drawer-panel">
        <div className="drawer-header">
          <div className="stack-col gap-6">
            <h3>{title || "Details"}</h3>
            {subtitle ? <div className="muted">{subtitle}</div> : null}
          </div>
          <div className="page-actions">
            {actions}
            <button type="button" className="btn secondary" onClick={onClose}>
              Close
            </button>
          </div>
        </div>
        <div className="drawer-body">{children}</div>
      </aside>
    </div>
  );
}
