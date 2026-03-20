import { useMemo, useState } from "react";

const styles = `
.action-arsenal {
  display: flex;
  flex-direction: column;
  height: 100%;
  border-right: 1px solid var(--border);
}

.arsenal-header {
  padding: var(--space-4);
  border-bottom: 1px solid var(--border);
  background: var(--panel-soft);
}

.arsenal-title {
  font-size: var(--font-size-sm);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  margin: 0;
}

.arsenal-content {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
}

.action-category {
  border-bottom: 1px solid var(--border);
}

.category-header {
  padding: var(--space-3) var(--space-4);
  background: var(--panel-strong);
  font-size: var(--font-size-xs);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  cursor: pointer;
  user-select: none;
  display: flex;
  align-items: center;
  justify-content: space-between;
  transition: background-color 150ms cubic-bezier(0.4, 0, 0.2, 1);
}

.category-header:hover {
  background: var(--border);
  color: var(--accent);
}

.category-toggle {
  width: 16px;
  height: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
}

.category-code {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 24px;
  padding: 2px 6px;
  margin-right: var(--space-2);
  border-radius: 999px;
  border: 1px solid var(--border);
  background: rgba(255, 255, 255, 0.04);
  color: var(--accent);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.08em;
}

.category-items {
  display: flex;
  flex-direction: column;
}

.action-item {
  padding: var(--space-3) var(--space-4);
  cursor: pointer;
  user-select: none;
  border-left: 3px solid transparent;
  display: flex;
  align-items: center;
  gap: var(--space-3);
  transition: all 150ms cubic-bezier(0.4, 0, 0.2, 1);
  position: relative;
}

.action-item:hover {
  background: var(--panel-soft);
  border-left-color: var(--accent);
  padding-left: calc(var(--space-4) - 3px);
}

.action-item.active {
  background: var(--panel-strong);
  border-left-color: var(--accent);
  color: var(--accent);
  padding-left: calc(var(--space-4) - 3px);
}

.action-icon {
  width: 20px;
  height: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  font-size: 12px;
}

.action-name {
  flex: 1;
  font-size: var(--font-size-sm);
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.action-tooltip {
  position: absolute;
  left: 100%;
  top: 50%;
  transform: translateY(-50%);
  margin-left: var(--space-2);
  background: rgba(15, 15, 21, 0.95);
  border: 1px solid rgba(59, 130, 246, 0.3);
  padding: var(--space-2) var(--space-3);
  border-radius: 6px;
  font-size: var(--font-size-xs);
  color: var(--text);
  white-space: nowrap;
  pointer-events: none;
  opacity: 0;
  visibility: hidden;
  transition: opacity 150ms ease-out, visibility 150ms ease-out;
  z-index: 100;
}

.action-item:hover .action-tooltip {
  opacity: 1;
  visibility: visible;
}
`;

const categoryIcon = {
  Containment: "CT",
  Investigation: "IN",
  Remediation: "RM",
};

const actionLabel = (action) => String(action?.label || action?.name || action?.id || "").trim();

export default function ActionArsenal({
  actions = [],
  selectedActionId = null,
  onActionSelect = () => {},
  searchQuery = "",
}) {
  const [expandedCategories, setExpandedCategories] = useState({
    Containment: true,
    Investigation: true,
    Remediation: true,
  });

  const filteredActions = useMemo(() => {
    const query = String(searchQuery || "").trim().toLowerCase();
    if (!query) return actions;
    return actions.filter((action) => {
      const label = actionLabel(action).toLowerCase();
      const id = String(action?.id || "").toLowerCase();
      const description = String(action?.description || "").toLowerCase();
      return label.includes(query) || id.includes(query) || description.includes(query);
    });
  }, [actions, searchQuery]);

  const groupedActions = useMemo(
    () => ({
      Containment: filteredActions.filter(
        (action) => action?.category === "Containment" || action?.type === "containment"
      ),
      Investigation: filteredActions.filter(
        (action) => action?.category === "Investigation" || action?.type === "investigation"
      ),
      Remediation: filteredActions.filter(
        (action) => action?.category === "Remediation" || action?.type === "remediation"
      ),
    }),
    [filteredActions]
  );

  const toggleCategory = (category) => {
    setExpandedCategories((current) => ({
      ...current,
      [category]: !current[category],
    }));
  };

  return (
    <>
      <style>{styles}</style>
      <div className="action-arsenal">
        <div className="arsenal-header">
          <h3 className="arsenal-title">Action Arsenal</h3>
        </div>

        <div className="arsenal-content">
          {Object.entries(groupedActions).map(([category, items]) => {
            if (!items.length) return null;
            return (
              <div key={category} className="action-category">
                <div className="category-header" onClick={() => toggleCategory(category)}>
                  <span><span className="category-code">{categoryIcon[category] || "--"}</span>{category}</span>
                  <span className="category-toggle">
                    {expandedCategories[category] ? "-" : "+"}
                  </span>
                </div>

                {expandedCategories[category] ? (
                  <div className="category-items">
                    {items.map((action) => (
                      <div
                        key={action.id}
                        className={`action-item transition-fast ${
                          selectedActionId === action.id ? "active" : ""
                        }`}
                        onClick={() => onActionSelect(action)}
                      >
                        <div className="action-icon">{categoryIcon[category] || "--"}</div>
                        <div className="action-name">{actionLabel(action)}</div>
                        {action.description ? (
                          <div className="action-tooltip">{action.description}</div>
                        ) : null}
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>
      </div>
    </>
  );
}
