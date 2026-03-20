const styles = `
.execution-chamber {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--panel);
  border-left: 1px solid var(--border);
}

.chamber-header {
  padding: var(--space-4);
  border-bottom: 1px solid var(--border);
  background: var(--panel-soft);
}

.chamber-title {
  font-size: var(--font-size-sm);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  margin: 0;
}

.chamber-content {
  flex: 1;
  padding: var(--space-4);
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.form-label {
  font-size: var(--font-size-xs);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
}

.form-input,
.form-textarea {
  background: var(--panel-strong);
  border: 1px solid var(--border);
  color: var(--text);
  padding: var(--space-3);
  border-radius: 6px;
  font-family: var(--font-family-ui);
  font-size: var(--font-size-sm);
  transition: all 150ms cubic-bezier(0.4, 0, 0.2, 1);
}

.form-textarea {
  font-family: var(--font-family-mono);
  font-size: var(--font-size-xs);
  resize: vertical;
  min-height: 80px;
}

.form-input:focus,
.form-textarea:focus {
  outline: none;
  border-color: var(--accent);
  background: var(--panel-strong);
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
}

.form-input::placeholder,
.form-textarea::placeholder {
  color: var(--muted);
}

.selected-action,
.targets-summary,
.status-message {
  padding: var(--space-3);
  background: var(--panel-strong);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: var(--font-size-sm);
}

.selected-action-name {
  font-weight: 600;
  color: var(--accent);
  font-family: var(--font-family-mono);
  word-break: break-all;
}

.selected-action-description {
  font-size: var(--font-size-xs);
  color: var(--muted);
  margin-top: var(--space-2);
}

.targets-count {
  color: var(--accent);
  font-weight: 600;
}

.status-message {
  font-size: var(--font-size-xs);
  color: var(--muted);
}

.chamber-footer {
  padding: var(--space-4);
  border-top: 1px solid var(--border);
  background: var(--panel-soft);
}

.run-button {
  width: 100%;
  padding: var(--space-3) var(--space-4);
  background: var(--accent);
  color: white;
  border: none;
  border-radius: 8px;
  font-weight: 700;
  font-size: var(--font-size-sm);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  cursor: pointer;
  transition: all 150ms cubic-bezier(0.4, 0, 0.2, 1);
  position: relative;
  overflow: hidden;
  box-shadow: 0 0 20px rgba(59, 130, 246, 0.4);
}

.run-button:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 30px rgba(59, 130, 246, 0.6);
}

.run-button:active:not(:disabled) {
  transform: translateY(0);
}

.run-button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.button-label {
  position: relative;
  z-index: 2;
}

.empty-chamber {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  flex-direction: column;
  gap: var(--space-4);
  color: var(--muted);
  text-align: center;
}

.empty-chamber-icon {
  font-size: 32px;
  opacity: 0.5;
}

.empty-chamber-text {
  font-size: var(--font-size-sm);
  max-width: 200px;
}
`;

const inputLabel = (field) => String(field?.label || field?.title || field?.name || "Input");

const inputPlaceholder = (field) =>
  String(field?.placeholder || field?.example || field?.description || "").trim();

const actionTitle = (action) => String(action?.label || action?.name || action?.id || "").trim();

export default function ExecutionChamber({
  selectedAction = null,
  selectedAgents = [],
  actionInputs = {},
  onActionInputChange = () => {},
  multilineFields = new Set(),
  onExecute = () => {},
  isExecuting = false,
  justification = "",
  onJustificationChange = () => {},
  statusMessage = "",
}) {
  const inputFields = Array.isArray(selectedAction?.inputs)
    ? selectedAction.inputs.filter((field) => field && field.name)
    : [];

  const missingRequiredInput = inputFields.some(
    (field) =>
      field.required &&
      !String(actionInputs?.[field.name] ?? "").trim()
  );

  const isReadyToExecute =
    Boolean(selectedAction) &&
    selectedAgents.length > 0 &&
    Boolean(justification.trim()) &&
    !missingRequiredInput;

  if (!selectedAction) {
    return (
      <>
        <style>{styles}</style>
        <div className="execution-chamber">
          <div className="chamber-header">
            <h3 className="chamber-title">Execution Chamber</h3>
          </div>
          <div className="empty-chamber">
            <div className="empty-chamber-icon">{">>"}</div>
            <div className="empty-chamber-text">Select an action to begin</div>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <style>{styles}</style>
      <div className="execution-chamber">
        <div className="chamber-header">
          <h3 className="chamber-title">Execution Chamber</h3>
        </div>

        <div className="chamber-content">
          <div className="form-group">
            <label className="form-label">Selected Action</label>
            <div className="selected-action">
              <div className="selected-action-name">{actionTitle(selectedAction)}</div>
              {selectedAction.description ? (
                <div className="selected-action-description">{selectedAction.description}</div>
              ) : null}
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Target Agents</label>
            <div className="targets-summary">
              <span className="targets-count">{selectedAgents.length}</span>{" "}
              agent{selectedAgents.length !== 1 ? "s" : ""} selected
            </div>
          </div>

          {inputFields.map((field) => {
            const name = String(field.name || "").trim();
            const required = Boolean(field.required);
            const multiline = Boolean(field.multiline) || multilineFields.has(name.toLowerCase());
            const value = String(actionInputs?.[name] ?? "");
            return (
              <div className="form-group" key={name}>
                <label className="form-label">
                  {inputLabel(field)}
                  {required ? " *" : ""}
                </label>
                {multiline ? (
                  <textarea
                    className="form-textarea"
                    placeholder={inputPlaceholder(field)}
                    value={value}
                    onChange={(event) => onActionInputChange(name, event.target.value)}
                    disabled={isExecuting}
                  />
                ) : (
                  <input
                    className="form-input"
                    type="text"
                    placeholder={inputPlaceholder(field)}
                    value={value}
                    onChange={(event) => onActionInputChange(name, event.target.value)}
                    disabled={isExecuting}
                  />
                )}
              </div>
            );
          })}

          <div className="form-group">
            <label className="form-label">Justification *</label>
            <textarea
              className="form-textarea"
              placeholder="Enter justification for this action execution..."
              value={justification}
              onChange={(event) => onJustificationChange(event.target.value)}
              disabled={isExecuting}
            />
          </div>

          {statusMessage ? <div className="status-message">{statusMessage}</div> : null}
        </div>

        <div className="chamber-footer">
          <button
            className="run-button transition-fast"
            onClick={() => onExecute()}
            disabled={!isReadyToExecute || isExecuting}
            type="button"
          >
            <span className="button-label">
              {isExecuting ? "Executing..." : "Run Action"}
            </span>
          </button>
          {!isReadyToExecute ? (
            <div style={{ marginTop: "8px", fontSize: "var(--font-size-xs)", color: "var(--muted)" }}>
              {selectedAgents.length === 0 && "Select target agents. "}
              {missingRequiredInput && "Complete required action inputs. "}
              {!justification.trim() && "Provide justification."}
            </div>
          ) : null}
        </div>
      </div>
    </>
  );
}
