import { useRef, useState } from "react";

const styles = `
.global-search-container {
  position: fixed;
  top: 16px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 500;
  width: 500px;
  max-width: 90%;
}

.global-search-bar {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-2) var(--space-4);
  border-radius: 8px;
  background: rgba(15, 15, 21, 0.7);
  -webkit-backdrop-filter: blur(10px);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(39, 39, 42, 0.5);
  transition: all 150ms cubic-bezier(0.4, 0, 0.2, 1);
}

.global-search-container.active .global-search-bar {
  background: rgba(15, 15, 21, 0.9);
  border-color: rgba(59, 130, 246, 0.5);
  box-shadow: 0 0 20px rgba(59, 130, 246, 0.2);
}

.search-icon {
  color: var(--muted);
  flex-shrink: 0;
  transition: color 150ms cubic-bezier(0.4, 0, 0.2, 1);
}

.global-search-container.active .search-icon {
  color: var(--accent);
}

.search-input {
  flex: 1;
  background: transparent;
  border: none;
  outline: none;
  color: var(--text);
  font-size: var(--font-size-sm);
  font-family: var(--font-family-ui);
  min-width: 200px;
}

.search-input::placeholder {
  color: var(--muted);
}

.search-input:focus {
  color: var(--text);
}
`;

export default function GlobalSearchBar({
  onSearch,
  placeholder = "Search actions by name or category...",
}) {
  const [isActive, setIsActive] = useState(false);
  const inputRef = useRef(null);

  const handleInputChange = (e) => {
    onSearch?.(e.target.value);
  };

  return (
    <>
      <style>{styles}</style>
      <div className={`global-search-container ${isActive ? "active" : ""}`}>
        <div className="glass global-search-bar transition-fast">
          <svg
            className="search-icon"
            width="18"
            height="18"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <circle cx="11" cy="11" r="8"></circle>
            <path d="m21 21-4.35-4.35"></path>
          </svg>
          <input
            ref={inputRef}
            type="text"
            className="search-input"
            placeholder={placeholder}
            onChange={handleInputChange}
            onFocus={() => setIsActive(true)}
            onBlur={() => setIsActive(false)}
          />
        </div>
      </div>
    </>
  );
}
