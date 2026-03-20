import { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { useLocation, useNavigate } from "react-router-dom";

const PADDING = 12;

const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

export default function MissionBriefing({ open, steps = [], onClose, onComplete }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [stepIndex, setStepIndex] = useState(0);
  const [targetRect, setTargetRect] = useState(null);
  const [targetReady, setTargetReady] = useState(false);

  const step = steps[stepIndex] || null;

  useEffect(() => {
    if (!open) {
      setStepIndex(0);
      setTargetRect(null);
      setTargetReady(false);
    }
  }, [open]);

  useEffect(() => {
    if (!open || !step?.route) return;
    if (location.pathname === step.route) return;
    navigate(step.route);
  }, [location.pathname, navigate, open, step?.route]);

  useEffect(() => {
    if (!open || !step) return undefined;
    let cancelled = false;
    let rafId = 0;
    let attempts = 0;

    const findTarget = () => {
      if (cancelled) return;
      const node = document.querySelector(step.selector);
      if (!node) {
        attempts += 1;
        setTargetReady(false);
        if (attempts < 40) {
          rafId = window.requestAnimationFrame(findTarget);
        }
        return;
      }
      node.scrollIntoView({ block: "center", behavior: "smooth" });
      const rect = node.getBoundingClientRect();
      setTargetRect(rect);
      setTargetReady(true);
    };

    rafId = window.requestAnimationFrame(findTarget);
    const handleResize = () => findTarget();
    window.addEventListener("resize", handleResize);
    window.addEventListener("scroll", handleResize, true);

    return () => {
      cancelled = true;
      window.cancelAnimationFrame(rafId);
      window.removeEventListener("resize", handleResize);
      window.removeEventListener("scroll", handleResize, true);
    };
  }, [location.pathname, open, step]);

  const spotlightStyle = useMemo(() => {
    if (!targetRect) return null;
    return {
      top: Math.max(8, targetRect.top - PADDING),
      left: Math.max(8, targetRect.left - PADDING),
      width: Math.max(120, targetRect.width + PADDING * 2),
      height: Math.max(72, targetRect.height + PADDING * 2),
    };
  }, [targetRect]);

  const popoverStyle = useMemo(() => {
    if (!spotlightStyle || typeof window === "undefined") {
      return {
        top: "50%",
        left: "50%",
        transform: "translate(-50%, -50%)",
      };
    }
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const preferredTop = spotlightStyle.top + spotlightStyle.height + 20;
    const preferredLeft = spotlightStyle.left;
    const top = preferredTop > viewportHeight - 280
      ? clamp(spotlightStyle.top - 244, 18, Math.max(18, viewportHeight - 244))
      : clamp(preferredTop, 18, Math.max(18, viewportHeight - 244));
    const left = clamp(preferredLeft, 18, Math.max(18, viewportWidth - 380));
    return {
      top,
      left,
      transform: "none",
    };
  }, [spotlightStyle]);

  if (!open || !step || typeof document === "undefined") return null;

  const closeTour = () => {
    onClose?.();
  };

  const advance = () => {
    if (stepIndex >= steps.length - 1) {
      onComplete?.();
      onClose?.();
      return;
    }
    setStepIndex((current) => current + 1);
  };

  const retreat = () => {
    setStepIndex((current) => Math.max(0, current - 1));
  };

  return createPortal(
    <div className="mission-briefing-layer" role="dialog" aria-modal="true" aria-label="Mission briefing">
      <div className="mission-briefing-backdrop" onClick={closeTour} />
      {spotlightStyle ? <div className="mission-briefing-spotlight" style={spotlightStyle} /> : null}
      <div className="mission-briefing-card" style={popoverStyle}>
        <div className="mission-briefing-step">Step {stepIndex + 1} / {steps.length}</div>
        <h3>{step.title}</h3>
        <p>{step.body}</p>
        {!targetReady ? <div className="mission-briefing-note">Loading this workspace surface...</div> : null}
        <div className="mission-briefing-actions">
          <button type="button" className="btn secondary" onClick={closeTour}>
            Skip
          </button>
          <button type="button" className="btn secondary" onClick={retreat} disabled={stepIndex === 0}>
            Back
          </button>
          <button type="button" className="btn" onClick={advance}>
            {stepIndex >= steps.length - 1 ? "Finish" : "Next"}
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}
