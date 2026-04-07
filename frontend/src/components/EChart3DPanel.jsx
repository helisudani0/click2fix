import { useEffect, useRef, useState } from "react";

export default function EChart3DPanel({
  option,
  className = "",
  style,
  loading = false,
  loadingText = "Loading 3D...",
  deferUntilVisible = true,
  unsupportedText = "3D rendering is unavailable in this browser. Switch back to 2D.",
}) {
  const shellRef = useRef(null);
  const hostRef = useRef(null);
  const chartRef = useRef(null);
  const echartsRef = useRef(null);
  const [shouldBoot, setShouldBoot] = useState(!deferUntilVisible);
  const [bootError, setBootError] = useState("");
  const [runtimeReady, setRuntimeReady] = useState(false);

  useEffect(() => {
    if (!deferUntilVisible || shouldBoot || !shellRef.current) return undefined;
    const observer = typeof IntersectionObserver !== "undefined"
      ? new IntersectionObserver(
        (entries) => {
          if (entries.some((entry) => entry.isIntersecting || entry.intersectionRatio > 0)) {
            setShouldBoot(true);
            observer.disconnect();
          }
        },
        { rootMargin: "220px" }
      )
      : null;
    if (observer) {
      observer.observe(shellRef.current);
    } else {
      setShouldBoot(true);
    }
    return () => observer?.disconnect();
  }, [deferUntilVisible, shouldBoot]);

  useEffect(() => {
    if (!shouldBoot || echartsRef.current) return undefined;
    let disposed = false;

    const bootRuntime = async () => {
      try {
        const echartsModule = await import("echarts");
        await import("echarts-gl");
        if (disposed) return;
        echartsRef.current = echartsModule;
        setRuntimeReady(true);
      } catch (error) {
        if (disposed) return;
        setBootError(String(error?.message || "Unable to initialize 3D renderer."));
      }
    };

    bootRuntime();
    return () => {
      disposed = true;
    };
  }, [shouldBoot]);

  useEffect(() => {
    if (!runtimeReady || !hostRef.current || chartRef.current || !echartsRef.current) return undefined;
    const chart = echartsRef.current.init(hostRef.current, undefined, {
      renderer: "canvas",
      useDirtyRect: true,
    });
    chartRef.current = chart;
    return () => {
      chartRef.current?.dispose();
      chartRef.current = null;
    };
  }, [runtimeReady]);

  useEffect(() => {
    const chart = chartRef.current;
    if (!chart || !option) return;
    chart.setOption(option, { notMerge: true, lazyUpdate: true });
  }, [option]);

  useEffect(() => {
    const chart = chartRef.current;
    if (!chart) return;
    if (loading) {
      chart.showLoading("default", {
        text: loadingText,
        color: "#72d6ff",
        textColor: "#cfe6ff",
        maskColor: "rgba(7, 14, 24, 0.56)",
      });
      return;
    }
    chart.hideLoading();
  }, [loading, loadingText]);

  useEffect(() => {
    if (!shellRef.current || !chartRef.current) return undefined;
    const chart = chartRef.current;
    const resize = () => chart.resize();

    const observer = typeof ResizeObserver !== "undefined"
      ? new ResizeObserver(() => resize())
      : null;

    if (observer) {
      observer.observe(shellRef.current);
    } else {
      window.addEventListener("resize", resize);
    }

    return () => {
      if (observer) {
        observer.disconnect();
      } else {
        window.removeEventListener("resize", resize);
      }
    };
  }, [runtimeReady]);

  const showBootOverlay = !runtimeReady && !bootError;
  const showErrorOverlay = Boolean(bootError);

  return (
    <div
      ref={shellRef}
      className={`echart-panel-shell ${className}`.trim()}
      style={style}
    >
      <div ref={hostRef} className="echart-panel echart-panel-3d" />
      {showBootOverlay ? (
        <div className="echart-panel-overlay">
          <span>Loading 3D engine...</span>
        </div>
      ) : null}
      {showErrorOverlay ? (
        <div className="echart-panel-overlay">
          <span>{unsupportedText}</span>
        </div>
      ) : null}
    </div>
  );
}
