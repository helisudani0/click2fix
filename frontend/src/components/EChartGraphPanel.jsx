import { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { GraphChart } from "echarts/charts";
import { TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";

echarts.use([
  GraphChart,
  TooltipComponent,
  CanvasRenderer,
]);

export default function EChartGraphPanel({
  option,
  className = "",
  style,
  loading = false,
  loadingText = "Loading...",
}) {
  const hostRef = useRef(null);
  const chartRef = useRef(null);

  useEffect(() => {
    if (!hostRef.current) return undefined;
    const chart = echarts.init(hostRef.current, undefined, {
      renderer: "canvas",
      useDirtyRect: true,
    });
    chartRef.current = chart;

    return () => {
      chartRef.current?.dispose();
      chartRef.current = null;
    };
  }, []);

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
    if (!hostRef.current || !chartRef.current) return undefined;
    const chart = chartRef.current;
    const resize = () => chart.resize();

    const observer = typeof ResizeObserver !== "undefined"
      ? new ResizeObserver(() => resize())
      : null;

    if (observer) {
      observer.observe(hostRef.current);
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
  }, []);

  return (
    <div
      ref={hostRef}
      className={`echart-panel ${className}`.trim()}
      style={style}
    />
  );
}
