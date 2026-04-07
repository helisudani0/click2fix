import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  addCaseNote,
  attachCaseAlert,
  createCaseRecord,
  downloadCaseAttachment,
  downloadCaseEvidence,
  getCaseAttackPath,
  getCaseAiSummary,
  getCaseAttachments,
  getCaseDetail,
  getCaseEvidence,
  getCaseEvidenceCustody,
  getCaseIocGraph,
  getCaseTimeline,
  getCaseTimelineExportUrl,
  getCases,
  lockCaseEvidence,
  updateCaseRisk,
  updateCaseStatus,
  uploadCaseAttachment,
  uploadCaseEvidence,
} from "../api/wazuh";
import RelativeTimestamp from "../components/RelativeTimestamp";
import EChartGraphPanel from "../components/EChartGraphPanel";
import EChart3DPanel from "../components/EChart3DPanel";
import { formatWazuhTimestamp } from "../utils/time";
import { formatApiError } from "../utils/httpErrors";

export default function Cases() {
  const [cases, setCases] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [attackPath, setAttackPath] = useState([]);
  const [attachments, setAttachments] = useState([]);
  const [evidence, setEvidence] = useState([]);
  const [custody, setCustody] = useState([]);
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [iocGraph, setIocGraph] = useState({ nodes: [], edges: [] });
  const [detailLoading, setDetailLoading] = useState(false);
  const [note, setNote] = useState("");
  const [statusValue, setStatusValue] = useState("OPEN");
  const [riskScore, setRiskScore] = useState("");
  const [riskImpact, setRiskImpact] = useState("medium");
  const [file, setFile] = useState(null);
  const [evidenceFile, setEvidenceFile] = useState(null);
  const [evidenceLabel, setEvidenceLabel] = useState("");
  const [evidenceCategory, setEvidenceCategory] = useState("");
  const [evidenceNotes, setEvidenceNotes] = useState("");
  const [timelineFilter, setTimelineFilter] = useState("");
  const [caseSearch, setCaseSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [newCaseTitle, setNewCaseTitle] = useState("");
  const [newCaseDesc, setNewCaseDesc] = useState("");
  const [newAlertId, setNewAlertId] = useState("");
  const [createStatus, setCreateStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [aiSummaryLoading, setAiSummaryLoading] = useState(false);
  const [aiSummaryError, setAiSummaryError] = useState("");
  const [aiSummary, setAiSummary] = useState(null);
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedCaseParam = searchParams.get("case") || "";
  const [iocThreeDAvailable, setIocThreeDAvailable] = useState(true);

  const loadCases = async () => {
    try {
      setLoading(true);
      const response = await getCases();
      setCases(response.data);
      setError(null);
    } catch (err) {
      console.error("Failed to load cases:", err);
      setError(formatApiError(err, "Failed to load cases."));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, []);

  const loadCaseDetail = useCallback(async (caseId, eventType = timelineFilter) => {
    setDetailLoading(true);
    try {
      const [detailRes, timelineRes] = await Promise.all([
        getCaseDetail(caseId),
        getCaseTimeline(caseId, eventType ? { event_type: eventType } : undefined)
      ]);
      setDetail(detailRes.data);
      setTimeline(timelineRes.data || []);
      const risk = detailRes.data?.risk;
      if (risk) {
        setRiskScore(risk[0] ?? "");
        setRiskImpact(risk[1] || "medium");
      } else {
        setRiskScore("");
        setRiskImpact("medium");
      }
      const [attackRes, attachmentsRes] = await Promise.all([
        getCaseAttackPath(caseId),
        getCaseAttachments(caseId)
      ]);
      setAttackPath(attackRes.data || []);
      setAttachments(attachmentsRes.data || []);
      const [evidenceRes, graphRes] = await Promise.all([
        getCaseEvidence(caseId),
        getCaseIocGraph(caseId)
      ]);
      setEvidence(evidenceRes.data || []);
      setIocGraph(graphRes.data || { nodes: [], edges: [] });
      const currentStatus = detailRes.data?.case?.[3];
      if (currentStatus) {
        setStatusValue(currentStatus);
      }
    } catch (err) {
      setError(formatApiError(err, "Failed to load case details."));
    } finally {
      setDetailLoading(false);
    }
  }, [timelineFilter]);

  const createCase = async () => {
    setCreateStatus("");
    if (!newCaseTitle.trim()) {
      setCreateStatus("Case title is required.");
      return;
    }
    try {
      const res = await createCaseRecord({
        title: newCaseTitle,
        description: newCaseDesc || "Investigation case",
      });
      const caseId = res.data?.id;
      if (caseId && newAlertId) {
        await attachCaseAlert(caseId, newAlertId);
      }
      setNewCaseTitle("");
      setNewCaseDesc("");
      setNewAlertId("");
      setCreateStatus(caseId ? `Case ${caseId} created.` : "Case created.");
      await loadCases();
      if (caseId) {
        setSearchParams({ case: String(caseId) });
      }
    } catch (err) {
      setCreateStatus(err.response?.data?.detail || err.message);
    }
  };

  useEffect(() => {
    if (!requestedCaseParam || cases.length === 0) return;
    const match = cases.find((c) => String(c[0]) === String(requestedCaseParam));
    if (!match) return;
    const id = Number(match[0]);
    if (selectedId === id) return;
    setSelectedId(id);
    setSelectedEvidence(null);
    setCustody([]);
    loadCaseDetail(id);
  }, [requestedCaseParam, cases, selectedId, loadCaseDetail]);

  useEffect(() => {
    setAiSummary(null);
    setAiSummaryError("");
    setAiSummaryLoading(false);
  }, [selectedId]);

  const generateCaseAiSummary = useCallback(async () => {
    if (!selectedId) return;
    try {
      setAiSummaryLoading(true);
      setAiSummaryError("");
      const response = await getCaseAiSummary(selectedId);
      setAiSummary(response?.data || null);
    } catch (err) {
      setAiSummary(null);
      setAiSummaryError(formatApiError(err, "Unable to generate AI case summary."));
    } finally {
      setAiSummaryLoading(false);
    }
  }, [selectedId]);

  const submitNote = async () => {
    if (!note.trim() || !selectedId) return;
    try {
      await addCaseNote(selectedId, note);
      setNote("");
      await loadCaseDetail(selectedId);
    } catch (err) {
      setError(formatApiError(err, "Unable to save note."));
    }
  };

  const updateStatus = async () => {
    if (!selectedId) return;
    try {
      await updateCaseStatus(selectedId, statusValue);
      await loadCaseDetail(selectedId);
      await loadCases();
    } catch (err) {
      setError(formatApiError(err, "Unable to update case status."));
    }
  };

  const updateRisk = async () => {
    if (!selectedId) return;
    try {
      await updateCaseRisk(selectedId, {
        risk_score: riskScore === "" ? null : Number(riskScore),
        impact: riskImpact
      });
      await loadCaseDetail(selectedId);
    } catch (err) {
      setError(formatApiError(err, "Unable to update case risk."));
    }
  };

  const uploadAttachment = async () => {
    if (!selectedId || !file) return;
    try {
      const form = new FormData();
      form.append("file", file);
      await uploadCaseAttachment(selectedId, form);
      setFile(null);
      await loadCaseDetail(selectedId);
    } catch (err) {
      setError(formatApiError(err, "Unable to upload attachment."));
    }
  };

  const downloadAttachment = async (attachment) => {
    if (!selectedId) return;
    try {
      const id = attachment[0];
      const filename = attachment[1];
      const res = await downloadCaseAttachment(selectedId, id);
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", filename || "attachment");
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      setError(formatApiError(err, "Unable to download attachment."));
    }
  };

  const uploadEvidence = async () => {
    if (!selectedId || !evidenceFile) return;
    try {
      const form = new FormData();
      form.append("file", evidenceFile);
      if (evidenceLabel) form.append("label", evidenceLabel);
      if (evidenceCategory) form.append("category", evidenceCategory);
      if (evidenceNotes) form.append("notes", evidenceNotes);
      await uploadCaseEvidence(selectedId, form);
      setEvidenceFile(null);
      setEvidenceLabel("");
      setEvidenceCategory("");
      setEvidenceNotes("");
      await loadCaseDetail(selectedId);
    } catch (err) {
      setError(formatApiError(err, "Unable to upload evidence."));
    }
  };

  const downloadEvidence = async (item) => {
    if (!selectedId) return;
    try {
      const id = item[0];
      const filename = item[1];
      const res = await downloadCaseEvidence(selectedId, id);
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", filename || "evidence");
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      setError(formatApiError(err, "Unable to download evidence."));
    }
  };

  const loadCustody = async (item) => {
    if (!selectedId) return;
    try {
      const id = item[0];
      setSelectedEvidence(item);
      const res = await getCaseEvidenceCustody(selectedId, id);
      setCustody(res.data || []);
    } catch (err) {
      setError(formatApiError(err, "Unable to load custody chain."));
    }
  };

  const exportTimeline = (format) => {
    if (!selectedId) return;
    const url = getCaseTimelineExportUrl(selectedId, {
      event_type: timelineFilter || undefined,
      format
    });
    window.open(url, "_blank");
  };

  const timelineTypes = [
    "",
    "case_created",
    "alert_attached",
    "approval_requested",
    "approval_approved",
    "approval_rejected",
    "execution_started",
    "execution_finished",
    "action_executed",
    "note_added",
    "status_changed",
    "attachment_added",
    "evidence_added",
    "evidence_locked",
    "risk_updated"
  ];

  const statusClass = (status) => {
    if (!status) return "neutral";
    if (status === "RESOLVED" || status === "CLOSED") return "success";
    if (status === "IN_PROGRESS") return "pending";
    return "neutral";
  };

  const filteredCases = cases.filter((c) => {
    const id = String(c[0] ?? "");
    const title = String(c[1] ?? "").toLowerCase();
    const status = String(c[3] ?? "");
    const owner = String(c[4] ?? "").toLowerCase();
    const query = caseSearch.trim().toLowerCase();
    const matchesQuery =
      !query ||
      id.includes(query) ||
      title.includes(query) ||
      owner.includes(query);
    const matchesStatus = !statusFilter || status === statusFilter;
    return matchesQuery && matchesStatus;
  });

  const caseStats = cases.reduce(
    (acc, c) => {
      const status = String(c[3] || "OPEN");
      acc.total += 1;
      acc[status] = (acc[status] || 0) + 1;
      return acc;
    },
    { total: 0, OPEN: 0, IN_PROGRESS: 0, RESOLVED: 0, CLOSED: 0 }
  );

  const lockEvidence = async (item) => {
    if (!selectedId) return;
    try {
      const id = item[0];
      await lockCaseEvidence(selectedId, id);
      await loadCaseDetail(selectedId);
      await loadCustody(item);
    } catch (err) {
      setError(formatApiError(err, "Unable to lock evidence."));
    }
  };

  const iocGraphView = useMemo(() => {
    const nodes = Array.isArray(iocGraph.nodes) ? iocGraph.nodes : [];
    const edges = Array.isArray(iocGraph.edges) ? iocGraph.edges : [];
    if (!nodes.length) {
      return { option: null, height: 280 };
    }

    const columns = { case: [], alert: [], ioc: [] };
    nodes.forEach((node) => {
      const typeKey = columns[node.type] ? node.type : "ioc";
      columns[typeKey].push(node);
    });

    const width = 760;
    const rowGap = 86;
    const columnX = { case: 120, alert: 380, ioc: 640 };
    const maxRows = Math.max(columns.case.length, columns.alert.length, columns.ioc.length, 1);
    const height = maxRows * rowGap + 100;
    const positions = {};

    ["case", "alert", "ioc"].forEach((column) => {
      columns[column].forEach((node, idx) => {
        positions[String(node.id)] = {
          x: columnX[column],
          y: 56 + idx * rowGap,
        };
      });
    });

    const palette = {
      case: ["#8ea8ff", "#4968e6"],
      alert: ["#ffaf94", "#ea7150"],
      ioc: ["#98ffd9", "#21ad82"],
    };

    const graphNodes = nodes.map((node) => {
      const typeKey = columns[node.type] ? node.type : "ioc";
      const pos = positions[String(node.id)] || { x: width / 2, y: height / 2 };
      const [colorA, colorB] = palette[typeKey];
      return {
        id: String(node.id),
        name: String(node.label || node.id || "node"),
        value: String(typeKey).toUpperCase(),
        x: pos.x,
        y: pos.y,
        symbolSize: typeKey === "ioc" ? 32 : 38,
        itemStyle: {
          color: {
            type: "radial",
            x: 0.34,
            y: 0.32,
            r: 1,
            colorStops: [
              { offset: 0, color: colorA },
              { offset: 1, color: colorB },
            ],
          },
          borderColor: "rgba(207, 228, 248, 0.86)",
          borderWidth: 1.6,
          shadowBlur: 16,
          shadowColor: "rgba(38, 118, 186, 0.35)",
        },
        label: {
          show: true,
          position: "right",
          formatter: (params) => `${params.name}\n{sub|${params.data.value}}`,
          rich: {
            sub: {
              color: "#9ab6d4",
              fontSize: 11,
              fontWeight: 600,
            },
          },
          color: "#e9f4ff",
          fontSize: 12,
          fontWeight: 700,
          lineHeight: 17,
          textBorderColor: "rgba(5, 10, 18, 0.9)",
          textBorderWidth: 3,
        },
      };
    });

    const graphLinks = edges
      .filter((edge) => positions[String(edge.source)] && positions[String(edge.target)])
      .map((edge) => ({
        source: String(edge.source),
        target: String(edge.target),
        lineStyle: {
          width: 2.6,
          curveness: 0.22,
          color: "rgba(117, 196, 247, 0.72)",
          shadowBlur: 8,
          shadowColor: "rgba(55, 157, 226, 0.22)",
        },
      }));

    return {
      height: Math.max(300, height),
      option: {
        backgroundColor: "transparent",
        tooltip: {
          trigger: "item",
          backgroundColor: "rgba(6, 12, 21, 0.94)",
          borderColor: "rgba(122, 166, 201, 0.62)",
          borderWidth: 1,
          textStyle: { color: "#d7ebff" },
          formatter: (params) => {
            if (params.dataType === "edge") {
              return `${params.data.source} -> ${params.data.target}`;
            }
            return `${params.data.value}: ${params.data.name}`;
          },
        },
        series: [
          {
            type: "graph",
            layout: "none",
            data: graphNodes,
            links: graphLinks,
            roam: true,
            draggable: false,
            edgeSymbol: ["none", "arrow"],
            edgeSymbolSize: [0, 7],
            lineStyle: { opacity: 0.78 },
            emphasis: {
              focus: "adjacency",
              scale: true,
              lineStyle: { width: 3.2, opacity: 1, color: "rgba(157, 223, 255, 1)" },
            },
            force: { repulsion: 140 },
          },
        ],
      },
    };
  }, [iocGraph]);

  const iocGraph3DView = useMemo(() => {
    const nodes = Array.isArray(iocGraph.nodes) ? iocGraph.nodes : [];
    const edges = Array.isArray(iocGraph.edges) ? iocGraph.edges : [];
    if (!nodes.length) {
      return { option: null, height: 320 };
    }

    const columns = { case: [], alert: [], ioc: [] };
    nodes.forEach((node) => {
      const typeKey = columns[node.type] ? node.type : "ioc";
      columns[typeKey].push(node);
    });

    const maxRows = Math.max(columns.case.length, columns.alert.length, columns.ioc.length, 1);
    const yOffset = ((maxRows - 1) * 14) / 2;
    const positions = {};
    const xByColumn = { case: -42, alert: 0, ioc: 42 };
    const zByType = { case: 8, alert: 0, ioc: -8 };
    const typeLabel = { case: "CASE", alert: "ALERT", ioc: "IOC" };
    const palette = {
      case: ["#8ea8ff", "#4f73f0"],
      alert: ["#ffb494", "#eb7657"],
      ioc: ["#94ffd9", "#24b488"],
    };

    ["case", "alert", "ioc"].forEach((column) => {
      columns[column].forEach((node, idx) => {
        positions[String(node.id)] = {
          x: xByColumn[column],
          y: yOffset - idx * 14,
          z: zByType[column],
        };
      });
    });

    const nodeData = nodes.map((node) => {
      const nodeId = String(node.id);
      const typeKey = columns[node.type] ? node.type : "ioc";
      const pos = positions[nodeId] || { x: 0, y: 0, z: 0 };
      const [colorA, colorB] = palette[typeKey];
      return {
        name: String(node.label || node.id || "node"),
        value: [pos.x, pos.y, pos.z, String(node.label || node.id || "node"), typeLabel[typeKey], typeKey === "ioc" ? 18 : 22],
        nodeType: typeLabel[typeKey],
        itemStyle: {
          color: {
            type: "linear",
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: colorA },
              { offset: 1, color: colorB },
            ],
          },
          opacity: 0.97,
        },
      };
    });

    const nodeNameById = new Map(nodes.map((node) => [String(node.id), String(node.label || node.id || "node")]));
    const linkData = edges
      .filter((edge) => positions[String(edge.source)] && positions[String(edge.target)])
      .map((edge) => ({
        sourceName: nodeNameById.get(String(edge.source)) || String(edge.source),
        targetName: nodeNameById.get(String(edge.target)) || String(edge.target),
        coords: [
          [positions[String(edge.source)].x, positions[String(edge.source)].y, positions[String(edge.source)].z],
          [positions[String(edge.target)].x, positions[String(edge.target)].y, positions[String(edge.target)].z],
        ],
      }));

    return {
      height: Math.max(320, maxRows * 44 + 118),
      option: {
        backgroundColor: "transparent",
        tooltip: {
          trigger: "item",
          backgroundColor: "rgba(6, 12, 21, 0.94)",
          borderColor: "rgba(122, 166, 201, 0.62)",
          borderWidth: 1,
          textStyle: { color: "#d7ebff" },
          formatter: (params) => {
            if (params.seriesType === "lines3D") {
              return `${params.data?.sourceName || "-"} -> ${params.data?.targetName || "-"}`;
            }
            const tuple = Array.isArray(params.value) ? params.value : [];
            return `${tuple[4] || "NODE"}: ${tuple[3] || params.name || "-"}`;
          },
        },
        xAxis3D: {
          type: "value",
          min: -56,
          max: 56,
          axisLine: { lineStyle: { color: "rgba(123, 164, 196, 0.5)" } },
          axisLabel: { show: false },
          splitLine: { lineStyle: { color: "rgba(123, 164, 196, 0.16)" } },
        },
        yAxis3D: {
          type: "value",
          min: -Math.max(18, yOffset + 10),
          max: Math.max(18, yOffset + 10),
          axisLine: { lineStyle: { color: "rgba(123, 164, 196, 0.38)" } },
          axisLabel: { show: false },
          splitLine: { lineStyle: { color: "rgba(123, 164, 196, 0.12)" } },
        },
        zAxis3D: {
          type: "value",
          min: -18,
          max: 18,
          axisLine: { lineStyle: { color: "rgba(123, 164, 196, 0.38)" } },
          axisLabel: { show: false },
          splitLine: { lineStyle: { color: "rgba(123, 164, 196, 0.12)" } },
        },
        grid3D: {
          boxWidth: 138,
          boxDepth: Math.max(44, maxRows * 17),
          boxHeight: 46,
          viewControl: {
            projection: "perspective",
            alpha: 18,
            beta: 26,
            distance: 136,
            panSensitivity: 1,
            rotateSensitivity: 1,
            zoomSensitivity: 0.7,
            autoRotate: false,
          },
          axisPointer: {
            show: true,
            lineStyle: { color: "rgba(132, 216, 255, 0.64)" },
          },
          light: {
            main: { intensity: 1.05, shadow: false },
            ambient: { intensity: 0.5 },
          },
        },
        series: [
          {
            type: "lines3D",
            data: linkData,
            blendMode: "lighter",
            lineStyle: {
              width: 2.2,
              color: "rgba(116, 206, 255, 0.76)",
              opacity: 0.86,
            },
          },
          {
            type: "scatter3D",
            symbol: "circle",
            data: nodeData,
            symbolSize: (value) => Number(value?.[5] || 18),
            label: {
              show: true,
              formatter: (params) => {
                const tuple = Array.isArray(params.value) ? params.value : [];
                return `${tuple[3] || params.name}\n${tuple[4] || "NODE"}`;
              },
              distance: 8,
              textStyle: {
                color: "#e7f4ff",
                fontSize: 11,
                fontWeight: 700,
                borderColor: "rgba(6, 12, 20, 0.9)",
                borderWidth: 3,
              },
            },
            itemStyle: {
              borderColor: "rgba(213, 232, 248, 0.86)",
              borderWidth: 1.4,
              shadowBlur: 10,
              shadowColor: "rgba(45, 125, 189, 0.38)",
            },
            emphasis: {
              itemStyle: {
                borderColor: "#d7f2ff",
                shadowBlur: 16,
                shadowColor: "rgba(100, 192, 255, 0.62)",
              },
            },
          },
        ],
      },
    };
  }, [iocGraph]);

  const renderGraph = () => {
    if (!iocGraphView.option) {
      return <div className="empty-state">No IOC graph data yet.</div>;
    }
    const use3D = iocThreeDAvailable && Boolean(iocGraph3DView.option);
    const activeHeight = use3D ? iocGraph3DView.height : iocGraphView.height;
    return (
      <div className="ioc-graph-wrap">
        {use3D ? (
          <EChart3DPanel
            option={iocGraph3DView.option}
            style={{ width: "100%", height: activeHeight }}
            loading={detailLoading}
            onUnavailable={() => setIocThreeDAvailable(false)}
          />
        ) : (
          <EChartGraphPanel option={iocGraphView.option} style={{ width: "100%", height: activeHeight }} />
        )}
      </div>
    );
  };

  if (loading) return <div className="page page-route-cases"><div className="empty-state">Loading cases...</div></div>;
  if (error) return <div className="page page-route-cases"><div className="empty-state">Error: {error}</div></div>;

  return (
    <div className="page page-route-cases">
      <div className="page-header">
        <div>
          <h2>Cases</h2>
          <p className="muted">Investigation pipeline and current case load.</p>
        </div>
        <div className="page-actions">
          <input
            className="input"
            value={caseSearch}
            onChange={(e) => setCaseSearch(e.target.value)}
            placeholder="Search by title, owner, or ID"
          />
          <select
            className="input"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="">All statuses</option>
            <option value="OPEN">OPEN</option>
            <option value="IN_PROGRESS">IN_PROGRESS</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="CLOSED">CLOSED</option>
          </select>
          <button className="btn secondary" onClick={loadCases}>Refresh</button>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>New Case</h3>
              <p className="muted">Log an incident and link an alert if needed.</p>
            </div>
          </div>
          <div className="list">
            <div className="list-item">
              <div className="muted">Case title</div>
              <input
                className="input"
                value={newCaseTitle}
                onChange={(e) => setNewCaseTitle(e.target.value)}
                placeholder="Suspicious login investigation"
              />
            </div>
            <div className="list-item">
              <div className="muted">Description</div>
              <textarea
                className="input"
                value={newCaseDesc}
                onChange={(e) => setNewCaseDesc(e.target.value)}
                placeholder="Capture the scope and initial context."
              />
            </div>
            <div className="list-item">
              <div className="muted">Link alert (optional)</div>
              <input
                className="input"
                value={newAlertId}
                onChange={(e) => setNewAlertId(e.target.value)}
                placeholder="Alert ID"
              />
            </div>
            <div className="list-item">
              <button className="btn" onClick={createCase}>Create Case</button>
            </div>
            {createStatus && <div className="empty-state">{createStatus}</div>}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Case Overview</h3>
              <p className="muted">Status distribution for active investigations.</p>
            </div>
          </div>
          <div className="kpi-grid">
            <div className="kpi-card">
              <div className="kpi-label">Total</div>
              <div className="kpi-value">{caseStats.total}</div>
              <div className="kpi-meta">All cases</div>
            </div>
            <div className="kpi-card">
              <div className="kpi-label">Open</div>
              <div className="kpi-value">{caseStats.OPEN}</div>
              <div className="kpi-meta">Awaiting triage</div>
            </div>
            <div className="kpi-card">
              <div className="kpi-label">In Progress</div>
              <div className="kpi-value">{caseStats.IN_PROGRESS}</div>
              <div className="kpi-meta">Active response</div>
            </div>
            <div className="kpi-card">
              <div className="kpi-label">Resolved</div>
              <div className="kpi-value">{caseStats.RESOLVED}</div>
              <div className="kpi-meta">Mitigated</div>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Case Queue</h3>
            <p className="muted">Current investigations and ownership across the case desk.</p>
          </div>
          <span className="chip">{filteredCases.length} visible</span>
        </div>
        <div className="table-scroll">
          <table className="table readable">
            <thead>
              <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Status</th>
                <th>Owner</th>
                <th>Created</th>
              </tr>
            </thead>

            <tbody>
              {filteredCases.length === 0 ? (
                <tr>
                  <td colSpan="5" className="text-center">
                    No cases found
                  </td>
                </tr>
              ) : (
                filteredCases.map(c => (
                  <tr
                    key={c[0]}
                    onClick={() => {
                      setSelectedId(c[0]);
                      setSelectedEvidence(null);
                      setCustody([]);
                      loadCaseDetail(c[0]);
                      setSearchParams({ case: String(c[0]) });
                    }}
                    className={`clickable ${selectedId === c[0] ? "selected" : ""}`}
                  >
                    <td>{c[0]}</td>
                    <td>{c[1]}</td>
                    <td>
                      <span className={`status-pill ${statusClass(c[3])}`}>{c[3]}</span>
                    </td>
                    <td>{c[4]}</td>
                    <td><RelativeTimestamp value={c[5]} /></td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selectedId && (
        <div className="grid-2 mt-24">
          <div className="card">
            <div className="card-header">
              <div>
                <h3>Case Detail</h3>
                <p className="muted">Context, alerts, and notes.</p>
              </div>
            </div>
            {detailLoading ? (
              <div className="empty-state">Loading details...</div>
            ) : detail ? (
              <div className="list">
                <div className="list-item">
                  <strong>{detail.case?.[1]}</strong>
                  <div className="muted">Status: {detail.case?.[3]}</div>
                  <div className="muted">Owner: {detail.case?.[4]}</div>
                </div>
                <div className="list-item">
                  <div className="muted">AI Case Summary</div>
                  <div className="page-actions mt-8">
                    <button className="btn secondary" onClick={generateCaseAiSummary} disabled={aiSummaryLoading}>
                      {aiSummaryLoading ? "Generating..." : "Generate AI Summary"}
                    </button>
                  </div>
                  <div className="muted mt-8">
                    AI uses Org Admin / Platform AI Configuration.
                  </div>
                  {aiSummaryError ? <div className="empty-state mt-8">{aiSummaryError}</div> : null}
                  {aiSummary ? (
                    <div className="list mt-8">
                      <div className="list-item">
                        <div>{aiSummary.summary || "-"}</div>
                      </div>
                      {Array.isArray(aiSummary.findings) && aiSummary.findings.length ? (
                        <div className="list-item">
                          <div className="muted">Findings</div>
                          <ul className="list mt-8">
                            {aiSummary.findings.map((item, idx) => (
                              <li className="list-item" key={`case-finding-${idx}`}>{item}</li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                      {Array.isArray(aiSummary.recommended_actions) && aiSummary.recommended_actions.length ? (
                        <div className="list-item">
                          <div className="muted">Recommended Actions</div>
                          <ul className="list mt-8">
                            {aiSummary.recommended_actions.map((item, idx) => (
                              <li className="list-item" key={`case-action-${idx}`}>{item}</li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                      {aiSummary.usage ? (
                        <div className="list-item">
                          <div className="muted">Token Usage</div>
                          <div className="meta-line mt-8">
                            Prompt: {aiSummary.usage.prompt_tokens ?? 0} | Completion: {aiSummary.usage.completion_tokens ?? 0} | Total: {aiSummary.usage.total_tokens ?? 0}
                          </div>
                        </div>
                      ) : null}
                    </div>
                  ) : null}
                </div>
                <div className="list-item">
                  <div className="muted">Update Status</div>
                  <div className="page-actions mt-8">
                    <select
                      className="input"
                      value={statusValue}
                      onChange={(e) => setStatusValue(e.target.value)}
                    >
                      <option value="OPEN">OPEN</option>
                      <option value="IN_PROGRESS">IN_PROGRESS</option>
                      <option value="RESOLVED">RESOLVED</option>
                      <option value="CLOSED">CLOSED</option>
                    </select>
                    <button className="btn" onClick={updateStatus}>
                      Save
                    </button>
                  </div>
                </div>
                <div className="list-item">
                  <div className="muted">Risk & Impact</div>
                  <div className="page-actions mt-8">
                    <input
                      className="input"
                      type="number"
                      min="0"
                      max="100"
                      placeholder="Risk score (0-100)"
                      value={riskScore}
                      onChange={(e) => setRiskScore(e.target.value)}
                    />
                    <select
                      className="input"
                      value={riskImpact}
                      onChange={(e) => setRiskImpact(e.target.value)}
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                    <button className="btn secondary" onClick={updateRisk}>
                      Update Risk
                    </button>
                  </div>
                </div>
                <div className="list-item">
                  <div className="muted">Linked Alerts</div>
                  {detail.alerts?.length ? (
                    <ul className="list">
                      {detail.alerts.map((a, i) => (
                        <li key={i} className="list-item">{a[0]}</li>
                      ))}
                    </ul>
                  ) : (
                    <div className="empty-state">No alerts linked.</div>
                  )}
                </div>
                <div className="list-item">
                  <div className="muted">Notes</div>
                  <div className="page-actions mt-8">
                    <input
                      className="input"
                      value={note}
                      onChange={(e) => setNote(e.target.value)}
                      placeholder="Add a note..."
                    />
                    <button className="btn secondary" onClick={submitNote}>
                      Add Note
                    </button>
                  </div>
                  {detail.notes?.length ? (
                    <ul className="list">
                      {detail.notes.map((n, i) => (
                        <li key={i} className="list-item">
                          <div>{n[1]}</div>
                          <div className="muted">{n[0]} - {formatWazuhTimestamp(n[2])}</div>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div className="empty-state">No notes.</div>
                  )}
                </div>
                <div className="list-item">
                  <div className="muted">Attachments</div>
                  <div className="page-actions mt-8">
                    <input
                      className="input"
                      type="file"
                      onChange={(e) => setFile(e.target.files?.[0] || null)}
                    />
                    <button className="btn secondary" onClick={uploadAttachment}>
                      Upload
                    </button>
                  </div>
                  {attachments.length ? (
                    <ul className="list">
                      {attachments.map((a) => (
                        <li key={a[0]} className="list-item">
                          <div>{a[1]}</div>
                          <div className="muted">
                            {a[3]} bytes - {a[5]} - {formatWazuhTimestamp(a[6])}
                          </div>
                          <button className="btn secondary" onClick={() => downloadAttachment(a)}>
                            Download
                          </button>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div className="empty-state">No attachments.</div>
                  )}
                </div>
                <div className="list-item">
                  <div className="muted">Evidence Locker</div>
                  <div className="page-actions mt-8">
                    <input
                      className="input"
                      type="file"
                      onChange={(e) => setEvidenceFile(e.target.files?.[0] || null)}
                    />
                    <input
                      className="input"
                      value={evidenceLabel}
                      onChange={(e) => setEvidenceLabel(e.target.value)}
                      placeholder="Label"
                    />
                    <input
                      className="input"
                      value={evidenceCategory}
                      onChange={(e) => setEvidenceCategory(e.target.value)}
                      placeholder="Category"
                    />
                    <input
                      className="input"
                      value={evidenceNotes}
                      onChange={(e) => setEvidenceNotes(e.target.value)}
                      placeholder="Notes"
                    />
                    <button className="btn secondary" onClick={uploadEvidence}>
                      Upload Evidence
                    </button>
                  </div>
                  {evidence.length ? (
                    <ul className="list">
                      {evidence.map((ev) => (
                        <li key={ev[0]} className="list-item">
                          <div>
                            <strong>{ev[5] || ev[1]}</strong>
                          </div>
                          <div className="muted">
                            {ev[3]} bytes - {ev[4]} - {formatWazuhTimestamp(ev[10])}
                          </div>
                          <div className="page-actions mt-8">
                            <button className="btn secondary" onClick={() => downloadEvidence(ev)}>
                              Download
                            </button>
                            <button className="btn" onClick={() => loadCustody(ev)}>
                              Custody
                            </button>
                            <button
                              className="btn danger"
                              onClick={() => lockEvidence(ev)}
                              disabled={ev[9]}
                            >
                              {ev[9] ? "Locked" : "Lock"}
                            </button>
                          </div>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div className="empty-state">No evidence yet.</div>
                  )}
                </div>
              </div>
            ) : (
              <div className="empty-state">Select a case to view details.</div>
            )}
          </div>
          <div className="card">
            <div className="card-header">
              <div>
                <h3>Timeline</h3>
                <p className="muted">Case actions and approvals.</p>
              </div>
              <div className="page-actions">
                <select
                  className="input"
                  value={timelineFilter}
                  onChange={(e) => {
                    const value = e.target.value;
                    setTimelineFilter(value);
                    if (selectedId) {
                      loadCaseDetail(selectedId, value);
                    }
                  }}
                >
                  {timelineTypes.map((t) => (
                    <option key={t || "all"} value={t}>
                      {t ? t.replace(/_/g, " ") : "All events"}
                    </option>
                  ))}
                </select>
                <button className="btn secondary" onClick={() => exportTimeline("csv")}>
                  Export CSV
                </button>
                <button className="btn" onClick={() => exportTimeline("json")}>
                  Export JSON
                </button>
              </div>
            </div>
            {detailLoading ? (
              <div className="empty-state">Loading timeline...</div>
            ) : timeline.length === 0 ? (
              <div className="empty-state">No timeline events.</div>
            ) : (
              <ul className="list">
                {timeline.map((e) => (
                  <li key={e[0]} className="list-item">
                    <strong>{e[1]}</strong>
                    <div className="muted">{formatWazuhTimestamp(e[4])}</div>
                    {e[2] && <div>{e[2]}</div>}
                    {e[3] && <div className="muted">Actor: {e[3]}</div>}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}

      {selectedId && (
        <div className="card mt-24">
          <div className="card-header">
            <div>
              <h3>Attack Path</h3>
              <p className="muted">MITRE-mapped path inferred from linked alerts.</p>
            </div>
          </div>
          {detailLoading ? (
            <div className="empty-state">Loading attack path...</div>
          ) : attackPath.length === 0 ? (
            <div className="empty-state">No attack path data yet.</div>
          ) : (
            <ul className="list">
              {attackPath.map((step, idx) => (
                <li key={`${step[0]}-${idx}`} className="list-item">
                  <strong>Step {idx + 1}</strong>
                  <div className="muted">{step[1]}</div>
                  <div>
                    {step[2] ? `${step[2]} - ${step[3]} (${step[4]})` : `Alert ${step[0]}`}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {selectedEvidence && (
        <div className="card mt-24">
          <div className="card-header">
            <div>
              <h3>Chain of Custody</h3>
              <p className="muted">Evidence access and custody log.</p>
            </div>
          </div>
          {custody.length === 0 ? (
            <div className="empty-state">No custody events yet.</div>
          ) : (
            <ul className="list">
              {custody.map((e) => (
                <li key={e[0]} className="list-item">
                  <strong>{e[1]}</strong>
                  <div className="muted">{e[4]}</div>
                  {e[2] && <div className="muted">Actor: {e[2]}</div>}
                  {e[3] && <div>{e[3]}</div>}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {selectedId && (
        <div className="card mt-24">
          <div className="card-header">
            <div>
              <h3>IOC Graph</h3>
              <p className="muted">Case - alerts - IOCs relationship map.</p>
            </div>
          </div>
          {detailLoading ? (
            <div className="empty-state">Loading IOC graph...</div>
          ) : (
            renderGraph()
          )}
        </div>
      )}
    </div>
  );
}

