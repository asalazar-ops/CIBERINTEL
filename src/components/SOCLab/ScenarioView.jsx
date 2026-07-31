import { useState } from "react";
import { Shield, Terminal, Zap, FileSearch, HelpCircle, Activity, ChevronRight, Lock, Unlock, Server } from "lucide-react";

export default function ScenarioView({ data }) {
  const [activeTab, setActiveTab] = useState("context");

  return (
    <div style={{ animation: "fu 0.4s ease-out both" }}>
      {/* Scenario Header */}
      <div style={{ 
        background: "linear-gradient(135deg, #0f172a 0%, #1e293b 100%)",
        padding: "32px", borderRadius: "12px", border: "1px solid #334155",
        marginBottom: "24px"
      }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div>
            <div style={{ background: "rgba(56, 189, 248, 0.1)", border: "1px solid #38bdf8", color: "#38bdf8", padding: "3px 10px", borderRadius: "4px", fontSize: "0.65rem", fontWeight: 700, letterSpacing: "1px", textTransform: "uppercase", display: "inline-block", marginBottom: "12px" }}>
              ESCENARIO {data.id} — ESET INSPECT
            </div>
            <h1 style={{ fontSize: "2rem", fontWeight: 800, color: "#f8fafc", margin: "0 0 8px 0" }}>{data.title}</h1>
            <p style={{ fontSize: "1rem", color: "#94a3b8", margin: 0 }}>{data.tagline}</p>
          </div>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", maxWidth: "400px", justifyContent: "flex-end" }}>
            {data.tags.map((tag, i) => (
              <span key={i} style={{ background: "rgba(15, 23, 42, 0.5)", border: "1px solid #334155", color: "#94a3b8", padding: "4px 10px", borderRadius: "16px", fontSize: "0.65rem", fontWeight: 500 }}>{tag}</span>
            ))}
          </div>
        </div>
      </div>

      {/* Internal Navigation */}
      <div style={{ display: "flex", gap: "12px", marginBottom: "24px", borderBottom: "1px solid #1e293b", paddingBottom: "12px" }}>
        {[
          { id: "context", label: "Contexto", icon: <Activity size={16} /> },
          { id: "detections", label: "Detecciones", icon: <Shield size={16} /> },
          { id: "investigation", label: "Investigación", icon: <Terminal size={16} /> },
          { id: "artifacts", label: "Artefactos", icon: <FileSearch size={16} /> },
          { id: "questions", label: "Desafío", icon: <HelpCircle size={16} /> }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{ 
              background: activeTab === tab.id ? "rgba(56, 189, 248, 0.1)" : "transparent",
              border: "none", color: activeTab === tab.id ? "#38bdf8" : "#64748b",
              padding: "8px 16px", borderRadius: "8px", fontSize: "0.85rem", fontWeight: 600,
              cursor: "pointer", display: "flex", alignItems: "center", gap: "8px",
              transition: "all 0.2s"
            }}
          >
            {tab.icon} {tab.label}
          </button>
        ))}
      </div>

      {/* Content Sections */}
      <div style={{ minHeight: "400px" }}>
        {activeTab === "context" && (
          <div style={{ animation: "fu 0.3s ease both" }}>
            <div style={{ background: "#1e293b", borderRadius: "12px", padding: "24px", border: "1px solid #334155", marginBottom: "24px" }}>
              <h3 style={{ color: "#38bdf8", fontSize: "0.75rem", fontWeight: 800, textTransform: "uppercase", letterSpacing: "2px", marginBottom: "12px" }}>01 — Contexto del ataque</h3>
              <p style={{ color: "#cbd5e1", lineHeight: 1.6, fontSize: "0.95rem" }}>{data.context}</p>
            </div>
            
            <h3 style={{ color: "#f8fafc", fontSize: "1rem", fontWeight: 700, marginBottom: "16px" }}>Kill Chain de la Amenaza</h3>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
              {data.killChain.map((step, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "8px", padding: "12px", textAlign: "center", minWidth: "140px" }}>
                    <div style={{ color: "#38bdf8", fontSize: "0.85rem", fontWeight: 700 }}>{step.name}</div>
                    <div style={{ color: "#64748b", fontSize: "0.65rem", fontWeight: 500, marginTop: "4px" }}>MITRE {step.tech}</div>
                  </div>
                  {i < data.killChain.length - 1 && <ChevronRight size={20} color="#334155" />}
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === "detections" && (
          <div style={{ animation: "fu 0.3s ease both" }}>
            <div style={{ background: "#1e293b", borderRadius: "12px", border: "1px solid #334155", overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "rgba(56, 189, 248, 0.1)" }}>
                    <th style={{ textAlign: "left", padding: "14px 20px", fontSize: "0.7rem", color: "#38bdf8", fontWeight: 700, textTransform: "uppercase" }}>Técnica</th>
                    <th style={{ textAlign: "left", padding: "14px 20px", fontSize: "0.7rem", color: "#38bdf8", fontWeight: 700, textTransform: "uppercase" }}>Comportamiento</th>
                    <th style={{ textAlign: "left", padding: "14px 20px", fontSize: "0.7rem", color: "#38bdf8", fontWeight: 700, textTransform: "uppercase" }}>Severidad</th>
                    <th style={{ textAlign: "left", padding: "14px 20px", fontSize: "0.7rem", color: "#38bdf8", fontWeight: 700, textTransform: "uppercase" }}>Ubicación</th>
                  </tr>
                </thead>
                <tbody>
                  {data.detections.map((det, i) => (
                    <tr key={i} style={{ borderBottom: "1px solid #334155" }}>
                      <td style={{ padding: "14px 20px", fontSize: "0.8rem", color: "#f8fafc", fontWeight: 600 }}>{det.tech}</td>
                      <td style={{ padding: "14px 20px", fontSize: "0.85rem", color: "#cbd5e1" }}>{det.behavior}</td>
                      <td style={{ padding: "14px 20px" }}>
                        <span style={{ 
                          background: det.severity === "THREAT" ? "rgba(239, 68, 68, 0.1)" : "rgba(245, 166, 35, 0.1)",
                          color: det.severity === "THREAT" ? "#ef4444" : "#f5a623",
                          padding: "3px 10px", borderRadius: "4px", fontSize: "0.7rem", fontWeight: 800, border: "1px solid"
                        }}>
                          {det.severity} {det.score}
                        </span>
                      </td>
                      <td style={{ padding: "14px 20px", fontSize: "0.8rem", color: "#94a3b8" }}>{det.location}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === "investigation" && (
          <div style={{ animation: "fu 0.3s ease both", display: "flex", flexDirection: "column", gap: "20px" }}>
            {data.phases.map((phase) => (
              <div key={phase.num} style={{ display: "flex", gap: "20px" }}>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                  <div style={{ width: "36px", height: "36px", background: "#38bdf8", color: "#0f172a", borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 800, fontSize: "0.9rem" }}>
                    {phase.num}
                  </div>
                  <div style={{ width: "2px", flex: 1, background: "#334155", marginTop: "8px" }} />
                </div>
                <div style={{ flex: 1, background: "#1e293b", border: "1px solid #334155", borderRadius: "12px", padding: "20px", marginBottom: "16px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px" }}>
                    <span style={{ background: "rgba(56, 189, 248, 0.1)", color: "#38bdf8", padding: "2px 8px", borderRadius: "4px", fontSize: "0.6rem", fontWeight: 700, textTransform: "uppercase" }}>Fase</span>
                    <h4 style={{ color: "#f8fafc", fontSize: "1.1rem", fontWeight: 700 }}>{phase.name}</h4>
                  </div>
                  <p style={{ color: "#94a3b8", fontSize: "0.9rem", marginBottom: "16px" }}>{phase.desc}</p>
                  <div style={{ background: "rgba(0,0,0,0.2)", borderRadius: "8px", padding: "16px", border: "1px solid #334155" }}>
                    <div style={{ color: "#38bdf8", fontSize: "0.65rem", fontWeight: 700, textTransform: "uppercase", letterSpacing: "1px", marginBottom: "12px" }}>Pasos en ESET Inspect</div>
                    {phase.steps.map((step, j) => (
                      <div key={j} style={{ display: "flex", gap: "10px", color: "#cbd5e1", fontSize: "0.85rem", marginBottom: "8px" }}>
                        <span style={{ color: "#38bdf8", fontWeight: 700 }}>{j + 1}.</span>
                        <span>{step}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === "artifacts" && (
          <div style={{ animation: "fu 0.3s ease both", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "20px" }}>
            {data.artifacts.map((art, i) => (
              <div key={i} style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "12px", padding: "20px", position: "relative", overflow: "hidden" }}>
                <div style={{ position: "absolute", top: 0, left: 0, width: "100%", height: "2px", background: "linear-gradient(90deg, #38bdf8, transparent)" }} />
                <div style={{ fontSize: "2rem", marginBottom: "12px" }}>{art.icon}</div>
                <h5 style={{ color: "#f8fafc", fontSize: "0.95rem", fontWeight: 700, marginBottom: "8px" }}>{art.title}</h5>
                <div style={{ background: "#0f172a", padding: "10px", borderRadius: "6px", color: "#38bdf8", fontFamily: "monospace", fontSize: "0.75rem", wordBreak: "break-all" }}>
                  {art.value}
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === "questions" && (
          <div style={{ animation: "fu 0.3s ease both", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
            {data.questions.map((q, i) => (
              <div key={i} style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "12px", padding: "24px", borderTop: "4px solid #38bdf8" }}>
                <div style={{ color: "#38bdf8", fontSize: "0.65rem", fontWeight: 700, textTransform: "uppercase", marginBottom: "8px" }}>Pregunta {i + 1}</div>
                <h4 style={{ color: "#f8fafc", fontSize: "1rem", fontWeight: 600, marginBottom: "16px", lineHeight: 1.4 }}>{q.q}</h4>
                <div style={{ borderTop: "1px solid #334155", paddingTop: "12px", marginTop: "12px" }}>
                  <span style={{ color: "#38bdf8", fontSize: "0.75rem", fontWeight: 700 }}>Pista:</span>
                  <p style={{ color: "#64748b", fontSize: "0.8rem", marginTop: "4px", fontStyle: "italic" }}>{q.hint}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
