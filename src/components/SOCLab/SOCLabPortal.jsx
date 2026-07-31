import { useState } from "react";
import { Terminal, Shield, List, Info, ChevronRight } from "lucide-react";
import LabOverview from "./LabOverview";
import ScenarioView from "./ScenarioView";
import { labData } from "./socLabContent";

export default function SOCLabPortal() {
  const [activeView, setActiveView] = useState("overview"); // overview, e1, e2, e3

  const renderContent = () => {
    switch (activeView) {
      case "overview":
        return <LabOverview data={labData.overview} />;
      case "e1":
        return <ScenarioView data={labData.scenarios[0]} />;
      case "e2":
        return <ScenarioView data={labData.scenarios[1]} />;
      case "e3":
        return <ScenarioView data={labData.scenarios[2]} />;
      default:
        return <LabOverview data={labData.overview} />;
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Top Breadcrumb/Nav */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div style={{ background: "#38bdf8", padding: "8px", borderRadius: "8px" }}><Terminal size={20} color="#0f172a" /></div>
          <div>
            <h2 style={{ fontSize: "1.5rem", fontWeight: 700, color: "#f8fafc", margin: 0 }}>SOC Lab Portal</h2>
            <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "#64748b", fontSize: "0.8rem" }}>
              Workshops <ChevronRight size={14} /> ESET Protect Elite <ChevronRight size={14} /> {activeView === "overview" ? "Overview" : `Escenario ${activeView.replace('e', '')}`}
            </div>
          </div>
        </div>

        <div style={{ display: "flex", background: "#1e293b", borderRadius: "10px", padding: "4px", border: "1px solid #334155" }}>
          <button 
            onClick={() => setActiveView("overview")}
            style={{ 
              background: activeView === "overview" ? "#334155" : "transparent",
              border: "none", color: activeView === "overview" ? "#f8fafc" : "#94a3b8",
              padding: "8px 16px", borderRadius: "6px", fontSize: "0.85rem", fontWeight: 600,
              cursor: "pointer", display: "flex", alignItems: "center", gap: "8px",
              transition: "all 0.2s"
            }}
          >
            <Info size={16} /> Resumen
          </button>
          {[1, 2, 3].map(num => (
            <button 
              key={num}
              onClick={() => setActiveView(`e${num}`)}
              style={{ 
                background: activeView === `e${num}` ? "#334155" : "transparent",
                border: "none", color: activeView === `e${num}` ? "#f8fafc" : "#94a3b8",
                padding: "8px 16px", borderRadius: "6px", fontSize: "0.85rem", fontWeight: 600,
                cursor: "pointer", display: "flex", alignItems: "center", gap: "8px",
                transition: "all 0.2s"
              }}
            >
              <Shield size={16} /> Escenario {num}
            </button>
          ))}
        </div>
      </div>

      {/* Main Content Area */}
      <div style={{ minHeight: "60vh" }}>
        {renderContent()}
      </div>

      {/* Footer Info */}
      <div style={{ 
        marginTop: "40px", padding: "20px", borderTop: "1px solid #1e293b",
        display: "flex", justifyContent: "space-between", alignItems: "center",
        color: "#475569", fontSize: "0.8rem"
      }}>
        <div>SOC Lab - ESET PROTECT Elite + ESET Inspect | INFORC Ecuador | 2026</div>
        <div style={{ color: "#ef4444", fontWeight: 600, display: "flex", alignItems: "center", gap: "6px" }}>
          <Shield size={14} /> SOLO PARA USO EN ENTORNOS CONTROLADOS
        </div>
      </div>
    </div>
  );
}
