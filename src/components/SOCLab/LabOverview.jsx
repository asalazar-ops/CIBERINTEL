import { Activity, Shield, Terminal, Zap, Calendar, User, Clock } from "lucide-react";

export default function LabOverview({ data }) {
  return (
    <div style={{ animation: "fu 0.4s ease-out both" }}>
      {/* Header Section */}
      <div style={{ 
        background: "radial-gradient(circle at top left, rgba(56, 189, 248, 0.15) 0%, transparent 70%)",
        padding: "40px", borderRadius: "16px", border: "1px solid rgba(56, 189, 248, 0.2)",
        marginBottom: "32px", position: "relative", overflow: "hidden"
      }}>
        <div style={{ position: "absolute", top: "20px", right: "20px", opacity: 0.1 }}><Shield size={120} color="#38bdf8" /></div>
        
        <div style={{ background: "rgba(56, 189, 248, 0.1)", border: "1px solid #38bdf8", color: "#38bdf8", padding: "4px 12px", borderRadius: "99px", fontSize: "0.7rem", fontWeight: 700, letterSpacing: "1.5px", textTransform: "uppercase", display: "inline-block", marginBottom: "16px" }}>
          Laboratorio Ejecutivo
        </div>
        
        <h1 style={{ fontSize: "2.8rem", fontWeight: 800, color: "#f8fafc", margin: "0 0 8px 0" }}>{data.title}</h1>
        <h2 style={{ fontSize: "1.5rem", fontWeight: 600, color: "#38bdf8", margin: "0 0 20px 0" }}>{data.subtitle}</h2>
        
        <p style={{ fontSize: "1.1rem", color: "#94a3b8", maxWidth: "800px", lineHeight: 1.6, margin: 0 }}>
          {data.description}
        </p>

        <div style={{ display: "flex", gap: "24px", marginTop: "32px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#cbd5e1", fontSize: "0.9rem" }}>
            <Clock size={18} color="#38bdf8" /> <strong>Duración:</strong> {data.duration}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#cbd5e1", fontSize: "0.9rem" }}>
            <User size={18} color="#38bdf8" /> <strong>Perfil:</strong> {data.target}
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px" }}>
        {/* Agenda Section */}
        <div style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "12px", padding: "24px" }}>
          <h3 style={{ fontSize: "1.1rem", fontWeight: 700, color: "#f8fafc", marginBottom: "20px", display: "flex", alignItems: "center", gap: "10px" }}>
            <Calendar size={20} color="#38bdf8" /> Agenda del Laboratorio
          </h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {data.agenda.map((item, i) => (
              <div key={i} style={{ display: "flex", gap: "12px", alignItems: "flex-start" }}>
                <div style={{ width: "22px", height: "22px", background: "rgba(56, 189, 248, 0.1)", borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", color: "#38bdf8", fontSize: "0.75rem", fontWeight: 700, flexShrink: 0 }}>
                  {i + 1}
                </div>
                <span style={{ color: "#cbd5e1", fontSize: "0.9rem" }}>{item}</span>
              </div>
            ))}
          </div>
        </div>

        {/* History Section */}
        <div style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "12px", padding: "24px" }}>
          <h3 style={{ fontSize: "1.1rem", fontWeight: 700, color: "#f8fafc", marginBottom: "20px", display: "flex", alignItems: "center", gap: "10px" }}>
            <Activity size={20} color="#ef4444" /> La historia completa
          </h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            {data.scenarios.map((s, i) => (
              <div key={s.id} style={{ padding: "12px", background: "rgba(15, 23, 42, 0.5)", borderRadius: "8px", borderLeft: "4px solid #38bdf8" }}>
                <h4 style={{ fontSize: "0.9rem", color: "#38bdf8", fontWeight: 700, marginBottom: "8px" }}>Escenario {s.id} · {s.title}</h4>
                <ul style={{ margin: 0, paddingLeft: "18px", color: "#94a3b8", fontSize: "0.8rem", display: "flex", flexDirection: "column", gap: "4px" }}>
                  {s.items.map((item, j) => (
                    <li key={j}>{item}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
