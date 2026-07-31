import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from "react-simple-maps";
import { LayoutDashboard, ShieldAlert, Activity, Database, FileText, Settings, Search, User, MoreHorizontal, Bell, MapPin, Shield, Zap, Calendar, Filter, ChevronDown, ChevronUp, ExternalLink, RefreshCw, Plus, Trash2, CheckCircle, XCircle, ShieldCheck, AlertTriangle, List, Globe, Server, ZoomIn, ZoomOut, Terminal } from "lucide-react";

// ─── CONSTANTES ───────────────────────────────────────────────────────────────
const REGIONS  = ["Todos", "Ecuador", "Latinoamérica", "Global"];
const SECTORS  = ["Todos", "Banca", "Cooperativas", "Ransomware", "Phishing", "Fraude", "Fintech", "Infraestructura", "Regulatorio", "Vulnerabilidad", "General"];

const SEV_CLR  = {
  CRÍTICO: { bg: "#7f1d1d", b: "#ef4444", t: "#fecaca" }, 
  ALTO:    { bg: "#7c2d12", b: "#f97316", t: "#fed7aa" },
  MEDIO:   { bg: "#713f12", b: "#eab308", t: "#fef08a" },
  BAJO:    { bg: "#14532d", b: "#22c55e", t: "#bbf7d0" },
};
const SEV_ORD  = { CRÍTICO: 4, ALTO: 3, MEDIO: 2, BAJO: 1 };
const REG_CLR  = { Ecuador: "#f87171", Latinoamérica: "#fb923c", Global: "#7dd3fc" };

// ─── COMPONENTES PEQUEÑOS ─────────────────────────────────────────────────────
function SevBadge({ level }) {
  const c = SEV_CLR[level] || SEV_CLR.BAJO;
  return (
    <span style={{
      background: c.bg, color: c.t, fontSize: "0.6rem", fontWeight: 600, 
      letterSpacing: "0.05em", padding: "3px 8px", borderRadius: "4px", 
      whiteSpace: "nowrap", border: `1px solid ${c.b}40`
    }}>{level}</span>
  );
}

function Chip({ children, active, accent, onClick }) {
  return (
    <button onClick={onClick} style={{
      background: active ? `${accent}1A` : "transparent",
      border: `1px solid ${active ? accent : "#334155"}`,
      color: active ? accent : "#94a3b8",
      fontSize: "0.65rem", padding: "6px 14px", borderRadius: "16px",
      cursor: "pointer", fontWeight: 500, transition: "all 0.2s ease", 
      whiteSpace: "nowrap",
    }}
    onMouseEnter={e => { if (!active) { e.currentTarget.style.borderColor = "#64748b"; e.currentTarget.style.color = "#cbd5e1"; } }}
    onMouseLeave={e => { if (!active) { e.currentTarget.style.borderColor = "#334155"; e.currentTarget.style.color = "#94a3b8"; } }}
    >{children}</button>
  );
}

function Sparkline({ color, points }) {
  const max = Math.max(...points) || 1;
  const w = 80; const h = 25;
  const path = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${(i/(points.length-1)) * w} ${h - (p/max)*h}`).join(" ");
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} fill="none" style={{ overflow: "visible" }}>
      <path d={path} stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function StatCard({ val, label, accent, sub, onClick, points }) {
  return (
    <div 
      onClick={onClick}
      style={{
        background: "#1e293b", border: "1px solid #334155", borderRadius: "10px", 
        padding: "16px 20px", flex: 1, minWidth: "200px", display: "flex", flexDirection: "column",
        cursor: onClick ? "pointer" : "default", transition: "all 0.2s ease",
        boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1)",
      }}
      onMouseEnter={e => { if (onClick) e.currentTarget.style.borderColor = accent; }}
      onMouseLeave={e => { if (onClick) e.currentTarget.style.borderColor = "#334155"; }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "12px" }}>
        <div style={{ color: "#94a3b8", fontSize: "0.7rem", fontWeight: 600, letterSpacing: "0.02em" }}>{label}</div>
        <div style={{ color: accent, background: `${accent}15`, padding: "4px", borderRadius: "6px" }}><Activity size={14} /></div>
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
        <div>
          <div style={{ color: "#f8fafc", fontSize: "1.8rem", fontWeight: 700, lineHeight: 1 }}>{val}</div>
          {sub && <div style={{ color: accent, fontSize: "0.65rem", marginTop: "6px", fontWeight: 600 }}>{sub}</div>}
        </div>
        {points && <Sparkline color={accent} points={points} />}
      </div>
    </div>
  );
}

// ─── THREAT CARD (Portal Original) ────────────────────────────────────────────
function ThreatCard({ item, idx }) {
  const [open, setOpen] = useState(false);
  const rc = REG_CLR[item.region] || item.color || "#64748b";

  return (
    <div
      onClick={() => setOpen(o => !o)}
      style={{
        background: "#1e293b", border: "1px solid #334155", borderLeft: `4px solid ${rc}`,
        borderRadius: "8px", padding: "16px 20px", cursor: "pointer", transition: "all 0.2s ease",
        animation: `fu 0.3s ease ${Math.min(idx, 30) * 0.02}s both`,
      }}
      onMouseEnter={e => { e.currentTarget.style.background = "#27354f"; e.currentTarget.style.borderColor = "#475569"; }}
      onMouseLeave={e => { e.currentTarget.style.background = "#1e293b"; e.currentTarget.style.borderColor = "#334155"; }}
    >
      <div style={{ display: "flex", gap: "12px", alignItems: "flex-start", justifyContent: "space-between" }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center", marginBottom: "8px" }}>
            <SevBadge level={item.severity} />
            <span style={{ color: "#475569", fontSize: "0.65rem" }}>•</span>
            <span style={{ color: rc, fontSize: "0.65rem", fontWeight: 600 }}>{item.region}</span>
            <span style={{ color: "#475569", fontSize: "0.65rem" }}>•</span>
            <span style={{ color: "#cbd5e1", fontSize: "0.65rem", fontWeight: 500 }}>{item.sector}</span>
            <span style={{ color: "#475569", fontSize: "0.65rem" }}>•</span>
            <span style={{ color: item.color || "#94a3b8", fontSize: "0.65rem", fontWeight: 500 }}>{item.source}</span>
            <span style={{ color: "#64748b", fontSize: "0.65rem", marginLeft: "auto", flexShrink: 0 }}>{item.dateAgo}</span>
          </div>
          <h3 style={{ color: "#f8fafc", fontSize: "1.05rem", fontWeight: 600, lineHeight: 1.4, margin: 0 }}>{item.title}</h3>
          
          {item.tags?.length > 0 && (
            <div style={{ display: "flex", gap: "6px", marginTop: "12px", flexWrap: "wrap" }}>
              {item.tags.map((t, i) => (
                <span key={i} style={{ background: "#0f172a", border: "1px solid #334155", color: "#94a3b8", fontSize: "0.6rem", padding: "3px 8px", borderRadius: "4px", fontWeight: 500 }}>{t}</span>
              ))}
            </div>
          )}
        </div>
        <div style={{ color: "#64748b", fontSize: "0.8rem", marginLeft: "12px", flexShrink: 0, marginTop: "2px", transition: "transform 0.2s", transform: open ? "rotate(180deg)" : "rotate(0deg)", width: "24px", height: "24px", display: "flex", alignItems: "center", justifyContent: "center", background: "#0f172a", borderRadius: "50%" }}>
          ▼
        </div>
      </div>

      {open && (
        <div style={{ marginTop: "16px", borderTop: "1px solid #334155", paddingTop: "16px", display: "flex", flexDirection: "column", gap: "12px" }}>
          {item.summary && (
            <div>
              <p style={{ color: "#cbd5e1", fontSize: "0.85rem", lineHeight: 1.6, margin: 0 }}>{item.summary}</p>
            </div>
          )}
          <a
            href={item.link} target="_blank" rel="noopener noreferrer"
            onClick={e => e.stopPropagation()}
            style={{ display: "inline-flex", alignItems: "center", gap: "6px", color: "#38bdf8", fontSize: "0.75rem", fontWeight: 600, textDecoration: "none", background: "#0c4a6e", padding: "8px 16px", borderRadius: "6px", width: "fit-content", transition: "background 0.2s" }}
            onMouseEnter={e => e.currentTarget.style.background = "#0284c7"}
            onMouseLeave={e => e.currentTarget.style.background = "#0c4a6e"}
          >
            Abrir Fuente Original ↗
          </a>
        </div>
      )}
    </div>
  );
}

// ─── MAPA DE AMENAZAS (REACT-SIMPLE-MAPS) ─────────────────────────────────────
const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

function GlobalThreatMap({ data }) {
  const [tooltip, setTooltip] = useState("");
  const [position, setPosition] = useState({ coordinates: [0, 20], zoom: 1 });

  const handleZoomIn = () => {
    if (position.zoom >= 4) return;
    setPosition((pos) => ({ ...pos, zoom: pos.zoom * 1.5 }));
  };

  const handleZoomOut = () => {
    if (position.zoom <= 1) {
      setPosition({ coordinates: [0, 20], zoom: 1 });
      return;
    }
    setPosition((pos) => ({ ...pos, zoom: pos.zoom / 1.5 }));
  };

  const handleMoveEnd = (newPosition) => {
    setPosition(newPosition);
  };

  const markers = useMemo(() => {
    // Coordenadas reales de capitales/ciudades principales [lon, lat]
    const COUNTRY_COORDS = {
      // Latinoamérica
      'ecuador':     [-78.52, -0.22],
      'quito':       [-78.52, -0.22],
      'guayaquil':   [-79.90, -2.19],
      'colombia':    [-74.07, 4.71],
      'bogotá':      [-74.07, 4.71],
      'bogota':      [-74.07, 4.71],
      'mexico':      [-99.13, 19.43],
      'méxico':      [-99.13, 19.43],
      'brasil':      [-47.93, -15.78],
      'brazil':      [-47.93, -15.78],
      'peru':        [-77.04, -12.05],
      'perú':        [-77.04, -12.05],
      'lima':        [-77.04, -12.05],
      'chile':       [-70.65, -33.45],
      'santiago':    [-70.65, -33.45],
      'argentina':   [-58.38, -34.60],
      'buenos aires':[-58.38, -34.60],
      'venezuela':   [-66.90, 10.49],
      'caracas':     [-66.90, 10.49],
      'panamá':      [-79.52, 8.98],
      'panama':      [-79.52, 8.98],
      'costa rica':  [-84.09, 9.93],
      'uruguay':     [-56.16, -34.90],
      'paraguay':    [-57.63, -25.28],
      'bolivia':     [-68.12, -16.50],
      'guatemala':   [-90.53, 14.63],
      'honduras':    [-87.22, 14.07],
      'el salvador': [-89.19, 13.69],
      'nicaragua':   [-86.25, 12.11],
      'cuba':        [-82.37, 23.11],
      'dominicana':  [-69.93, 18.49],
      // Norteamérica
      'estados unidos': [-77.04, 38.91],
      'united states':  [-77.04, 38.91],
      'usa':            [-77.04, 38.91],
      'washington':     [-77.04, 38.91],
      'new york':       [-74.01, 40.71],
      'california':     [-119.42, 36.78],
      'texas':          [-97.74, 30.27],
      'canada':         [-75.70, 45.42],
      'canadá':         [-75.70, 45.42],
      // Europa
      'españa':         [-3.70, 40.42],
      'spain':          [-3.70, 40.42],
      'madrid':         [-3.70, 40.42],
      'reino unido':    [-0.13, 51.51],
      'united kingdom': [-0.13, 51.51],
      'london':         [-0.13, 51.51],
      'londres':        [-0.13, 51.51],
      'francia':        [2.35, 48.86],
      'france':         [2.35, 48.86],
      'paris':          [2.35, 48.86],
      'alemania':       [13.41, 52.52],
      'germany':        [13.41, 52.52],
      'berlin':         [13.41, 52.52],
      'italia':         [12.50, 41.90],
      'italy':          [12.50, 41.90],
      'roma':           [12.50, 41.90],
      'holanda':        [4.90, 52.37],
      'netherlands':    [4.90, 52.37],
      'suiza':          [7.45, 46.95],
      'switzerland':    [7.45, 46.95],
      'portugal':       [-9.14, 38.74],
      'ucrania':        [30.52, 50.45],
      'ukraine':        [30.52, 50.45],
      'poland':         [21.01, 52.23],
      'polonia':        [21.01, 52.23],
      // Asia
      'china':          [116.41, 39.90],
      'beijing':        [116.41, 39.90],
      'japan':          [139.69, 35.69],
      'japón':          [139.69, 35.69],
      'tokyo':          [139.69, 35.69],
      'corea del norte':  [125.75, 39.02],
      'north korea':    [125.75, 39.02],
      'corea del sur':  [126.98, 37.57],
      'south korea':    [126.98, 37.57],
      'india':          [77.21, 28.61],
      'iran':           [51.39, 35.69],
      'irán':           [51.39, 35.69],
      'israel':         [35.22, 31.77],
      'taiwan':         [121.57, 25.03],
      'singapur':       [103.85, 1.35],
      'singapore':      [103.85, 1.35],
      // Rusia
      'rusia':          [37.62, 55.76],
      'russia':         [37.62, 55.76],
      'moscow':         [37.62, 55.76],
      'moscú':          [37.62, 55.76],
      // África / Oceanía
      'australia':      [149.13, -35.28],
      'sudáfrica':      [28.05, -25.75],
      'south africa':   [28.05, -25.75],
      'nigeria':        [3.39, 6.52],
    };

    // Coordenadas regionales por defecto (centros de masa terrestres, no oceánicos)
    const REGION_DEFAULTS = {
      'Ecuador':        [-78.52, -0.22],
      'Latinoamérica':  [-65.00, -10.00],
      'Global':         [10.00, 48.00],
    };

    // Centros de masa terrestres para distribución de "Global" sin país detectado
    const GLOBAL_LAND_CENTERS = [
      [-77.04, 38.91],   // Washington DC, USA
      [-3.70, 40.42],    // Madrid, España
      [13.41, 52.52],    // Berlin, Alemania
      [37.62, 55.76],    // Moscú, Rusia
      [116.41, 39.90],   // Beijing, China
      [139.69, 35.69],   // Tokyo, Japón
      [77.21, 28.61],    // Delhi, India
      [149.13, -35.28],  // Canberra, Australia
      [28.05, -25.75],   // Pretoria, Sudáfrica
      [-0.13, 51.51],    // Londres, UK
    ];

    return data.slice(0, 80).map((d, idx) => {
      const text = `${d.title || ''} ${d.summary || ''} ${(d.tags || []).join(' ')}`.toLowerCase();
      let coords = null;

      // 1. Buscar país específico mencionado en el texto
      for (const [keyword, lonlat] of Object.entries(COUNTRY_COORDS)) {
        if (text.includes(keyword)) {
          coords = [...lonlat];
          break;
        }
      }

      // 2. Si no se encontró país, usar lógica regional
      if (!coords) {
        if (d.region === 'Ecuador') {
          coords = [...REGION_DEFAULTS['Ecuador']];
        } else if (d.region === 'Latinoamérica') {
          // Distribuir por LATAM de forma realista
          const latamCities = [
            [-74.07, 4.71],   // Bogotá
            [-99.13, 19.43],  // CDMX
            [-47.93, -15.78], // Brasilia
            [-77.04, -12.05], // Lima
            [-70.65, -33.45], // Santiago
            [-58.38, -34.60], // Buenos Aires
            [-66.90, 10.49],  // Caracas
            [-79.52, 8.98],   // Panamá
          ];
          coords = [...latamCities[idx % latamCities.length]];
        } else {
          // Global: distribuir en centros terrestres reales
          coords = [...GLOBAL_LAND_CENTERS[idx % GLOBAL_LAND_CENTERS.length]];
        }
      }

      // 3. Pequeño jitter (±0.5°) para evitar superposición exacta de puntos en la misma ciudad
      coords[0] += (Math.random() - 0.5) * 1.0;
      coords[1] += (Math.random() - 0.5) * 1.0;

      return { ...d, coords };
    });
  }, [data]);

  return (
    <div style={{ background: "#1e293b", borderRadius: "10px", border: "1px solid #334155", display: "flex", flexDirection: "column", height: "400px", position: "relative" }}>
      <div style={{ padding: "12px 20px", borderBottom: "1px solid #334155", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h3 style={{ fontSize: "0.9rem", fontWeight: 600, color: "#f8fafc", margin: 0, display: "flex", alignItems: "center", gap: "8px" }}><MapPin size={16} color="#94a3b8"/> Global Threat Map</h3>
        <div style={{ display: "flex", gap: "8px" }}>
          <button onClick={handleZoomIn} style={{ background: "rgba(56, 189, 248, 0.1)", border: "none", color: "#38bdf8", cursor: "pointer", padding: "4px", borderRadius: "4px", display: "flex" }}>
            <ZoomIn size={16} />
          </button>
          <button onClick={handleZoomOut} style={{ background: "rgba(239, 68, 68, 0.1)", border: "none", color: "#ef4444", cursor: "pointer", padding: "4px", borderRadius: "4px", display: "flex" }}>
            <ZoomOut size={16} />
          </button>
        </div>
      </div>
      <div style={{ flex: 1, position: "relative", overflow: "hidden", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <ComposableMap projection="geoMercator" projectionConfig={{ scale: 130 }} width={800} height={400} style={{ width: "100%", height: "100%" }}>
          <ZoomableGroup zoom={position.zoom} center={position.coordinates} onMoveEnd={handleMoveEnd}>
            <Geographies geography={geoUrl}>
              {({ geographies }) =>
                geographies.map((geo) => (
                  <Geography key={geo.rsmKey} geography={geo} fill="#0f172a" stroke="#334155" strokeWidth={0.5 / position.zoom} style={{ default: { outline: "none" }, hover: { fill: "#1e293b", outline: "none" }, pressed: { outline: "none" } }} />
                ))
              }
            </Geographies>
            {markers.map((m, i) => {
              const clr = SEV_CLR[m.severity]?.b || "#38bdf8";
              return (
                <Marker key={i} coordinates={m.coords} onMouseEnter={() => setTooltip(`${m.title.substring(0, 40)}... (${m.severity})`)} onMouseLeave={() => setTooltip("")}>
                  <circle r={3 / position.zoom} fill={clr} opacity={0.8} />
                  <circle r={8 / position.zoom} fill={clr} opacity={0.3}>
                    <animate attributeName="r" from={3 / position.zoom} to={12 / position.zoom} dur="2s" repeatCount="indefinite" />
                    <animate attributeName="opacity" from="0.6" to="0" dur="2s" repeatCount="indefinite" />
                  </circle>
                </Marker>
              );
            })}
          </ZoomableGroup>
        </ComposableMap>
        {tooltip && (
          <div style={{ position: "absolute", bottom: "16px", left: "16px", background: "rgba(15,23,42,0.95)", padding: "8px 12px", borderRadius: "6px", color: "#f8fafc", fontSize: "0.75rem", border: "1px solid #334155", maxWidth: "250px", pointerEvents: "none", zIndex: 10 }}>
            {tooltip}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── PANEL IoCs (OTX INTEGRATION) ─────────────────────────────────────────────
function TopIndicators() {
  const [indicators, setIndicators] = useState([]);
  const [loading, setLoading] = useState(false);
  const [source, setSource] = useState("TODOS"); // TODOS, Global, LATAM

  const fetchIndicators = async () => {
    setLoading(true);
    try {
      const url = source === "TODOS" ? '/api/otx/indicators?limit=50' : `/api/otx/indicators?source=${source}&limit=50`;
      const res = await fetch(url);
      const d = await res.json();
      if (d.success) setIndicators(d.indicators || []);
    } catch (e) { console.error("Error fetching OTX indicators:", e); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    fetchIndicators();
    const iv = setInterval(fetchIndicators, 60000); // refresh every minute
    return () => clearInterval(iv);
  }, [source]);

  const getIcon = (type) => {
    if (type.includes('IPv4') || type.includes('IPv6')) return '🌐';
    if (type.includes('Domain') || type.includes('Hostname')) return '🔗';
    if (type.includes('FileHash')) return '📄';
    if (type.includes('URL')) return '📍';
    if (type.includes('CVE')) return '🛡️';
    return '🔹';
  };

  return (
    <div style={{ background: "#1e293b", borderRadius: "10px", border: "1px solid #334155", display: "flex", flexDirection: "column", height: "380px", position: "relative", overflow: "hidden" }}>
      <div style={{ padding: "12px 20px", borderBottom: "1px solid #334155", display: "flex", justifyContent: "space-between", alignItems: "center", background: "#0f172a" }}>
        <h3 style={{ fontSize: "0.9rem", fontWeight: 600, color: "#f8fafc", margin: 0, display: "flex", alignItems: "center", gap: "8px" }}>
          <Database size={16} color="#38bdf8"/> AlienVault OTX (Real-time IoCs)
        </h3>
        <div style={{ display: "flex", background: "#1e293b", borderRadius: "6px", padding: "2px" }}>
          {["TODOS", "LATAM", "Global"].map(s => (
            <button key={s} onClick={() => setSource(s)} style={{ background: source === s ? "#334155" : "transparent", border: "none", color: source === s ? "#38bdf8" : "#64748b", padding: "4px 8px", borderRadius: "4px", fontSize: "0.65rem", fontWeight: 700, cursor: "pointer" }}>{s}</button>
          ))}
        </div>
      </div>
      <div style={{ padding: "0", flex: 1, overflowY: "auto" }}>
        {loading && indicators.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#64748b" }}>
            <RefreshCw size={24} className="spin" style={{ marginBottom: "12px" }} />
            <p style={{ fontSize: "0.8rem" }}>Sincronizando con AlienVault OTX...</p>
          </div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead style={{ position: "sticky", top: 0, background: "#1e293b", zIndex: 5 }}>
              <tr>
                <th style={{ textAlign: "left", fontSize: "0.65rem", color: "#64748b", padding: "12px 16px", borderBottom: "1px solid #334155" }}>TYPE / INDICATOR</th>
                <th style={{ textAlign: "right", fontSize: "0.65rem", color: "#64748b", padding: "12px 16px", borderBottom: "1px solid #334155" }}>PULSE / SOURCE</th>
              </tr>
            </thead>
            <tbody>
              {indicators.map((ind, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #33415533", transition: "background 0.2s" }} onMouseEnter={e => e.currentTarget.style.background = "#0f172a"} onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                  <td style={{ padding: "10px 16px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span title={ind.type}>{getIcon(ind.type)}</span>
                      <div style={{ display: "flex", flexDirection: "column" }}>
                        <span style={{ fontSize: "0.8rem", color: "#f8fafc", fontWeight: 600, fontFamily: "monospace", wordBreak: "break-all" }}>{ind.indicator}</span>
                        <span style={{ fontSize: "0.65rem", color: "#64748b" }}>{ind.type}</span>
                      </div>
                    </div>
                  </td>
                  <td style={{ padding: "10px 16px", textAlign: "right" }}>
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "4px" }}>
                      <span style={{ fontSize: "0.7rem", color: "#38bdf8", maxWidth: "150px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={ind.pulse_name}>{ind.pulse_name}</span>
                      <span style={{ background: ind.source === 'LATAM' ? "#14532d" : "#1e293b", color: ind.source === 'LATAM' ? "#4ade80" : "#94a3b8", padding: "2px 6px", borderRadius: "4px", fontSize: "0.6rem", fontWeight: 700 }}>{ind.source}</span>
                    </div>
                  </td>
                </tr>
              ))}
              {indicators.length === 0 && !loading && (
                <tr>
                  <td colSpan="2" style={{ textAlign: "center", padding: "40px", color: "#64748b", fontSize: "0.8rem" }}>No se encontraron indicadores para este filtro.</td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
      <div style={{ padding: "8px 16px", borderTop: "1px solid #334155", background: "#0f172a", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: "0.6rem", color: "#475569" }}>DATA VIA OTX API v1</span>
        <button onClick={fetchIndicators} style={{ background: "none", border: "none", color: "#38bdf8", fontSize: "0.65rem", cursor: "pointer", display: "flex", alignItems: "center", gap: "4px" }}>
          <RefreshCw size={10} className={loading ? "spin" : ""} /> Force Refresh
        </button>
      </div>
    </div>
  );
}


function LatamActors({ localData = [] }) {
  const [actors, setActors] = useState([]);
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState("OTX"); // OTX | Local

  const fetchActors = async () => {
    if (mode === "Local") {
      // Formatear data local para que coincida con la estructura
      const formatted = localData.map(([name, count]) => ({ name, count }));
      setActors(formatted);
      return;
    }
    
    setLoading(true);
    try {
      const res = await fetch('/api/otx/adversaries');
      const d = await res.json();
      if (d.success) setActors(d.adversaries || []);
    } catch (e) { console.error("Error fetching OTX adversaries:", e); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    fetchActors();
  }, [mode, localData]);

  return (
    <div style={{ background: "#1e293b", borderRadius: "10px", border: "1px solid #334155", display: "flex", flexDirection: "column", flex: 1, minHeight: "220px" }}>
      <div style={{ padding: "12px 20px", borderBottom: "1px solid #334155", display: "flex", justifyContent: "space-between", alignItems: "center", background: "#0f172a" }}>
        <h3 style={{ fontSize: "0.9rem", fontWeight: 600, color: "#f8fafc", margin: 0, display: "flex", alignItems: "center", gap: "8px" }}>
          <Shield size={16} color="#ef4444"/> Threat Actors
        </h3>
        <div style={{ display: "flex", background: "#1e293b", borderRadius: "6px", padding: "2px" }}>
          {["OTX", "Local"].map(m => (
            <button key={m} onClick={() => setMode(m)} style={{ background: mode === m ? "#334155" : "transparent", border: "none", color: mode === m ? "#38bdf8" : "#64748b", padding: "4px 10px", borderRadius: "4px", fontSize: "0.65rem", fontWeight: 700, cursor: "pointer" }}>{m}</button>
          ))}
        </div>
      </div>
      <div style={{ padding: "16px", flex: 1 }}>
        {actors.length > 0 ? (
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {actors.slice(0, 10).map((actor, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: i === 0 ? "#ef4444" : "#f97316", boxShadow: i === 0 ? "0 0 8px #ef4444" : "none" }} />
                  <span style={{ fontSize: "0.85rem", color: "#f8fafc", fontWeight: 600 }}>{actor.name}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span style={{ fontSize: "0.65rem", color: "#64748b", fontWeight: 500 }}>{actor.count} {mode === "OTX" ? "PULSES" : "EVENTOS"}</span>
                  <span style={{ background: "rgba(239, 68, 68, 0.1)", color: "#f87171", fontSize: "0.6rem", padding: "2px 6px", borderRadius: "4px", fontWeight: 700, border: "1px solid rgba(239, 68, 68, 0.2)" }}>{mode === "OTX" ? "COMMUNITY" : "DETECTION"}</span>
                </div>
              </div>
            ))}
          </div>
        ) : loading ? (
          <div style={{ textAlign: "center", paddingTop: "40px", color: "#64748b", fontSize: "0.8rem" }}>Cargando actores...</div>
        ) : (
          <div style={{ color: "#64748b", fontSize: "0.75rem", textAlign: "center", paddingTop: "40px" }}>No se detectaron actores {mode === "Local" ? "locales" : ""} específicos.</div>
        )}
      </div>
      <div style={{ padding: "8px 20px", borderTop: "1px solid #334155", textAlign: "right" }}>
        <span style={{ fontSize: "0.6rem", color: "#475569" }}>SOURCE: {mode === "OTX" ? "ALIENVAULT COMMUNITY" : "CONSOLE THREATS (LATAM/EC)"}</span>
      </div>
    </div>
  );
}

function IndustrySectors() {
  const [industries, setIndustries] = useState([]);
  const [loading, setLoading] = useState(false);
  const [source, setSource] = useState("TODOS");

  const fetchIndustries = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/otx/industries?source=${source}`);
      const d = await res.json();
      if (d.success) setIndustries(d.industries || []);
    } catch (e) { console.error("Error fetching OTX industries:", e); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    fetchIndustries();
  }, [source]);

  const maxVal = industries.length > 0 ? industries[0].count : 1;

  return (
    <div style={{ background: "#1e293b", borderRadius: "10px", border: "1px solid #334155", display: "flex", flexDirection: "column", flex: 1, minHeight: "220px" }}>
      <div style={{ padding: "12px 20px", borderBottom: "1px solid #334155", display: "flex", justifyContent: "space-between", alignItems: "center", background: "#0f172a" }}>
        <h3 style={{ fontSize: "0.9rem", fontWeight: 600, color: "#f8fafc", margin: 0, display: "flex", alignItems: "center", gap: "8px" }}>
          <Activity size={16} color="#38bdf8"/> Industries (Targeted)
        </h3>
        <div style={{ display: "flex", background: "#1e293b", borderRadius: "6px", padding: "2px" }}>
          {["TODOS", "LATAM", "Global"].map(s => (
            <button key={s} onClick={() => setSource(s)} style={{ background: source === s ? "#334155" : "transparent", border: "none", color: source === s ? "#38bdf8" : "#64748b", padding: "4px 8px", borderRadius: "4px", fontSize: "0.6rem", fontWeight: 700, cursor: "pointer" }}>{s}</button>
          ))}
        </div>
      </div>
      <div style={{ padding: "16px", flex: 1 }}>
        {industries.length > 0 ? (
          <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
            {industries.slice(0, 5).map((ind, i) => (
              <div key={i}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
                  <span style={{ fontSize: "0.75rem", color: "#cbd5e1", fontWeight: 600 }}>{ind.name}</span>
                  <span style={{ fontSize: "0.7rem", color: "#94a3b8" }}>{ind.count} pulses</span>
                </div>
                <div style={{ height: "6px", background: "#0f172a", borderRadius: "3px", overflow: "hidden" }}>
                  <div style={{ height: "100%", background: "linear-gradient(90deg, #38bdf8, #818cf8)", width: `${(ind.count / maxVal) * 100}%`, borderRadius: "3px", transition: "width 0.5s ease" }} />
                </div>
              </div>
            ))}
          </div>
        ) : loading ? (
          <div style={{ textAlign: "center", paddingTop: "40px", color: "#64748b", fontSize: "0.8rem" }}>Cargando sectores...</div>
        ) : (
          <div style={{ color: "#64748b", fontSize: "0.75rem", textAlign: "center", paddingTop: "40px" }}>No se encontraron sectores específicos en este filtro.</div>
        )}
      </div>
      <div style={{ padding: "8px 20px", borderTop: "1px solid #334155", textAlign: "right" }}>
        <span style={{ fontSize: "0.6rem", color: "#475569" }}>DATA REFRESHED VIA OTX PULSES</span>
      </div>
    </div>
  );
}


function AssetsView() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [newDomain, setNewDomain] = useState("");
  const [scanningId, setScanningId] = useState(null);
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [reconResults, setReconResults] = useState([]);
  const [reconLoading, setReconLoading] = useState(false);
  const [fbResults, setFbResults] = useState([]);
  const [fbLoading, setFbLoading] = useState(false);
  const [showOffline, setShowOffline] = useState(false);
  const [fbScraper, setFbScraper] = useState({ results: [], cachedAt: null, loading: false });
  const [assetTab, setAssetTab] = useState("surface");
  const [filterActiveOnly, setFilterActiveOnly] = useState(false);

  const fetchAssets = async () => {
    try {
      const res = await fetch('/api/assets');
      const data = await res.json();
      setAssets(data);
    } catch (e) { console.error(e); }
  };

  useEffect(() => { fetchAssets(); }, []);

  const addAsset = async () => {
    if (!newDomain) return;
    setLoading(true);
    try {
      const res = await fetch('/api/assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: newDomain })
      });
      if (res.ok) { setNewDomain(""); fetchAssets(); }
      else { const d = await res.json(); alert(d.error); }
    } catch (e) { alert(e.message); }
    finally { setLoading(false); }
  };

  const deleteAsset = async (e, id) => {
    console.log("Intentando borrar asset:", id);
    if (e) e.stopPropagation();
    if (!window.confirm("¿Estás seguro de que deseas eliminar este dominio del monitoreo?")) return;
    
    try {
      const res = await fetch(`/api/assets/${id}`, { method: 'DELETE' });
      const data = await res.json();
      console.log("Respuesta de borrado:", data);
      fetchAssets();
    } catch (err) {
      console.error("Error al borrar:", err);
      alert("Error al eliminar: " + err.message);
    }
  };

  const rescanAsset = async (e, id) => {
    e.stopPropagation();
    setScanningId(id);
    await fetch(`/api/assets/scan/${id}`);
    setScanningId(null);
    fetchAssets();
  };

  const runRecon = async (id) => {
    setReconLoading(true);
    setReconResults([]);
    try {
      const res = await fetch(`/api/assets/recon/${id}`, { method: 'POST' });
      const data = await res.json();
      if (data.results) setReconResults(data.results);
      else alert(data.error || "No se encontraron resultados");
    } catch (e) { alert("Error de conexión: " + e.message); }
    finally { setReconLoading(false); }
  };

  const runFbRecon = async (id) => {
    setFbLoading(true);
    setFbResults([]);
    try {
      const res = await fetch(`/api/assets/facebook-recon/${id}`, { method: 'POST' });
      const data = await res.json();
      if (data.results) setFbResults(data.results);
      else alert(data.error || "No se encontraron resultados en Facebook");
    } catch (e) { alert("Error de conexión: " + e.message); }
    finally { setFbLoading(false); }
  };

  // Cargar caché del Facebook Scraper (sin consumir API)
  const loadFbScraper = async (id) => {
    setFbScraper(prev => ({ ...prev, loading: true }));
    try {
      const res = await fetch(`/api/assets/fb-scraper/${id}`);
      const data = await res.json();
      setFbScraper({ results: data.results || [], cachedAt: data.cachedAt || null, loading: false });
    } catch (e) { setFbScraper({ results: [], cachedAt: null, loading: false }); }
  };

  // Ejecutar nuevo escaneo real con Apify (consume API)
  const runFbScraper = async (id) => {
    setFbScraper(prev => ({ ...prev, loading: true }));
    try {
      const res = await fetch(`/api/assets/fb-scraper/${id}`, { method: 'POST' });
      const data = await res.json();
      if (data.results) setFbScraper({ results: data.results, cachedAt: data.cachedAt, loading: false });
      else { alert(data.error || 'Sin resultados'); setFbScraper(prev => ({ ...prev, loading: false })); }
    } catch (e) { alert('Error: ' + e.message); setFbScraper(prev => ({ ...prev, loading: false })); }
  };

  const closeAssetModal = () => {
    setSelectedAsset(null);
    setReconResults([]);
    setFbResults([]);
    setFbScraper({ results: [], cachedAt: null, loading: false });
  };

  return (
    <div style={{ animation: "fu 0.3s ease both", display: "flex", flexDirection: "column", gap: "24px" }}>
       <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <h2 style={{ fontSize: "1.5rem", fontWeight: 700, color: "#f8fafc" }}>Asset Management</h2>
            <p style={{ fontSize: "0.85rem", color: "#64748b" }}>Monitoreo de dominios, salud DNS y detección de suplantación.</p>
          </div>
          <div style={{ display: "flex", gap: "12px" }}>
            <input 
              value={newDomain}
              onChange={e => setNewDomain(e.target.value)}
              placeholder="ej. mi-banco.com" 
              style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "8px", padding: "8px 16px", color: "#f8fafc", width: "250px" }}
            />
            <button 
              onClick={addAsset}
              disabled={loading}
              style={{ background: "#38bdf8", color: "#0f172a", border: "none", borderRadius: "8px", padding: "8px 20px", fontWeight: 600, cursor: "pointer", display: "flex", alignItems: "center", gap: "8px" }}
            >
              {loading ? <RefreshCw size={16} className="spin" /> : <Plus size={18} />} Añadir Dominio
            </button>
          </div>
       </div>

       <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))", gap: "24px" }}>
          {assets.map(asset => (
            <div 
              key={asset.id} 
              onClick={() => { setSelectedAsset(asset); loadFbScraper(asset.id); }}
              style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "12px", padding: "24px", cursor: "pointer", transition: "all 0.2s" }}
              onMouseEnter={(e) => e.currentTarget.style.borderColor = "#38bdf8"}
              onMouseLeave={(e) => e.currentTarget.style.borderColor = "#334155"}
            >
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "20px" }}>
                <div>
                  <h3 style={{ fontSize: "1.1rem", fontWeight: 700, color: "#f8fafc", letterSpacing: "0.5px" }}>{asset.domain}</h3>
                  <span style={{ fontSize: "0.65rem", color: "#64748b", fontFamily: "monospace" }}>ID: {asset.id}</span>
                </div>
                <div style={{ display: "flex", gap: "12px" }} onClick={(e) => e.stopPropagation()}>
                   <button 
                     onClick={(e) => rescanAsset(e, asset.id)} 
                     style={{ background: "rgba(148, 163, 184, 0.1)", border: "none", color: "#94a3b8", cursor: "pointer", padding: "8px", borderRadius: "8px", display: "flex", alignItems: "center", justifyContent: "center", transition: "all 0.2s" }} 
                     onMouseEnter={(e) => e.currentTarget.style.background = "rgba(148, 163, 184, 0.2)"}
                     onMouseLeave={(e) => e.currentTarget.style.background = "rgba(148, 163, 184, 0.1)"}
                     title="Re-escanear"
                   >
                     <RefreshCw size={18} className={scanningId === asset.id ? "spin" : ""} style={{ pointerEvents: "none" }} />
                   </button>
                   <button 
                     onClick={(e) => deleteAsset(e, asset.id)} 
                     style={{ background: "rgba(239, 68, 68, 0.1)", border: "none", color: "#ef4444", cursor: "pointer", padding: "8px", borderRadius: "8px", display: "flex", alignItems: "center", justifyContent: "center", transition: "all 0.2s" }} 
                     onMouseEnter={(e) => e.currentTarget.style.background = "rgba(239, 68, 68, 0.2)"}
                     onMouseLeave={(e) => e.currentTarget.style.background = "rgba(239, 68, 68, 0.1)"}
                     title="Eliminar"
                   >
                     <Trash2 size={18} style={{ pointerEvents: "none" }} />
                   </button>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "20px" }}>
                <div style={{ background: "#0f172a", padding: "12px", borderRadius: "8px", border: "1px solid #334155" }}>
                  <div style={{ fontSize: "0.6rem", color: "#64748b", fontWeight: 700, marginBottom: "6px", letterSpacing: "0.05em" }}>SPF RECORD</div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    {asset.spf.status === 'valid' ? <CheckCircle size={14} color="#22c55e"/> : <XCircle size={14} color="#ef4444"/>}
                    <span style={{ fontSize: "0.75rem", fontWeight: 600, color: asset.spf.status === 'valid' ? "#f8fafc" : "#ef4444" }}>{asset.spf.status.toUpperCase()}</span>
                  </div>
                </div>
                <div style={{ background: "#0f172a", padding: "12px", borderRadius: "8px", border: "1px solid #334155" }}>
                  <div style={{ fontSize: "0.6rem", color: "#64748b", fontWeight: 700, marginBottom: "6px", letterSpacing: "0.05em" }}>DMARC STATUS</div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    {asset.dmarc.status === 'valid' ? <ShieldCheck size={14} color="#22c55e"/> : <AlertTriangle size={14} color="#f59e0b"/>}
                    <span style={{ fontSize: "0.75rem", fontWeight: 600, color: asset.dmarc.status === 'valid' ? "#f8fafc" : "#f59e0b" }}>{asset.dmarc.status.toUpperCase()}</span>
                  </div>
                </div>
              </div>

              <div style={{ marginBottom: "20px" }}>
                 <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                   <span style={{ fontSize: "0.75rem", color: "#94a3b8", fontWeight: 500 }}>Risk Score</span>
                   <span style={{ fontSize: "0.75rem", fontWeight: 700, color: asset.riskScore > 50 ? "#ef4444" : "#22c55e" }}>{asset.riskScore}%</span>
                 </div>
                 <div style={{ height: "6px", background: "#0f172a", borderRadius: "3px", overflow: "hidden" }}>
                   <div style={{ height: "100%", background: asset.riskScore > 50 ? "linear-gradient(90deg, #ef4444, #f87171)" : "linear-gradient(90deg, #22c55e, #4ade80)", width: `${asset.riskScore}%`, borderRadius: "3px" }} />
                 </div>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: "12px", padding: "12px", background: "rgba(15,23,42,0.3)", borderRadius: "8px" }}>
                 <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.75rem" }}>
                   <span style={{ color: "#64748b" }}>Subdominios activos:</span>
                   <span style={{ color: "#f8fafc", fontWeight: 600 }}>{asset.subdomains.filter(s => s.status === 'online' || typeof s === 'string').length}</span>
                 </div>
                 <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.75rem" }}>
                   <span style={{ color: "#64748b" }}>Suplantaciones (Squatting):</span>
                   <span style={{ color: asset.impersonations.length > 0 ? "#ef4444" : "#22c55e", fontWeight: 600 }}>{asset.impersonations.length} detectadas</span>
                 </div>
              </div>
            </div>
          ))}
          {assets.length === 0 && !loading && (
            <div style={{ gridColumn: "1/-1", textAlign: "center", padding: "60px", background: "#0f172a", borderRadius: "12px", border: "2px dashed #334155" }}>
              <div style={{ color: "#334155", marginBottom: "16px" }}><Database size={48} /></div>
              <h3 style={{ color: "#94a3b8", fontSize: "1.1rem" }}>No hay dominios registrados</h3>
              <p style={{ color: "#475569", fontSize: "0.85rem" }}>Añade tu primer dominio institucional en la parte superior.</p>
            </div>
          )}
       </div>

       {selectedAsset && (
         <div style={{ position: "fixed", inset: 0, background: "rgba(2,6,23,0.85)", backdropFilter: "blur(8px)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, padding: "20px" }}>
           <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "16px", width: "100%", maxWidth: "800px", maxHeight: "90vh", overflow: "auto", display: "flex", flexDirection: "column", boxShadow: "0 25px 50px -12px rgba(0,0,0,0.5)" }}>
              <div style={{ padding: "24px", borderBottom: "1px solid #1e293b", display: "flex", justifyContent: "space-between", alignItems: "center", background: "#1e293b" }}>
                <div>
                  <h2 style={{ fontSize: "1.5rem", fontWeight: 700, color: "#f8fafc" }}>{selectedAsset.domain}</h2>
                  <p style={{ fontSize: "0.8rem", color: "#38bdf8", fontWeight: 500 }}>Technical Surface Analysis Report</p>
                </div>
                <button onClick={closeAssetModal} style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer" }}><XCircle size={24} /></button>
              </div>

              {/* TAB NAVIGATION */}
              <div style={{ display: "flex", background: "#1e293b", borderBottom: "1px solid #334155" }}>
                 {[
                   { id: 'surface', label: 'Technical Surface', icon: <Database size={14}/> },
                   { id: 'subdomains', label: 'Subdomains', icon: <List size={14}/> },
                   { id: 'brand', label: '🛡️ Brand Protection', icon: <Globe size={14}/> }
                 ].map(tab => (
                   <button
                     key={tab.id}
                     onClick={() => setAssetTab(tab.id)}
                     style={{
                       flex: 1, padding: "14px", border: "none",
                       background: assetTab === tab.id ? "#0f172a" : "transparent",
                       color: assetTab === tab.id ? "#38bdf8" : "#64748b",
                       fontWeight: 700, fontSize: "0.75rem", cursor: "pointer",
                       borderBottom: assetTab === tab.id ? "2px solid #38bdf8" : "none",
                       display: "flex", alignItems: "center", justifyContent: "center", gap: "8px",
                       transition: "all 0.2s"
                     }}
                   >
                     {tab.icon} {tab.label}
                   </button>
                 ))}
              </div>

              <div style={{ padding: "32px", display: "flex", flexDirection: "column", gap: "32px" }}>
                
                {/* TAB 1: TECHNICAL SURFACE */}
                {assetTab === 'surface' && (
                  <div style={{ display: "flex", flexDirection: "column", gap: "32px", animation: "fu 0.3s ease" }}>
                     <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px" }}>
                       <div style={{ background: "#1e293b", padding: "20px", borderRadius: "12px", border: "1px solid #334155" }}>
                         <h4 style={{ fontSize: "0.7rem", color: "#64748b", marginBottom: "12px", fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.05em" }}>Public SPF Record</h4>
                         <div style={{ background: "#0f172a", padding: "12px", borderRadius: "8px", border: "1px solid #1e293b" }}>
                           <code style={{ fontSize: "0.8rem", color: selectedAsset.spf.record ? "#38bdf8" : "#ef4444", wordBreak: "break-all", fontFamily: "monospace" }}>
                             {selectedAsset.spf.record || "No record found. Mail identity is unprotected."}
                           </code>
                         </div>
                       </div>
                       <div style={{ background: "#1e293b", padding: "20px", borderRadius: "12px", border: "1px solid #334155" }}>
                         <h4 style={{ fontSize: "0.7rem", color: "#64748b", marginBottom: "12px", fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.05em" }}>Public DMARC Record</h4>
                         <div style={{ background: "#0f172a", padding: "12px", borderRadius: "8px", border: "1px solid #1e293b" }}>
                           <code style={{ fontSize: "0.8rem", color: selectedAsset.dmarc.record ? "#38bdf8" : "#f59e0b", wordBreak: "break-all", fontFamily: "monospace" }}>
                             {selectedAsset.dmarc.record || "No record found. Anti-spoofing policy is missing."}
                           </code>
                         </div>
                       </div>
                     </div>
                  </div>
                )}

                {/* TAB 2: SUBDOMAINS */}
                {assetTab === 'subdomains' && (
                  <div style={{ animation: "fu 0.3s ease" }}>
                     <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                       <h4 style={{ fontSize: "0.9rem", color: "#f8fafc", display: "flex", alignItems: "center", gap: "10px", fontWeight: 600, margin: 0 }}>
                         <List size={18} color="#38bdf8" /> Subdomains Discovered ({selectedAsset.subdomains.filter(s => s.status === 'online').length}/{selectedAsset.subdomains.length})
                       </h4>
                       <button 
                         onClick={() => setShowOffline(!showOffline)}
                         style={{ background: showOffline ? "#38bdf8" : "rgba(148, 163, 184, 0.1)", color: showOffline ? "#0f172a" : "#94a3b8", border: "none", borderRadius: "6px", padding: "4px 12px", fontSize: "0.7rem", fontWeight: 700, cursor: "pointer", transition: "all 0.2s" }}
                       >
                         {showOffline ? "Ocultar Inactivos" : "Mostrar Inactivos"}
                       </button>
                     </div>
                     <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: "12px", maxHeight: "400px", overflow: "auto", background: "#020617", padding: "20px", borderRadius: "12px", border: "1px solid #1e293b" }}>
                       {selectedAsset.subdomains.map((sub, idx) => {
                         const subName = typeof sub === 'string' ? sub : sub.name;
                         const isOnline = typeof sub === 'string' || sub.status === 'online';
                         if (!showOffline && !isOnline) return null;
                         return (
                           <div key={idx} style={{ padding: "8px 12px", background: "#0f172a", borderRadius: "6px", fontSize: "0.75rem", color: isOnline ? "#f8fafc" : "#475569", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                             <span>{subName}</span>
                             {isOnline && <div style={{ width: "6px", height: "6px", background: "#22c55e", borderRadius: "50%" }} />}
                           </div>
                         );
                       })}
                     </div>
                  </div>
                )}

                {/* TAB 3: BRAND PROTECTION */}
                {assetTab === 'brand' && (
                  <div style={{ animation: "fu 0.3s ease", display: "flex", flexDirection: "column", gap: "32px" }}>
                     <div style={{ background: "#1e293b", padding: "24px", borderRadius: "16px", border: "1px solid #334155" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                            <h4 style={{ fontSize: "1rem", color: "#f8fafc", fontWeight: 700, margin: 0 }}>🛡️ Brand Monitor Results</h4>
                            {selectedAsset.fbScraperCache?.newFindings > 0 && (
                              <span style={{ background: "#ef4444", color: "#fff", fontSize: "0.65rem", fontWeight: 800, padding: "2px 8px", borderRadius: "12px", animation: "pulse 2s infinite" }}>
                                {selectedAsset.fbScraperCache.newFindings} NUEVOS
                              </span>
                            )}
                          </div>
                          
                          {/* Filtro de Activos */}
                          <button 
                            onClick={() => setFilterActiveOnly(!filterActiveOnly)}
                            style={{
                              padding: "4px 10px",
                              borderRadius: "6px",
                              fontSize: "0.7rem",
                              background: filterActiveOnly ? "#3b82f6" : "rgba(255,255,255,0.05)",
                              color: filterActiveOnly ? "#fff" : "#94a3b8",
                              border: `1px solid ${filterActiveOnly ? "#3b82f6" : "#334155"}`,
                              cursor: "pointer",
                              fontWeight: 600,
                              transition: "all 0.2s"
                            }}
                          >
                            {filterActiveOnly ? "✓ Solo Activos" : "Filtrar Activos"}
                          </button>
                        </div>
                        <div style={{ background: "#020617", borderRadius: "12px", padding: "20px", minHeight: "100px", maxHeight: "400px", overflow: "auto" }}>
                          {fbScraper.results.filter(r => {
                            if (!filterActiveOnly) return true;
                            // FILTRO ESTRICTO: Solo si está activo, resuelve o tiene un riesgo superior a LOW
                            const isLive = r.status === 'active' || r.isResolving || r.verified;
                            const isHighRisk = r.riskLevel && !['N/A', 'LOW', '0', 0].includes(r.riskLevel);
                            return isLive || isHighRisk;
                          }).length > 0 ? fbScraper.results
                            .filter(r => {
                              if (!filterActiveOnly) return true;
                              const isLive = r.status === 'active' || r.isResolving || r.verified;
                              const isHighRisk = r.riskLevel && !['N/A', 'LOW', '0', 0].includes(r.riskLevel);
                              return isLive || isHighRisk;
                            })
                            .map((res, i) => (
                              <div key={i} style={{ paddingBottom: "12px", borderBottom: "1px solid #1e293b", marginBottom: "12px", position: "relative" }}>
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                                  <a href={res.url} target="_blank" rel="noopener noreferrer" style={{ color: "#38bdf8", fontSize: "0.85rem", textDecoration: "none", fontWeight: 600, maxWidth: "80%" }}>{res.title}</a>
                                  {res.isNew && <span style={{ background: "rgba(239, 68, 68, 0.2)", color: "#ef4444", border: "1px solid #ef4444", fontSize: "0.6rem", fontWeight: 800, padding: "1px 6px", borderRadius: "4px" }}>NEW</span>}
                                </div>
                                <p style={{ fontSize: "0.75rem", color: "#94a3b8", margin: "4px 0" }}>{res.description}</p>
                                <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "6px" }}>
                                   <span style={{ fontSize: "0.6rem", padding: "2px 6px", background: "#1e293b", borderRadius: "4px", color: "#cbd5e1" }}>{res.type}</span>
                                   {(res.status === 'active' || res.isResolving) && <span style={{ fontSize: "0.6rem", padding: "2px 6px", background: "rgba(34, 197, 94, 0.1)", borderRadius: "4px", color: "#22c55e", border: "1px solid rgba(34, 197, 94, 0.2)" }}>ACTIVE</span>}
                                   {res.riskLevel !== 'N/A' && <span style={{ fontSize: "0.6rem", padding: "2px 6px", background: "rgba(245, 158, 11, 0.1)", borderRadius: "4px", color: "#f59e0b" }}>Risk: {res.riskLevel}</span>}
                                </div>
                              </div>
                            )) : <p style={{ textAlign: "center", color: "#475569", fontSize: "0.8rem", padding: "20px" }}>No se encontraron amenazas activas (resolviendo o con riesgo) con el filtro actual.</p>}
                        </div>
                     </div>

                     <div>
                       <h4 style={{ fontSize: "0.9rem", color: "#f8fafc", marginBottom: "16px", display: "flex", alignItems: "center", gap: "10px", fontWeight: 600 }}>
                         <ShieldAlert size={18} color="#ef4444" /> Typosquatting Variants
                       </h4>
                       <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                         {selectedAsset.impersonations.length > 0 ? selectedAsset.impersonations.map(imp => (
                           <div key={imp.domain} style={{ background: "rgba(239, 68, 68, 0.05)", border: "1px solid rgba(239, 68, 68, 0.2)", padding: "16px", borderRadius: "12px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                             <span style={{ fontSize: "0.9rem", color: "#fca5a5", fontWeight: 700 }}>{imp.domain}</span>
                             <span style={{ fontSize: "0.6rem", background: "#ef4444", color: "#fff", padding: "2px 8px", borderRadius: "4px", fontWeight: 800 }}>LIVE ATTEMPT</span>
                           </div>
                         )) : <div style={{ textAlign: "center", color: "#475569", fontSize: "0.8rem", padding: "20px", background: "#0f172a", borderRadius: "12px" }}>No active variants detected.</div>}
                       </div>
                     </div>
                  </div>
                )}
              </div>

              <div style={{ padding: "20px 32px", background: "#1e293b", borderTop: "1px solid #334155", textAlign: "right" }}>
                 <button onClick={closeAssetModal} style={{ background: "#38bdf8", color: "#0f172a", border: "none", borderRadius: "8px", padding: "10px 32px", cursor: "pointer", fontWeight: 700, fontSize: "0.85rem" }}>Close Analysis</button>
              </div>
           </div>
         </div>
       )}
    </div>
  );
}
function AnalysisView() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(false);

  const loadSummary = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/sensors/analysis/summary');
      if (res.ok) {
        const d = await res.json();
        setSummary(d);
      }
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    loadSummary();
    const iv = setInterval(loadSummary, 30000);
    return () => clearInterval(iv);
  }, []);

  if (!summary && loading) return <div style={{ padding: "60px", textAlign: "center", color: "#64748b" }}><RefreshCw size={32} className="spin" /></div>;

  return (
    <div style={{ animation: "fu 0.3s ease both", display: "flex", flexDirection: "column", gap: "24px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h2 style={{ fontSize: "1.5rem", fontWeight: 700, color: "#f8fafc" }}>Security Analysis & Threat Hunting</h2>
          <p style={{ fontSize: "0.85rem", color: "#64748b" }}>Consolidado global de telemetría de riesgo y detecciones confirmadas por el motor EDR.</p>
        </div>
        <button onClick={loadSummary} disabled={loading} style={{ background: "#38bdf8", color: "#0f172a", border: "none", borderRadius: "8px", padding: "8px 20px", fontWeight: 600, cursor: "pointer", display: "flex", alignItems: "center", gap: "8px", fontSize: "0.85rem" }}>
          <RefreshCw size={16} className={loading ? "spin" : ""} /> Refrescar Análisis
        </button>
      </div>

      {/* Summary Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "20px" }}>
        <div style={{ background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.2)", padding: "20px", borderRadius: "12px", textAlign: "center" }}>
          <div style={{ color: "#ef4444", fontSize: "2rem", fontWeight: 800 }}>{summary?.counts?.critical || 0}</div>
          <div style={{ color: "#fca5a5", fontSize: "0.75rem", fontWeight: 700, textTransform: "uppercase", marginTop: "4px" }}>Amenazas Críticas</div>
        </div>
        <div style={{ background: "rgba(249, 115, 22, 0.1)", border: "1px solid rgba(249, 115, 22, 0.2)", padding: "20px", borderRadius: "12px", textAlign: "center" }}>
          <div style={{ color: "#f97316", fontSize: "2rem", fontWeight: 800 }}>{summary?.counts?.high || 0}</div>
          <div style={{ color: "#fdba74", fontSize: "0.75rem", fontWeight: 700, textTransform: "uppercase", marginTop: "4px" }}>Alertas Altas</div>
        </div>
        <div style={{ background: "rgba(251, 191, 36, 0.1)", border: "1px solid rgba(251, 191, 36, 0.2)", padding: "20px", borderRadius: "12px", textAlign: "center" }}>
          <div style={{ color: "#fbbf24", fontSize: "2rem", fontWeight: 800 }}>{summary?.counts?.suspicious || 0}</div>
          <div style={{ color: "#fde68a", fontSize: "0.75rem", fontWeight: 700, textTransform: "uppercase", marginTop: "4px" }}>Eventos Sospechosos</div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px" }}>
        {/* Top Endpoints */}
        <div style={{ background: "#1e293b", borderRadius: "12px", border: "1px solid #334155", padding: "20px" }}>
          <h3 style={{ fontSize: "0.9rem", fontWeight: 600, color: "#f8fafc", marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
            <Server size={18} color="#38bdf8" /> Top Targeted Endpoints
          </h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {summary?.top_endpoints?.length > 0 ? summary.top_endpoints.map((e, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px", background: "#0f172a", borderRadius: "8px" }}>
                <span style={{ fontSize: "0.85rem", color: "#e2e8f0", fontWeight: 600 }}>{e.hostname}</span>
                <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                  <span style={{ fontSize: "0.75rem", color: (e.current_score >= 60 ? "#ef4444" : "#fbbf24") }}>{e.current_score} pts</span>
                  <span style={{ fontSize: "0.6rem", background: (e.status === 'critical' ? "#ef4444" : "#334155"), padding: "2px 6px", borderRadius: "4px", fontWeight: 700 }}>{(e.status || 'LOW').toUpperCase()}</span>
                </div>
              </div>
            )) : <p style={{ color: "#475569", fontSize: "0.8rem", textAlign: "center" }}>No hay equipos con riesgo registrado.</p>}
          </div>
        </div>

        {/* Top Threats */}
        <div style={{ background: "#1e293b", borderRadius: "12px", border: "1px solid #334155", padding: "20px" }}>
          <h3 style={{ fontSize: "0.9rem", fontWeight: 600, color: "#f8fafc", marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
            <ShieldAlert size={18} color="#ef4444" /> Threat Type Distribution
          </h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {summary?.top_threats?.length > 0 ? summary.top_threats.map((t, i) => (
              <div key={i}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                  <span style={{ fontSize: "0.75rem", color: "#cbd5e1" }}>{(t.event_type || 'Unknown').toUpperCase()}</span>
                  <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>{t.count} eventos</span>
                </div>
                <div style={{ height: "4px", background: "#0f172a", borderRadius: "2px", overflow: "hidden" }}>
                  <div style={{ height: "100%", background: "#ef4444", width: `${(t.count / (summary.top_threats[0]?.count || 1)) * 100}%` }} />
                </div>
              </div>
            )) : <p style={{ color: "#475569", fontSize: "0.8rem", textAlign: "center" }}>Sin telemetría de amenazas.</p>}
          </div>
        </div>
      </div>

      {/* Global Detection Feed */}
      <div style={{ background: "#1e293b", borderRadius: "12px", border: "1px solid #334155", overflow: "hidden" }}>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid #334155", background: "#0f172a" }}>
          <h3 style={{ fontSize: "0.9rem", fontWeight: 600, color: "#f8fafc", margin: 0 }}>Global EDR Detection Feed (Confirmed Threats)</h3>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #334155" }}>
                <th style={{ textAlign: "left", padding: "12px 20px", fontSize: "0.7rem", color: "#64748b" }}>TIMESTAMP</th>
                <th style={{ textAlign: "left", padding: "12px 20px", fontSize: "0.7rem", color: "#64748b" }}>ENDPOINT</th>
                <th style={{ textAlign: "left", padding: "12px 20px", fontSize: "0.7rem", color: "#64748b" }}>TYPE</th>
                <th style={{ textAlign: "left", padding: "12px 20px", fontSize: "0.7rem", color: "#64748b" }}>SEVERITY</th>
                <th style={{ textAlign: "left", padding: "12px 20px", fontSize: "0.7rem", color: "#64748b" }}>DETAILS</th>
              </tr>
            </thead>
            <tbody>
              {summary?.recent_detections?.length > 0 ? summary.recent_detections.map((d, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #0f172a", background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)" }}>
                  <td style={{ padding: "12px 20px", fontSize: "0.75rem", color: "#94a3b8" }}>{new Date(d.timestamp).toLocaleString()}</td>
                  <td style={{ padding: "12px 20px", fontSize: "0.8rem", color: "#f8fafc", fontWeight: 600 }}>{d.hostname}</td>
                  <td style={{ padding: "12px 20px", fontSize: "0.7rem", color: "#38bdf8" }}>{d.detection_type}</td>
                  <td style={{ padding: "12px 20px" }}>
                    <span style={{ background: d.severity === 'CRITICAL' ? "#450a0a" : "#431407", color: d.severity === 'CRITICAL' ? "#fca5a5" : "#fdba74", padding: "2px 8px", borderRadius: "4px", fontSize: "0.65rem", fontWeight: 800 }}>{d.severity}</span>
                  </td>
                  <td style={{ padding: "12px 20px", fontSize: "0.75rem", color: "#cbd5e1" }}>{d.details}</td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="5" style={{ textAlign: "center", padding: "30px", color: "#475569", fontSize: "0.8rem" }}>No se han detectado amenazas críticas recientemente.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function EndpointsView({ data, refresh }) {
  const [openMenu, setOpenMenu] = useState(null);
  const [selectedEndpoint, setSelectedEndpoint] = useState(null);
  const [infoTab, setInfoTab] = useState("hardware");
  const [swSearch, setSwSearch] = useState("");
  const [behaviorData, setBehaviorData] = useState(null);

  useEffect(() => {
    let iv;
    if (selectedEndpoint && infoTab === "behavior") {
      loadBehavior(selectedEndpoint.agent_id);
      iv = setInterval(() => loadBehavior(selectedEndpoint.agent_id), 3000);
    }
    return () => clearInterval(iv);
  }, [selectedEndpoint, infoTab]);

  const loadBehavior = async (id) => {
    try {
      const res = await fetch(`/api/sensors/behavior/${id}`);
      if (res.ok) {
        const d = await res.json();
        setBehaviorData(d);
      }
    } catch(e) { console.error("Error cargando comportamiento:", e); }
  };

  const handleDelete = async (id) => {
    if (!window.confirm("¿Seguro que deseas eliminar este endpoint?")) return;
    try {
      const res = await fetch(`/api/sensors/endpoints/${id}`, { method: 'DELETE' });
      if (res.ok) { refresh(); } else { alert("Error eliminando endpoint"); }
    } catch(e) { alert("Error: " + e.message); }
    setOpenMenu(null);
  };

  const handleForce = async (id) => {
    try {
      const res = await fetch(`/api/sensors/force-reconnect/${id}`, { method: 'POST' });
      const d = await res.json();
      alert(d.message);
      refresh();
    } catch(e) { alert("Error: " + e.message); }
    setOpenMenu(null);
  };

  const openDetail = (ep) => {
    setSelectedEndpoint(ep);
    setInfoTab("hardware");
    setSwSearch("");
    setBehaviorData(null);
    loadBehavior(ep.agent_id);
  };

  let hw = null;
  let sw = [];
  try { hw = selectedEndpoint?.hardware_info ? (typeof selectedEndpoint.hardware_info === 'string' ? JSON.parse(selectedEndpoint.hardware_info) : selectedEndpoint.hardware_info) : null; } catch(e) {}
  try { sw = selectedEndpoint?.software_info ? (typeof selectedEndpoint.software_info === 'string' ? JSON.parse(selectedEndpoint.software_info) : selectedEndpoint.software_info) : []; } catch(e) {}
  if (!Array.isArray(sw)) sw = [];
  const filteredSw = sw.filter(s => !swSearch || (s.name || '').toLowerCase().includes(swSearch.toLowerCase()) || (s.publisher || '').toLowerCase().includes(swSearch.toLowerCase()));

  return (
    <div style={{ animation: "fu 0.3s ease both", display: "flex", flexDirection: "column", gap: "24px" }} onClick={() => setOpenMenu(null)}>
       <div>
         <h2 style={{ fontSize: "1.5rem", fontWeight: 700, color: "#f8fafc" }}>Endpoint Management</h2>
         <p style={{ fontSize: "0.85rem", color: "#64748b" }}>Sensores desplegados y estado de conexión en tiempo real. Haz clic en un hostname para ver detalles.</p>
       </div>
       <div style={{ background: "#1e293b", borderRadius: "12px", border: "1px solid #334155", overflow: "visible" }}>
         <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "800px" }}>
           <thead>
             <tr style={{ borderBottom: "1px solid #334155", background: "#0f172a" }}>
               <th style={{ textAlign: "left", padding: "16px 24px", fontSize: "0.75rem", fontWeight: 600, color: "#94a3b8" }}>Hostname</th>
               <th style={{ textAlign: "left", padding: "16px 24px", fontSize: "0.75rem", fontWeight: 600, color: "#94a3b8" }}>IP Address</th>
               <th style={{ textAlign: "center", padding: "16px 24px", fontSize: "0.75rem", fontWeight: 600, color: "#94a3b8" }}>Status</th>
               <th style={{ textAlign: "right", padding: "16px 24px", fontSize: "0.75rem", fontWeight: 600, color: "#94a3b8" }}>Last Seen</th>
               <th style={{ width: "50px" }}></th>
             </tr>
           </thead>
           <tbody>
             {data.map((ep, idx) => {
               const isOnline = ep.status === 'ONLINE';
               return (
                 <tr key={idx} style={{ borderBottom: "1px solid #1e293b", transition: "background 0.2s", cursor: "pointer" }} onMouseEnter={e => e.currentTarget.style.background = "#334155"} onMouseLeave={e => e.currentTarget.style.background = "transparent"} onClick={() => openDetail(ep)}>
                   <td style={{ padding: "16px 24px", fontSize: "0.85rem", color: "#38bdf8", fontWeight: 600, display: "flex", alignItems: "center", gap: "10px" }}>
                     <Server size={16} color={isOnline ? "#22c55e" : "#64748b"} />
                     {ep.hostname}
                   </td>
                   <td style={{ padding: "16px 24px", fontSize: "0.8rem", color: "#94a3b8", fontFamily: "monospace" }}>{ep.ip}</td>
                   <td style={{ padding: "16px 24px", textAlign: "center" }}>
                     <span style={{ background: isOnline ? "rgba(34,197,94,0.1)" : "rgba(100,116,139,0.1)", color: isOnline ? "#22c55e" : "#64748b", padding: "4px 10px", borderRadius: "12px", fontSize: "0.7rem", fontWeight: 700 }}>
                       {ep.status}
                     </span>
                   </td>
                   <td style={{ padding: "16px 24px", fontSize: "0.8rem", color: "#cbd5e1", textAlign: "right" }}>
                     {new Date(ep.last_seen + "Z").toLocaleString('es-EC')}
                   </td>
                   <td style={{ padding: "16px 24px", position: "relative" }} onClick={e => e.stopPropagation()}>
                     <button onClick={(e) => { e.stopPropagation(); setOpenMenu(openMenu === ep.agent_id ? null : ep.agent_id); }} style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer", display: "flex", alignItems: "center" }}>
                       <MoreHorizontal size={18} />
                     </button>
                     {openMenu === ep.agent_id && (
                       <div style={{ position: "absolute", right: "20px", top: "50px", background: "#0f172a", border: "1px solid #334155", borderRadius: "8px", zIndex: 50, padding: "8px", display: "flex", flexDirection: "column", gap: "4px", boxShadow: "0 10px 15px -3px rgba(0,0,0,0.5)", minWidth: "160px" }}>
                         <button onClick={() => handleDelete(ep.agent_id)} style={{ background: "transparent", border: "none", color: "#fca5a5", padding: "8px 12px", textAlign: "left", cursor: "pointer", fontSize: "0.8rem", borderRadius: "4px", width: "100%", display: "flex", alignItems: "center", gap: "8px" }} onMouseEnter={e => e.currentTarget.style.background = "#450a0a"} onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                           <Trash2 size={14} /> Eliminar
                         </button>
                         <button onClick={() => handleForce(ep.agent_id)} style={{ background: "transparent", border: "none", color: "#e2e8f0", padding: "8px 12px", textAlign: "left", cursor: "pointer", fontSize: "0.8rem", borderRadius: "4px", width: "100%", display: "flex", alignItems: "center", gap: "8px" }} onMouseEnter={e => e.currentTarget.style.background = "#1e293b"} onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                           <RefreshCw size={14} /> Forzar Conexión
                         </button>
                       </div>
                     )}
                   </td>
                 </tr>
               );
             })}
             {data.length === 0 && (
               <tr>
                 <td colSpan="5" style={{ textAlign: "center", padding: "40px", color: "#64748b", fontSize: "0.85rem" }}>
                   No hay sensores registrados. Ejecuta el script del agente para comenzar.
                 </td>
               </tr>
             )}
           </tbody>
         </table>
       </div>

       {/* ── MODAL DETALLE DEL ENDPOINT ── */}
       {selectedEndpoint && (
         <div style={{ position: "fixed", inset: 0, background: "rgba(2,6,23,0.85)", backdropFilter: "blur(8px)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, padding: "20px" }} onClick={() => setSelectedEndpoint(null)}>
           <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "16px", width: "100%", maxWidth: "750px", maxHeight: "85vh", overflow: "auto", display: "flex", flexDirection: "column", boxShadow: "0 25px 50px -12px rgba(0,0,0,0.5)" }} onClick={e => e.stopPropagation()}>
             {/* Header */}
             <div style={{ padding: "24px", borderBottom: "1px solid #1e293b", background: "#1e293b", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
               <div>
                 <h2 style={{ fontSize: "1.3rem", fontWeight: 700, color: "#f8fafc", display: "flex", alignItems: "center", gap: "10px" }}>
                   <Server size={20} color="#38bdf8" /> {selectedEndpoint.hostname}
                 </h2>
                 <p style={{ fontSize: "0.8rem", color: "#94a3b8", marginTop: "4px" }}>
                   {selectedEndpoint.ip} · {selectedEndpoint.hostname} · ID: {selectedEndpoint.agent_id}
                 </p>
               </div>
               <button onClick={() => setSelectedEndpoint(null)} style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer" }}><XCircle size={24} /></button>
             </div>

             {/* Tabs */}
             <div style={{ display: "flex", gap: "0", borderBottom: "1px solid #334155" }}>
               <button onClick={() => setInfoTab("hardware")} style={{ flex: 1, padding: "14px", border: "none", background: infoTab === "hardware" ? "#0f172a" : "#1e293b", color: infoTab === "hardware" ? "#38bdf8" : "#94a3b8", fontWeight: 600, fontSize: "0.85rem", cursor: "pointer", borderBottom: infoTab === "hardware" ? "2px solid #38bdf8" : "none" }}>
                 🖥️ Hardware
               </button>
               <button onClick={() => setInfoTab("software")} style={{ flex: 1, padding: "14px", border: "none", background: infoTab === "software" ? "#0f172a" : "#1e293b", color: infoTab === "software" ? "#38bdf8" : "#94a3b8", fontWeight: 600, fontSize: "0.85rem", cursor: "pointer", borderBottom: infoTab === "software" ? "2px solid #38bdf8" : "none" }}>
                 📦 Software ({sw.length})
               </button>
               <button onClick={() => setInfoTab("behavior")} style={{ flex: 1, padding: "14px", border: "none", background: infoTab === "behavior" ? "#0f172a" : "#1e293b", color: infoTab === "behavior" ? "#38bdf8" : "#94a3b8", fontWeight: 600, fontSize: "0.85rem", cursor: "pointer", borderBottom: infoTab === "behavior" ? "2px solid #38bdf8" : "none" }}>
                 🧠 Behavior {behaviorData?.score?.current_score > 0 ? `(${behaviorData.score.current_score})` : ''}
               </button>
             </div>

             {/* Content */}
             <div style={{ padding: "24px" }}>
               {infoTab === "hardware" && (
                 hw ? (
                   <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
                     {[
                       { label: "Sistema Operativo", value: hw.os_name || 'N/A', sub: `${hw.os_version || ''} (${hw.os_arch || ''})` },
                       { label: "Procesador", value: hw.cpu_name || 'N/A', sub: `${hw.cpu_cores || '?'} cores / ${hw.cpu_threads || '?'} threads` },
                       { label: "Memoria RAM", value: `${hw.ram_total_gb || '?'} GB`, sub: "Total Física" },
                       { label: "Fabricante", value: hw.manufacturer || 'N/A', sub: hw.model || '' },
                       { label: "Serial BIOS", value: hw.bios_serial || 'N/A', sub: "" },
                       { label: "Discos", value: hw.disks || 'N/A', sub: "" },
                     ].map((item, i) => (
                       <div key={i} style={{ background: "#1e293b", padding: "16px", borderRadius: "10px", border: "1px solid #334155" }}>
                         <div style={{ fontSize: "0.65rem", color: "#64748b", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>{item.label}</div>
                         <div style={{ fontSize: "0.9rem", color: "#f8fafc", fontWeight: 600, wordBreak: "break-word" }}>{item.value}</div>
                         {item.sub && <div style={{ fontSize: "0.7rem", color: "#94a3b8", marginTop: "4px" }}>{item.sub}</div>}
                       </div>
                     ))}
                   </div>
                 ) : (
                   <div style={{ textAlign: "center", padding: "40px", color: "#64748b", fontSize: "0.85rem" }}>
                     No se ha recibido información de hardware. Reinicia el agente en el equipo para recolectar estos datos.
                   </div>
                 )
               )}

               {infoTab === "software" && (
                 sw.length > 0 ? (
                   <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                     <div style={{ position: "relative" }}>
                       <span style={{ position: "absolute", left: "14px", top: "50%", transform: "translateY(-50%)", color: "#64748b" }}><Search size={16}/></span>
                       <input value={swSearch} onChange={e => setSwSearch(e.target.value)} placeholder="Buscar aplicación..." style={{ width: "100%", background: "#1e293b", border: "1px solid #334155", color: "#f8fafc", padding: "10px 14px 10px 40px", borderRadius: "8px", fontSize: "0.85rem" }} />
                     </div>
                     <div style={{ maxHeight: "400px", overflow: "auto", background: "#020617", borderRadius: "10px", border: "1px solid #1e293b" }}>
                       <table style={{ width: "100%", borderCollapse: "collapse" }}>
                         <thead>
                           <tr style={{ borderBottom: "1px solid #334155", position: "sticky", top: 0, background: "#0f172a" }}>
                             <th style={{ textAlign: "left", padding: "12px 16px", fontSize: "0.7rem", fontWeight: 600, color: "#94a3b8" }}>Aplicación</th>
                             <th style={{ textAlign: "left", padding: "12px 16px", fontSize: "0.7rem", fontWeight: 600, color: "#94a3b8" }}>Versión</th>
                             <th style={{ textAlign: "left", padding: "12px 16px", fontSize: "0.7rem", fontWeight: 600, color: "#94a3b8" }}>Fabricante</th>
                           </tr>
                         </thead>
                         <tbody>
                           {filteredSw.map((app, i) => (
                             <tr key={i} style={{ borderBottom: "1px solid #1e293b" }}>
                               <td style={{ padding: "10px 16px", fontSize: "0.8rem", color: "#f8fafc", fontWeight: 500 }}>{app.name || '-'}</td>
                               <td style={{ padding: "10px 16px", fontSize: "0.75rem", color: "#94a3b8", fontFamily: "monospace" }}>{app.version || '-'}</td>
                               <td style={{ padding: "10px 16px", fontSize: "0.75rem", color: "#64748b" }}>{app.publisher || '-'}</td>
                             </tr>
                           ))}
                           {filteredSw.length === 0 && (
                             <tr><td colSpan="3" style={{ textAlign: "center", padding: "20px", color: "#64748b", fontSize: "0.8rem" }}>Sin coincidencias.</td></tr>
                           )}
                         </tbody>
                       </table>
                     </div>
                     <div style={{ fontSize: "0.7rem", color: "#64748b", textAlign: "right" }}>
                       Mostrando {filteredSw.length} de {sw.length} aplicaciones
                     </div>
                   </div>
                 ) : (
                   <div style={{ textAlign: "center", padding: "40px", color: "#64748b", fontSize: "0.85rem" }}>
                     No se ha recibido información de software. Reinicia el agente en el equipo para recolectar estos datos.
                   </div>
                 )
               )}

               {infoTab === "behavior" && (
                 <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
                   {/* Score Header */}
                   <div style={{ background: "#1e293b", padding: "20px", borderRadius: "12px", border: "1px solid #334155", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                     <div>
                       <div style={{ fontSize: "0.7rem", color: "#94a3b8", fontWeight: 700, textTransform: "uppercase", marginBottom: "4px" }}>RISK SCORE</div>
                       <div style={{ fontSize: "2rem", fontWeight: 800, color: (behaviorData?.score?.current_score || 0) >= 80 ? "#ef4444" : (behaviorData?.score?.current_score || 0) >= 60 ? "#f97316" : (behaviorData?.score?.current_score || 0) >= 30 ? "#fbbf24" : "#22c55e" }}>
                         {behaviorData?.score?.current_score || 0}
                       </div>
                     </div>
                     <div style={{ textAlign: "right" }}>
                       <div style={{ fontSize: "0.7rem", color: "#94a3b8", fontWeight: 700, textTransform: "uppercase", marginBottom: "4px" }}>STATUS</div>
                       <span style={{ 
                         background: (behaviorData?.score?.status === 'critical' || (behaviorData?.score?.current_score || 0) >= 80) ? "rgba(239,68,68,0.15)" : "rgba(34,197,94,0.15)", 
                         color: (behaviorData?.score?.status === 'critical' || (behaviorData?.score?.current_score || 0) >= 80) ? "#ef4444" : "#22c55e",
                         padding: "6px 12px", borderRadius: "8px", fontSize: "0.8rem", fontWeight: 800, textTransform: "uppercase", border: "1px solid"
                       }}>
                         {behaviorData?.score?.status || 'LOW'}
                       </span>
                     </div>
                   </div>

                   {/* Timeline */}
                   <div>
                     <h3 style={{ fontSize: "0.9rem", color: "#f8fafc", marginBottom: "12px", display: "flex", alignItems: "center", gap: "8px" }}>
                       <Activity size={16} /> Behavioral Timeline
                     </h3>
                     <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "300px", overflow: "auto" }}>
                       {behaviorData?.telemetry?.map((ev, i) => {
                        if (!ev) return null;
                        const eventType = (ev.event_type || 'info').toUpperCase();
                        const displayName = typeof ev.process_name === 'string' ? ev.process_name : (ev.target_path || ev.dst_ip || 'Activity');
                        let ts = ev.timestamp || "";
                        if (ts && !ts.endsWith('Z')) ts += 'Z';
                        const timestamp = ts ? new Date(ts).toLocaleTimeString() : '--:--';
                        return (
                          <div key={i} style={{ background: "#0f172a", padding: "12px", borderRadius: "8px", borderLeft: `4px solid ${ev.risk_score > 0 ? '#ef4444' : '#334155'}`, display: "flex", justifyContent: "space-between" }}>
                            <div>
                              <div style={{ fontSize: "0.75rem", color: "#e2e8f0", fontWeight: 600 }}>{eventType} - {displayName}</div>
                              <div style={{ fontSize: "0.65rem", color: "#38bdf8", fontWeight: 600, marginTop: "2px" }}>{ev.description || (ev.risk_score > 0 ? 'Actividad sospechosa detectada' : 'Actividad normal')}</div>
                              <div style={{ fontSize: "0.6rem", color: "#64748b", marginTop: "2px" }}>{timestamp} {ev.parent_process ? `· Parent: ${ev.parent_process}` : ''}</div>
                            </div>
                            {ev.risk_score > 0 && <span style={{ color: "#ef4444", fontWeight: 700, fontSize: "0.75rem" }}>+{ev.risk_score}</span>}
                          </div>
                        );
                      })}
                       {(!behaviorData?.telemetry || behaviorData.telemetry.length === 0) && (
                         <div style={{ textAlign: "center", padding: "20px", color: "#64748b", fontSize: "0.8rem" }}>No telemetry events recorded yet.</div>
                       )}
                     </div>
                   </div>
                 </div>
               )}
             </div>
           </div>
         </div>
       )}
    </div>
  );
}

// ─── COMPONENTE PRINCIPAL ─────────────────────────────────────────────────────
export default function App() {
  const [dataRecientes, setDataRecientes] = useState([]);
  const [dataHistorico, setDataHistorico] = useState([]);
  const [feedsMeta, setFeedsMeta] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [lastUp, setLastUp] = useState(null);
  const [feedStatus, setFeedStatus] = useState({});
  const [dbTotal, setDbTotal] = useState(0);

  // Navegación
  const [activeSidebar, setActiveSidebar] = useState("dashboard"); // "dashboard" | "threats"
  const [activeTab, setActiveTab] = useState("recientes");
  const [showManage, setShowManage] = useState(false);

  // Filtros (Threats View)
  const [q, setQ] = useState("");
  const [region, setRegion] = useState("Todos");
  const [sector, setSector] = useState("Todos");
  const [minSev, setMinSev] = useState("TODOS");
  const [sourceFilter, setSourceFilter] = useState("Todos");
  const [sortBy, setSortBy] = useState("date");
  const [showFilters, setShowFilters] = useState(false);

  const init = useRef(false);

  const loadNews = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/feeds');
      if (!res.ok) throw new Error(`Error del servidor: ${res.status}`);
      const data = await res.json();
      
      setDataRecientes(data.recientes || []);
      setDataHistorico(data.historico || []);
      setFeedsMeta(data.feedsMeta || []);
      setDbTotal(data.total || 0);
      setFeedStatus(data.feedStatus || {});
      setLastUp(new Date().toLocaleTimeString("es-EC", { hour: "2-digit", minute: "2-digit" }));
    } catch (err) {
      setError(err.message.includes('fetch') ? 'Sin conexión al servidor local.' : `Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!init.current) { init.current = true; loadNews(); }
    const interval = setInterval(() => {
      console.log("Auto-refreshing feeds (1 hour interval)...");
      loadNews();
    }, 3600000); // 1 hora
    return () => clearInterval(interval);
  }, [loadNews]);

  const purgeData = async (filterType) => {
    if (!confirm("¿Confirma la eliminación de estos registros?")) return;
    try {
      const res = await fetch('/api/feeds', { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ filterType }) });
      await res.json();
      setShowManage(false);
      loadNews();
    } catch (err) { alert("Error eliminando datos: " + err.message); }
  };

  const [endpointsData, setEndpointsData] = useState([]);

  const loadEndpoints = useCallback(async () => {
    try {
      const res = await fetch('/api/sensors/endpoints');
      if (res.ok) {
        const data = await res.json();
        setEndpointsData(data.endpoints || []);
      }
    } catch (e) {
      console.error("Error cargando endpoints:", e);
    }
  }, []);

  useEffect(() => {
    if (activeSidebar === "endpoints") {
      loadEndpoints();
      const interval = setInterval(loadEndpoints, 15000); // refresh every 15s when active
      return () => clearInterval(interval);
    }
  }, [activeSidebar, loadEndpoints]);

  const currentData = activeTab === "recientes" ? dataRecientes : dataHistorico;

  // Filtrado General (se usa tanto en Dashboard como Threats)
  const filtered = currentData
    .filter(n => {
      const qOk  = !q || [n.title, n.summary, n.source, n.sector, ...(n.tags || [])].join(" ").toLowerCase().includes(q.toLowerCase());
      const rOk  = region === "Todos" || n.region === region;
      const sOk  = sector === "Todos" || n.sector === sector;
      const srcOk = sourceFilter === "Todos" || n.feed === sourceFilter || n.feedId === sourceFilter || n.source === sourceFilter;
      const sevOk = minSev === "TODOS" || (SEV_ORD[n.severity] || 0) >= SEV_ORD[minSev];
      return qOk && rOk && sOk && sevOk && srcOk;
    })
    .sort((a, b) => {
      if (sortBy === "severity") return (SEV_ORD[b.severity] || 0) - (SEV_ORD[a.severity] || 0);
      if (sortBy === "date") return (b.date ? new Date(b.date) : 0) - (a.date ? new Date(a.date) : 0);
      return (a.region || "").localeCompare(b.region || "");
    });

  const dashboardAttacks = useMemo(() => {
    return currentData
      .filter(n => 
        n.severity === 'CRÍTICO' || 
        n.severity === 'ALTO' || 
        ['Ransomware', 'Phishing', 'Fraude', 'Infraestructura', 'Vulnerabilidad'].includes(n.sector)
      )
      .slice(0, 5);
  }, [currentData]);

  const total = currentData.length;
  const ecN = currentData.filter(n => n.region === "Ecuador").length;
  const laN = currentData.filter(n => n.region === "Latinoamérica").length;
  const critN = currentData.filter(n => n.severity === "CRÍTICO").length;
  const highN = currentData.filter(n => n.severity === "ALTO").length;

  const latamMonthly = useMemo(() => {
    const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
    return currentData.filter(n => 
      (n.region === "Ecuador" || n.region === "Latinoamérica") && 
      new Date(n.date).getTime() > thirtyDaysAgo
    );
  }, [currentData]);

  const topActors = useMemo(() => {
    const counts = {};
    latamMonthly.forEach(n => {
      if (n.actor) counts[n.actor] = (counts[n.actor] || 0) + 1;
    });
    return Object.entries(counts).sort((a,b) => b[1] - a[1]).slice(0, 10);
  }, [latamMonthly]);

  const topSectorsLatam = useMemo(() => {
    const counts = {};
    latamMonthly.forEach(n => {
      if (n.sector && n.sector !== 'General') counts[n.sector] = (counts[n.sector] || 0) + 1;
    });
    return Object.entries(counts).sort((a,b) => b[1] - a[1]).slice(0, 10);
  }, [latamMonthly]);

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0b1120; font-family: 'Inter', sans-serif; color: #f8fafc; overflow: hidden; }
        @keyframes fu { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes zapSpin { 100% { transform: rotate(360deg); } }
        .spin { animation: zapSpin 1s linear infinite; color: #38bdf8 !important; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #475569; }
        input:focus { outline: none; border-color: #38bdf8 !important; }
      `}</style>

      {/* MODAL GESTIÓN */}
      {showManage && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(11,17,32,0.9)", backdropFilter: "blur(4px)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "12px", padding: "32px", width: "400px" }}>
            <h2 style={{ fontSize: "1.2rem", marginBottom: "16px" }}>Gestión de Datos ({dbTotal})</h2>
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <button onClick={() => purgeData('historico_all')} style={{ background: "#1e1b4b", border: "1px solid #3730a3", color: "#a5b4fc", padding: "12px", borderRadius: "8px", cursor: "pointer" }}>Limpiar &gt; 60 días</button>
              <button onClick={() => purgeData('all')} style={{ background: "#450a0a", border: "1px solid #7f1d1d", color: "#fca5a5", padding: "12px", borderRadius: "8px", cursor: "pointer" }}>VACIAR BASE DE DATOS</button>
              <button onClick={() => setShowManage(false)} style={{ background: "transparent", border: "1px solid #334155", color: "#94a3b8", padding: "12px", borderRadius: "8px", cursor: "pointer" }}>Cancelar</button>
            </div>
          </div>
        </div>
      )}

      {/* ── LAYOUT PRINCIPAL (SIDEBAR + MAIN) ── */}
      <div style={{ display: "flex", height: "100vh", width: "100vw" }}>
        
        {/* ── SIDEBAR ── */}
        <aside style={{ width: "240px", background: "#0f172a", borderRight: "1px solid #1e293b", display: "flex", flexDirection: "column" }}>
          <div style={{ padding: "24px 20px", display: "flex", alignItems: "center", gap: "12px", borderBottom: "1px solid #1e293b" }}>
            <div style={{ background: "#38bdf8", padding: "6px", borderRadius: "8px" }}><Shield size={20} color="#0f172a" /></div>
            <div>
              <div style={{ fontSize: "1rem", fontWeight: 700, letterSpacing: "0.5px" }}>INTEL<span style={{fontWeight: 400}}>LECT</span></div>
              <div style={{ fontSize: "0.6rem", color: "#94a3b8", letterSpacing: "1px" }}>SECURITY EC</div>
            </div>
          </div>

          <nav style={{ padding: "20px 10px", display: "flex", flexDirection: "column", gap: "8px", flex: 1 }}>
            <div style={{ color: "#64748b", fontSize: "0.65rem", fontWeight: 600, padding: "0 10px", marginBottom: "4px" }}>MENU</div>
            <button 
              onClick={() => {setActiveSidebar("dashboard"); setQ(""); setSourceFilter("Todos"); setRegion("Todos"); setSector("Todos"); setMinSev("TODOS");}} 
              style={{ display: "flex", alignItems: "center", gap: "12px", background: activeSidebar === "dashboard" ? "#1e293b" : "transparent", color: activeSidebar === "dashboard" ? "#38bdf8" : "#94a3b8", border: "none", padding: "10px 12px", borderRadius: "8px", fontSize: "0.85rem", fontWeight: 500, cursor: "pointer" }}
            >
              <LayoutDashboard size={18} /> Dashboard {activeSidebar === "dashboard" && <span style={{marginLeft:"auto", fontSize:"0.6rem", background:"#0c4a6e", color:"#bae6fd", padding:"2px 6px", borderRadius:"10px"}}>Active</span>}
            </button>
            <button 
              onClick={() => setActiveSidebar("threats")} 
              style={{ display: "flex", alignItems: "center", gap: "12px", background: activeSidebar === "threats" ? "#1e293b" : "transparent", color: activeSidebar === "threats" ? "#38bdf8" : "#94a3b8", border: "none", padding: "10px 12px", borderRadius: "8px", fontSize: "0.85rem", fontWeight: 500, cursor: "pointer" }}
            >
              <ShieldAlert size={18} /> Threats {activeSidebar === "threats" && <span style={{marginLeft:"auto", fontSize:"0.6rem", background:"#0c4a6e", color:"#bae6fd", padding:"2px 6px", borderRadius:"10px"}}>Active</span>}
            </button>
            <button 
              onClick={() => setActiveSidebar("assets")} 
              style={{ display: "flex", alignItems: "center", gap: "12px", background: activeSidebar === "assets" ? "#1e293b" : "transparent", color: activeSidebar === "assets" ? "#38bdf8" : "#94a3b8", border: "none", padding: "10px 12px", borderRadius: "8px", fontSize: "0.85rem", fontWeight: 500, cursor: "pointer" }}
            >
              <Database size={18} /> Assets {activeSidebar === "assets" && <span style={{marginLeft:"auto", fontSize:"0.6rem", background:"#0c4a6e", color:"#bae6fd", padding:"2px 6px", borderRadius:"10px"}}>Active</span>}
            </button>
            <button 
              onClick={() => setActiveSidebar("endpoints")} 
              style={{ display: "flex", alignItems: "center", gap: "12px", background: activeSidebar === "endpoints" ? "#1e293b" : "transparent", color: activeSidebar === "endpoints" ? "#38bdf8" : "#94a3b8", border: "none", padding: "10px 12px", borderRadius: "8px", fontSize: "0.85rem", fontWeight: 500, cursor: "pointer" }}
            >
              <Server size={18} /> Endpoints {activeSidebar === "endpoints" && <span style={{marginLeft:"auto", fontSize:"0.6rem", background:"#0c4a6e", color:"#bae6fd", padding:"2px 6px", borderRadius:"10px"}}>Active</span>}
            </button>
            <button 
              onClick={() => setActiveSidebar("analysis")} 
              style={{ display: "flex", alignItems: "center", gap: "12px", background: activeSidebar === "analysis" ? "#1e293b" : "transparent", color: activeSidebar === "analysis" ? "#38bdf8" : "#94a3b8", border: "none", padding: "10px 12px", borderRadius: "8px", fontSize: "0.85rem", fontWeight: 500, cursor: "pointer" }}
            >
              <Activity size={18} /> Analysis {activeSidebar === "analysis" && <span style={{marginLeft:"auto", fontSize:"0.6rem", background:"#0c4a6e", color:"#bae6fd", padding:"2px 6px", borderRadius:"10px"}}>Active</span>}
            </button>
            <button style={{ display: "flex", alignItems: "center", gap: "12px", background: "transparent", color: "#475569", border: "none", padding: "10px 12px", borderRadius: "8px", fontSize: "0.85rem", fontWeight: 500, cursor: "not-allowed" }}><FileText size={18} /> Reports</button>
          </nav>
        </aside>

        {/* ── CONTENIDO PRINCIPAL ── */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", background: "#0b1120" }}>
          
          {/* HEADER NAV */}
          <header style={{ height: "70px", borderBottom: "1px solid #1e293b", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 32px", background: "#0f172a" }}>
            <div style={{ display: "flex", gap: "24px" }}>
              <span onClick={()=>setActiveSidebar("dashboard")} style={{ cursor:"pointer", color: activeSidebar==="dashboard" ? "#f8fafc" : "#64748b", fontSize: "0.85rem", fontWeight: 600, borderBottom: activeSidebar==="dashboard"?"2px solid #38bdf8":"none", paddingBottom: activeSidebar==="dashboard"?"23px":"0", paddingTop: activeSidebar==="dashboard"?"23px":"0" }}>Dashboard</span>
              <span onClick={()=>setActiveSidebar("threats")} style={{ cursor:"pointer", color: activeSidebar==="threats" ? "#f8fafc" : "#64748b", fontSize: "0.85rem", fontWeight: 600, borderBottom: activeSidebar==="threats"?"2px solid #38bdf8":"none", paddingBottom: activeSidebar==="threats"?"23px":"0", paddingTop: activeSidebar==="threats"?"23px":"0" }}>Threats</span>
              <span onClick={()=>setActiveSidebar("assets")} style={{ cursor:"pointer", color: activeSidebar==="assets" ? "#f8fafc" : "#64748b", fontSize: "0.85rem", fontWeight: 600, borderBottom: activeSidebar==="assets"?"2px solid #38bdf8":"none", paddingBottom: activeSidebar==="assets"?"23px":"0", paddingTop: activeSidebar==="assets"?"23px":"0" }}>Assets</span>
            </div>
            
            <div style={{ display: "flex", alignItems: "center", gap: "20px", color: "#94a3b8" }}>
              {lastUp && <span style={{fontSize:"0.7rem"}}>Última: {lastUp}</span>}
              <button onClick={loadNews} disabled={loading} style={{ background:"none", border:"none", color:"#94a3b8", cursor: loading ? "wait" : "pointer", display:"flex"}}>
                <Zap size={18} className={loading ? "spin" : ""} />
              </button>
              <button onClick={() => setShowManage(true)} style={{ background:"none", border:"none", color:"#94a3b8", cursor:"pointer", display:"flex"}}><Settings size={18} /></button>
              <div style={{ width: "1px", height: "20px", background: "#1e293b" }} />
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <div style={{ background: "#334155", borderRadius: "50%", padding: "6px" }}><User size={16} color="#f8fafc" /></div>
                <span style={{ fontSize: "0.85rem", color: "#e2e8f0", fontWeight: 500 }}>Admin EC ▾</span>
              </div>
            </div>
          </header>

          {/* MAIN SCROLLABLE AREA */}
          <main style={{ flex: 1, overflowY: "auto", padding: "32px", display: "flex", flexDirection: "column", gap: "24px" }}>
            
            {error && (
              <div style={{ background: "#450a0a", border: "1px solid #7f1d1d", borderRadius: "8px", padding: "16px", color: "#fca5a5" }}>{error}</div>
            )}

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
              <h1 style={{ fontSize: "1.5rem", fontWeight: 600, color: "#f8fafc", margin: 0 }}>
                {activeSidebar === "dashboard" ? "Threat Intelligence Dashboard" : "Threat Hunting & Analysis"}
              </h1>
              <div style={{ display: "flex", background: "#1e293b", borderRadius: "8px", padding: "4px" }}>
                <button onClick={() => setActiveTab("recientes")} style={{ background: activeTab === "recientes" ? "#334155" : "transparent", border: "none", color: activeTab === "recientes" ? "#f8fafc" : "#94a3b8", padding: "6px 16px", borderRadius: "6px", fontSize: "0.8rem", fontWeight: 500, cursor: "pointer" }}>Recientes (60d)</button>
                <button onClick={() => setActiveTab("historico")} style={{ background: activeTab === "historico" ? "#334155" : "transparent", border: "none", color: activeTab === "historico" ? "#f8fafc" : "#94a3b8", padding: "6px 16px", borderRadius: "6px", fontSize: "0.8rem", fontWeight: 500, cursor: "pointer" }}>Histórico</button>
              </div>
            </div>

            {activeSidebar === "assets" && <AssetsView />}
            {activeSidebar === "endpoints" && <EndpointsView data={endpointsData} refresh={loadEndpoints} />}
            {activeSidebar === "analysis" && <AnalysisView />}

            {/* ── VISTA 1: DASHBOARD EJECUTIVO ── */}
            {activeSidebar === "dashboard" && (
              <>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "20px" }}>
                  <StatCard val={total} label="Total Events" accent="#38bdf8" sub="Values accent" points={[20,40,30,60,50,80,40,70]} onClick={() => setActiveSidebar("threats")} />
                  <StatCard val={critN} label="Critical Alerts" accent="#ef4444" sub="[High Severity]" points={[10,20,15,30,50,40,60,80]} onClick={() => {setMinSev("CRÍTICO"); setActiveSidebar("threats");}} />
                  <StatCard val={ecN} label="Ecuador Impact" accent="#f97316" sub="Local Events" points={[5,15,25,20,40,35,50,45]} onClick={() => {setRegion("Ecuador"); setActiveSidebar("threats");}} />
                  <StatCard val={laN} label="Latam Activity" accent="#eab308" sub="[Warning Zone]" points={[30,20,40,25,45,30,50,40]} onClick={() => {setRegion("Latinoamérica"); setActiveSidebar("threats");}} />
                </div>

                <div style={{ background: "#1e293b", borderRadius: "10px", border: "1px solid #334155", display: "flex", flexDirection: "column" }}>
                  <div style={{ padding: "16px 20px", borderBottom: "1px solid #334155", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "#f8fafc", margin: 0 }}>Recent Attack Alerts (Top 5)</h3>
                  </div>
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "800px" }}>
                      <thead>
                        <tr style={{ borderBottom: "1px solid #334155" }}>
                          <th style={{ textAlign: "left", padding: "14px 20px", fontSize: "0.75rem", fontWeight: 600, color: "#94a3b8" }}>Timestamp</th>
                          <th style={{ textAlign: "left", padding: "14px 20px", fontSize: "0.75rem", fontWeight: 600, color: "#94a3b8" }}>Severity</th>
                          <th style={{ textAlign: "left", padding: "14px 20px", fontSize: "0.75rem", fontWeight: 600, color: "#94a3b8" }}>Source</th>
                          <th style={{ textAlign: "left", padding: "14px 20px", fontSize: "0.75rem", fontWeight: 600, color: "#94a3b8" }}>Headline</th>
                          <th style={{ textAlign: "left", padding: "14px 20px", fontSize: "0.75rem", fontWeight: 600, color: "#94a3b8" }}>Type</th>
                        </tr>
                      </thead>
                      <tbody>
                        {dashboardAttacks.map((item, i) => (
                          <tr key={item.id} style={{ borderBottom: "1px solid #1e293b", background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)" }}>
                            <td style={{ padding: "14px 20px", fontSize: "0.75rem", color: "#cbd5e1" }}>{item.dateAgo}</td>
                            <td style={{ padding: "14px 20px" }}><SevBadge level={item.severity} /></td>
                            <td style={{ padding: "14px 20px", fontSize: "0.75rem", color: "#94a3b8" }}>{item.source}</td>
                            <td style={{ padding: "14px 20px", fontSize: "0.85rem", color: "#f8fafc", fontWeight: 500 }}>{item.title.length > 50 ? item.title.substring(0,50)+'...' : item.title}</td>
                            <td style={{ padding: "14px 20px", fontSize: "0.75rem", color: "#cbd5e1" }}>{item.tags?.[0] || item.sector}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div style={{ padding: "12px 20px", borderTop: "1px solid #334155", textAlign: "center" }}>
                    <button onClick={() => setActiveSidebar("threats")} style={{ background: "transparent", border: "none", color: "#38bdf8", fontSize: "0.8rem", cursor: "pointer", fontWeight: 500 }}>Explorar todos los {filtered.length} eventos en Threats ▾</button>
                  </div>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "24px" }}>
                  <GlobalThreatMap data={filtered} />
                  <TopIndicators />
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px" }}>
                  <LatamActors localData={topActors} />
                  <IndustrySectors />
                </div>
              </>
            )}

            {/* ── VISTA 2: THREATS (PORTAL ORIGINAL) ── */}
            {activeSidebar === "threats" && (
              <>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "16px", marginBottom: "8px", animation: "fu 0.3s ease both" }}>
                  <StatCard val={filtered.length} label="EN PESTAÑA" onClick={() => { setRegion("Todos"); setSector("Todos"); setMinSev("TODOS"); setQ(""); setSourceFilter("Todos"); }} />
                  <StatCard val={filtered.filter(n=>n.region==="Ecuador").length} label="ECUADOR" accent="#f87171" onClick={() => { setRegion("Ecuador"); setSector("Todos"); setMinSev("TODOS"); setQ(""); setSourceFilter("Todos"); }} />
                  <StatCard val={filtered.filter(n=>n.region==="Latinoamérica").length} label="LATAM" accent="#fb923c" onClick={() => { setRegion("Latinoamérica"); setSector("Todos"); setMinSev("TODOS"); setQ(""); setSourceFilter("Todos"); }} />
                  <StatCard val={filtered.filter(n=>n.severity==="CRÍTICO").length} label="CRÍTICOS" accent="#ef4444" onClick={() => { setMinSev("CRÍTICO"); setRegion("Todos"); setSector("Todos"); setQ(""); setSourceFilter("Todos"); }} />
                  <StatCard val={filtered.filter(n=>n.severity==="ALTO").length} label="ALTA SEV" accent="#f97316" onClick={() => { setMinSev("ALTO"); setRegion("Todos"); setSector("Todos"); setQ(""); setSourceFilter("Todos"); }} />
                </div>

                <div style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "12px", padding: "20px" }}>
                  
                  {/* SEARCH BAR & FILTER TOGGLE */}
                  <div style={{ display: "flex", gap: "12px", marginBottom: showFilters ? "20px" : "0" }}>
                    <div style={{ position: "relative", flex: 1 }}>
                      <span style={{ position: "absolute", left: "16px", top: "50%", transform: "translateY(-50%)", color: "#64748b" }}><Search size={18}/></span>
                      <input 
                        value={q} onChange={e => setQ(e.target.value)} 
                        placeholder="Búsqueda profunda (ransomware, phishing, entidades...)" 
                        style={{ width: "100%", background: "#0f172a", border: "1px solid #334155", color: "#f8fafc", fontSize: "0.95rem", padding: "14px 16px 14px 46px", borderRadius: "8px", transition: "all 0.2s" }} 
                      />
                      {q && <button onClick={() => setQ("")} style={{ position: "absolute", right: "16px", top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "#94a3b8", cursor: "pointer", fontSize: "1rem" }}>✕</button>}
                    </div>
                    <button 
                      onClick={() => setShowFilters(!showFilters)}
                      style={{ 
                        background: showFilters ? "#38bdf8" : "#0f172a", 
                        color: showFilters ? "#0f172a" : "#94a3b8", 
                        border: "1px solid #334155", 
                        borderRadius: "8px", 
                        padding: "0 20px", 
                        cursor: "pointer", 
                        display: "flex", 
                        alignItems: "center", 
                        gap: "10px", 
                        transition: "all 0.2s",
                        whiteSpace: "nowrap"
                      }}
                    >
                      <Filter size={18} />
                      <span style={{ fontSize: "0.85rem", fontWeight: 600 }}>Filtros</span>
                      {showFilters ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                    </button>
                  </div>

                  {/* FILTERS (COLLAPSIBLE) */}
                  {showFilters && (
                    <div style={{ display: "flex", flexDirection: "column", gap: "16px", animation: "fu 0.3s ease both" }}>
                    <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
                      <span style={{ color: "#64748b", fontSize: "0.7rem", fontWeight: 700, marginRight: "8px", width: "70px" }}>REGIÓN</span>
                      {REGIONS.map(r => <Chip key={r} active={region === r} accent={REG_CLR[r] || "#94a3b8"} onClick={() => setRegion(r)}>{r === "Todos" ? "🌍 Global" : r === "Ecuador" ? "🇪🇨 Ecuador" : r === "Latinoamérica" ? "🌎 Latam" : "🌐 Resto del Mundo"}</Chip>)}
                    </div>
                    <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
                      <span style={{ color: "#64748b", fontSize: "0.7rem", fontWeight: 700, marginRight: "8px", width: "70px" }}>RIESGO</span>
                      {["TODOS", "CRÍTICO", "ALTO", "MEDIO"].map(s => <Chip key={s} active={minSev === s} accent="#eab308" onClick={() => setMinSev(s)}>{s === "TODOS" ? "Cualquiera" : `≥ ${s}`}</Chip>)}
                    </div>
                    <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
                      <span style={{ color: "#64748b", fontSize: "0.7rem", fontWeight: 700, marginRight: "8px", width: "70px" }}>SECTOR</span>
                      {SECTORS.map(s => <Chip key={s} active={sector === s} accent="#38bdf8" onClick={() => setSector(s)}>{s}</Chip>)}
                    </div>
                    
                    {/* FEED CHIPS */}
                    {Object.keys(feedStatus).length > 0 && (
                      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center", paddingTop: "12px", borderTop: "1px solid #334155" }}>
                        <span style={{ color: "#64748b", fontSize: "0.7rem", fontWeight: 700, marginRight: "8px", width: "70px" }}>FUENTE</span>
                        <Chip active={sourceFilter === "Todos"} accent="#94a3b8" onClick={() => setSourceFilter("Todos")}>Todas</Chip>
                        {feedsMeta.map(feedObj => {
                          const info = feedStatus[feedObj.id];
                          const clr = info?.status === "ok" ? "#22c55e" : "#ef4444";
                          const active = sourceFilter === feedObj.id;
                          return (
                            <button 
                              key={feedObj.id} onClick={() => setSourceFilter(feedObj.id)}
                              style={{ 
                                display: "flex", alignItems: "center", gap: "6px", 
                                background: active ? `${clr}1A` : "transparent", 
                                border: `1px solid ${active ? clr : "#334155"}`, 
                                borderRadius: "6px", padding: "4px 10px", fontSize: "0.65rem", fontWeight: 500, color: active ? clr : "#94a3b8", cursor: "pointer", transition: "all 0.15s"
                              }}
                            >
                              <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: clr, display: "inline-block", boxShadow: `0 0 6px ${clr}` }} />
                              {feedObj.name} {info?.status === "ok" && info?.added > 0 ? `(+${info.added})` : ""}
                            </button>
                          );
                        })}
                      </div>
                    )}
                  </div>
                  )}
                </div>

                {/* THREAT CARDS LIST */}
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: "0.85rem", color: "#94a3b8", fontWeight: 500 }}>Mostrando <strong style={{color:"#f8fafc"}}>{filtered.length}</strong> eventos analíticos</span>
                  <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                    <span style={{ fontSize: "0.75rem", color: "#64748b", fontWeight: 600 }}>ORDEN:</span>
                    <select value={sortBy} onChange={e => setSortBy(e.target.value)} style={{ background: "#1e293b", border: "1px solid #334155", color: "#e2e8f0", fontSize: "0.8rem", padding: "6px 12px", borderRadius: "6px", cursor: "pointer" }}>
                      <option value="date">Más Recientes</option>
                      <option value="severity">Mayor Severidad</option>
                      <option value="region">Región</option>
                    </select>
                  </div>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                  {filtered.map((item, i) => <ThreatCard key={item.id} item={item} idx={i} />)}
                </div>
              </>
            )}

          </main>
        </div>
      </div>
    </>
  );
}
