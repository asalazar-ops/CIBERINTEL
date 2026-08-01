import { RefreshCw } from "lucide-react";

/**
 * Indicador de carga reutilizable. Antes de este componente, algunas vistas
 * mostraban spinner durante la carga inicial (TopIndicators, AnalysisView) y
 * otras no mostraban nada hasta que llegaba la respuesta (AssetsView,
 * EndpointsView) — mismo ícono/spin ya usado en la app, ahora estandarizado.
 */
export default function Spinner({ label = "Cargando...", size = 16 }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "#64748b", fontSize: "0.85rem", padding: "8px 0" }}>
      <RefreshCw size={size} className="spin" />
      {label}
    </div>
  );
}
