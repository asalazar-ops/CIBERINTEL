import { AlertTriangle } from "lucide-react";

/**
 * Banner de error inline reutilizable, para fetches que fallan en silencio
 * (antes: solo console.error — ver fetchAssets, loadEndpoints, loadSummary,
 * loadBehavior, los paneles OTX en src/App.jsx). No reemplaza a los toasts:
 * el toast es para el resultado de una acción puntual (ej. al hacer clic en
 * "Añadir"), este banner es para el estado persistente de una carga que
 * falló y que el usuario debe seguir viendo mientras no se resuelva.
 */
export default function ErrorBanner({ children }) {
  if (!children) return null;
  return (
    <div style={{ background: "rgba(239, 68, 68, 0.1)", border: "1px solid #ef4444", borderRadius: "8px", padding: "12px 16px", color: "#fca5a5", fontSize: "0.85rem", display: "flex", alignItems: "center", gap: "8px" }}>
      <AlertTriangle size={16} /> {children}
    </div>
  );
}
