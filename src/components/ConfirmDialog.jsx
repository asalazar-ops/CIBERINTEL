import { createContext, useCallback, useContext, useRef, useState } from "react";
import { AlertTriangle } from "lucide-react";

const ConfirmContext = createContext(null);

/**
 * Reemplaza los window.confirm()/confirm() nativos (ver src/App.jsx:
 * deleteAsset, handleDelete de endpoints, purgeData) por un modal propio.
 * window.confirm() es síncrono y bloqueante; este modal no puede serlo, así
 * que se resuelve como Promise<boolean> — el caller solo cambia
 * `if (!confirm(msg)) return;` por `if (!await confirmDialog(msg)) return;`
 * dentro de una función async, sin reestructurar el resto del flujo.
 */
export function ConfirmProvider({ children }) {
  const [dialog, setDialog] = useState(null);
  const resolver = useRef(null);

  const confirmDialog = useCallback((message, options = {}) => {
    return new Promise((resolve) => {
      resolver.current = resolve;
      setDialog({ message, title: options.title || "Confirmar acción", danger: options.danger !== false });
    });
  }, []);

  const handle = (result) => {
    resolver.current?.(result);
    setDialog(null);
  };

  return (
    <ConfirmContext.Provider value={confirmDialog}>
      {children}
      {dialog && (
        <div
          role="presentation"
          onClick={() => handle(false)}
          style={{ position: "fixed", inset: 0, background: "rgba(2, 6, 23, 0.7)", zIndex: 3000, display: "flex", alignItems: "center", justifyContent: "center" }}
        >
          <div
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="confirm-dialog-title"
            onClick={(e) => e.stopPropagation()}
            style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "12px", padding: "24px", width: "380px", maxWidth: "90vw", boxShadow: "0 16px 40px rgba(0,0,0,0.5)" }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "12px" }}>
              <AlertTriangle size={20} color={dialog.danger ? "#ef4444" : "#38bdf8"} />
              <h3 id="confirm-dialog-title" style={{ margin: 0, color: "#f8fafc", fontSize: "1.05rem", fontWeight: 700 }}>{dialog.title}</h3>
            </div>
            <p style={{ color: "#94a3b8", fontSize: "0.85rem", lineHeight: 1.5, margin: "0 0 20px" }}>{dialog.message}</p>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
              <button
                onClick={() => handle(false)}
                style={{ background: "none", border: "1px solid #334155", color: "#94a3b8", borderRadius: "8px", padding: "8px 16px", cursor: "pointer", fontSize: "0.85rem", fontWeight: 600 }}
              >
                Cancelar
              </button>
              <button
                onClick={() => handle(true)}
                style={{ background: dialog.danger ? "#ef4444" : "#38bdf8", border: "none", color: dialog.danger ? "#fff" : "#0f172a", borderRadius: "8px", padding: "8px 16px", cursor: "pointer", fontSize: "0.85rem", fontWeight: 700 }}
              >
                Confirmar
              </button>
            </div>
          </div>
        </div>
      )}
    </ConfirmContext.Provider>
  );
}

/** Devuelve confirmDialog(message, { title?, danger? }) => Promise<boolean>. */
export function useConfirm() {
  const ctx = useContext(ConfirmContext);
  if (!ctx) throw new Error("useConfirm debe usarse dentro de <ConfirmProvider>");
  return ctx;
}
