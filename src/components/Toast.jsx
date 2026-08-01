import { createContext, useCallback, useContext, useRef, useState } from "react";
import { CheckCircle, XCircle, AlertTriangle, X } from "lucide-react";

const ToastContext = createContext(null);

const VARIANTS = {
  success: { icon: CheckCircle, color: "#22c55e", bg: "rgba(34, 197, 94, 0.1)" },
  error:   { icon: XCircle,      color: "#ef4444", bg: "rgba(239, 68, 68, 0.1)" },
  info:    { icon: AlertTriangle, color: "#38bdf8", bg: "rgba(56, 189, 248, 0.1)" },
};

/**
 * Reemplaza los alert() nativos (ver src/App.jsx: AssetsView, EndpointsView,
 * purga de datos) por notificaciones propias, no bloqueantes. Envolver <App/>
 * con <ToastProvider> una sola vez; cualquier componente hijo llama a
 * useToast() para disparar toasts sin prop-drilling.
 */
export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const nextId = useRef(0);

  const dismiss = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const showToast = useCallback((message, variant = "info", duration = 5000) => {
    const id = ++nextId.current;
    setToasts(prev => [...prev, { id, message, variant }]);
    if (duration > 0) {
      setTimeout(() => dismiss(id), duration);
    }
    return id;
  }, [dismiss]);

  return (
    <ToastContext.Provider value={showToast}>
      {children}
      <div style={{ position: "fixed", bottom: "24px", right: "24px", zIndex: 2000, display: "flex", flexDirection: "column", gap: "10px", maxWidth: "380px" }}>
        {toasts.map(t => {
          const v = VARIANTS[t.variant] || VARIANTS.info;
          const Icon = v.icon;
          return (
            <div
              key={t.id}
              role="alert"
              style={{
                background: "#1e293b", border: `1px solid ${v.color}`, borderRadius: "10px",
                padding: "14px 16px", display: "flex", alignItems: "flex-start", gap: "10px",
                boxShadow: "0 8px 24px rgba(0,0,0,0.4)", animation: "toast-in 0.2s ease both",
              }}
            >
              <Icon size={18} color={v.color} style={{ flexShrink: 0, marginTop: "1px" }} />
              <span style={{ color: "#e2e8f0", fontSize: "0.85rem", lineHeight: 1.4, flex: 1 }}>{t.message}</span>
              <button
                onClick={() => dismiss(t.id)}
                aria-label="Cerrar notificación"
                style={{ background: "none", border: "none", color: "#64748b", cursor: "pointer", padding: 0, display: "flex", flexShrink: 0 }}
              >
                <X size={16} />
              </button>
            </div>
          );
        })}
      </div>
      <style>{`
        @keyframes toast-in {
          from { opacity: 0; transform: translateX(20px); }
          to { opacity: 1; transform: translateX(0); }
        }
      `}</style>
    </ToastContext.Provider>
  );
}

/** Devuelve showToast(message, variant, duration) — variant: "success" | "error" | "info". */
export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast debe usarse dentro de <ToastProvider>");
  return ctx;
}
