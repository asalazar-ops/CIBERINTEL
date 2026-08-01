import { useState } from "react";
import { Zap, Lock, Mail, AlertCircle } from "lucide-react";

export default function Login({ onLoginSuccess }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'No se pudo iniciar sesión.');
        return;
      }
      onLoginSuccess(data.email);
    } catch (err) {
      setError('Sin conexión al servidor.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "#0f172a", padding: "20px" }}>
      <form onSubmit={handleSubmit} style={{ width: "100%", maxWidth: "380px", background: "#1e293b", border: "1px solid #334155", borderRadius: "12px", padding: "32px" }}>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "10px", marginBottom: "28px" }}>
          <div style={{ background: "#38bdf8", padding: "12px", borderRadius: "10px" }}>
            <Zap size={24} color="#0f172a" />
          </div>
          <h1 style={{ fontSize: "1.2rem", fontWeight: 700, color: "#f8fafc", margin: 0 }}>CyberIntel EC</h1>
          <p style={{ fontSize: "0.8rem", color: "#64748b", margin: 0 }}>Inicia sesión para continuar</p>
        </div>

        <label style={{ display: "block", fontSize: "0.75rem", color: "#94a3b8", marginBottom: "6px", fontWeight: 600 }}>Correo</label>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", background: "#0f172a", border: "1px solid #334155", borderRadius: "8px", padding: "10px 12px", marginBottom: "16px" }}>
          <Mail size={16} color="#64748b" />
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoFocus
            autoComplete="username"
            style={{ background: "transparent", border: "none", outline: "none", color: "#f8fafc", fontSize: "0.85rem", width: "100%" }}
          />
        </div>

        <label style={{ display: "block", fontSize: "0.75rem", color: "#94a3b8", marginBottom: "6px", fontWeight: 600 }}>Contraseña</label>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", background: "#0f172a", border: "1px solid #334155", borderRadius: "8px", padding: "10px 12px", marginBottom: "20px" }}>
          <Lock size={16} color="#64748b" />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
            style={{ background: "transparent", border: "none", outline: "none", color: "#f8fafc", fontSize: "0.85rem", width: "100%" }}
          />
        </div>

        {error && (
          <div style={{ display: "flex", alignItems: "center", gap: "8px", background: "#7f1d1d", border: "1px solid #ef4444", color: "#fecaca", fontSize: "0.8rem", padding: "10px 12px", borderRadius: "8px", marginBottom: "16px" }}>
            <AlertCircle size={16} />
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          style={{ width: "100%", background: "#38bdf8", color: "#0f172a", border: "none", borderRadius: "8px", padding: "12px", fontSize: "0.85rem", fontWeight: 700, cursor: loading ? "default" : "pointer", opacity: loading ? 0.7 : 1 }}
        >
          {loading ? "Verificando..." : "Iniciar sesión"}
        </button>
      </form>
    </div>
  );
}
