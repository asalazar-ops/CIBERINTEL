import { useState } from "react";
import { Zap, Lock, Mail, AlertCircle } from "lucide-react";
import loginBg from "../assets/loginplane.webp";

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
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "20px",
        backgroundImage: `linear-gradient(180deg, rgba(4, 10, 22, 0.55) 0%, rgba(4, 10, 22, 0.75) 100%), url(${loginBg})`,
        backgroundSize: "cover",
        backgroundPosition: "center",
      }}
    >
      <form
        onSubmit={handleSubmit}
        style={{
          width: "100%",
          maxWidth: "380px",
          background: "rgba(15, 23, 42, 0.55)",
          backdropFilter: "blur(16px)",
          WebkitBackdropFilter: "blur(16px)",
          border: "1px solid rgba(148, 163, 184, 0.25)",
          borderRadius: "14px",
          padding: "32px",
          boxShadow: "0 24px 60px rgba(0, 0, 0, 0.45)",
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "10px", marginBottom: "28px" }}>
          <div style={{ background: "#38bdf8", padding: "12px", borderRadius: "10px" }}>
            <Zap size={24} color="#0f172a" />
          </div>
          <h1 style={{ fontSize: "1.2rem", fontWeight: 700, color: "#f8fafc", margin: 0 }}>CyberIntel EC</h1>
          <p style={{ fontSize: "0.8rem", color: "#cbd5e1", margin: 0 }}>Inicia sesión para continuar</p>
        </div>

        <label style={{ display: "block", fontSize: "0.75rem", color: "#cbd5e1", marginBottom: "6px", fontWeight: 600 }}>Correo</label>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", background: "rgba(15, 23, 42, 0.55)", border: "1px solid rgba(148, 163, 184, 0.25)", borderRadius: "8px", padding: "10px 12px", marginBottom: "16px" }}>
          <Mail size={16} color="#94a3b8" />
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

        <label style={{ display: "block", fontSize: "0.75rem", color: "#cbd5e1", marginBottom: "6px", fontWeight: 600 }}>Contraseña</label>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", background: "rgba(15, 23, 42, 0.55)", border: "1px solid rgba(148, 163, 184, 0.25)", borderRadius: "8px", padding: "10px 12px", marginBottom: "20px" }}>
          <Lock size={16} color="#94a3b8" />
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
          <div style={{ display: "flex", alignItems: "center", gap: "8px", background: "rgba(127, 29, 29, 0.65)", border: "1px solid #ef4444", color: "#fecaca", fontSize: "0.8rem", padding: "10px 12px", borderRadius: "8px", marginBottom: "16px" }}>
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
