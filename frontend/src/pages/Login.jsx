import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useSession } from "../lib/session";

export function Login() {
  const { login } = useSession();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(email, password);
      navigate("/overview");
    } catch (err) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-box" onSubmit={handleSubmit}>
        <div className="brand">SentriMeshAstra</div>
        <div className="brand-sub">AI SECURITY TEAM PLATFORM</div>
        <p className="muted">
          Sign in as the platform admin, or as your company's designated security holder.
        </p>
        <label>Email</label>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        {error && <div className="error-text">{error}</div>}
        <button className="primary" type="submit" style={{ width: "100%", marginTop: 20 }} disabled={loading}>
          {loading ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
