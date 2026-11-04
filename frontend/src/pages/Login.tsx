import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { apiLogin } from "../api";
import { setToken } from "../auth";
import { Logo } from "../components/Logo";
import { ErrorBox } from "../components/ui";

export function Login() {
  const nav = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const r = await apiLogin(username, password);
      setToken(r.accessToken);
      nav("/");
      window.location.reload();
    } catch (err) {
      setError(err);
    }
  };
  return (
    <div className="login-wrap">
      <div className="sim-banner" role="status">SIMULATED ENVIRONMENT - NO REAL DEVICES ARE BEING SCANNED</div>
      <form className="login" onSubmit={submit}>
        <Logo />
        <div className="project-title">OT Discovery &amp; Probing Console</div>
        <label>Username<input autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} /></label>
        <label>Password<input type="password" autoComplete="current-password" value={password}
          onChange={(e) => setPassword(e.target.value)} /></label>
        <button className="btn btn-primary" disabled={!username || !password}>SIGN IN</button>
        <ErrorBox error={error} />
        <p className="hint">Demo users (synthetic): operator / operator-demo · approver / approver-demo · admin / admin-demo</p>
      </form>
    </div>
  );
}
