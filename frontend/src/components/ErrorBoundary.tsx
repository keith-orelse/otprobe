import { Component, type ErrorInfo, type ReactNode } from "react";

interface State { error: Error | null }

/** Keeps the shell (sidebar, banner, navigation) usable when a single page fails to render. */
export class ErrorBoundary extends Component<{ children: ReactNode; resetKey: string }, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("Page render failed", error, info.componentStack);
  }

  componentDidUpdate(prev: { resetKey: string }): void {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }

  render(): ReactNode {
    if (!this.state.error) return this.props.children;
    return (
      <div className="error-box page-error">
        <b>This page could not be displayed.</b>
        <div>{this.state.error.message}</div>
        <div className="muted">If you just updated OTProbe, restart the API so the console and API versions match, then reload.</div>
        <button className="btn btn-sm" onClick={() => window.location.reload()}>Reload</button>
      </div>
    );
  }
}
