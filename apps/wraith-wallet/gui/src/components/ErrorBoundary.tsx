import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  /// Called when an error is caught — used to surface the failure to
  /// telemetry / the host shell. Optional.
  onError?: (err: Error, info: ErrorInfo) => void;
  /// What to render in place of the crashed subtree. Receives the
  /// error and a `reset` callback that re-mounts the children.
  fallback?: (err: Error, reset: () => void) => ReactNode;
  children: ReactNode;
}

interface State {
  err: Error | null;
}

/// Catch render-time errors in the subtree so a single screen's bad
/// state can't blank the whole app. Used to wrap <main>'s active
/// screen — the nav, header, and other screens stay reachable even
/// if the current screen blew up. (E.g. a stale shape mismatch in a
/// daemon response that crashed the renderer before the rest of
/// React could finish mounting.)
export class ErrorBoundary extends Component<Props, State> {
  state: State = { err: null };

  static getDerivedStateFromError(err: Error): State {
    return { err };
  }

  componentDidCatch(err: Error, info: ErrorInfo) {
    this.props.onError?.(err, info);
    // Surface in console as well — devs poking at the webview's
    // DevTools will see the original stack alongside React's wrap.
    console.error("[ErrorBoundary]", err, info);
  }

  reset = () => {
    this.setState({ err: null });
  };

  render() {
    if (this.state.err) {
      if (this.props.fallback) {
        return this.props.fallback(this.state.err, this.reset);
      }
      return (
        <div className="screen">
          <div className="card error-card">
            <div className="eyebrow eyebrow-fail">screen crashed</div>
            <h2>Something went wrong on this screen.</h2>
            <p className="muted">
              The rest of the app is still running — switch to another tab
              and come back, or click Retry below to re-mount this one.
            </p>
            <pre className="error-details">{this.state.err.message}</pre>
            <button className="btn btn-primary" onClick={this.reset}>
              Retry
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
