import { Component, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  /** Optional label used in the error message to identify which panel failed. */
  label?: string;
}

interface State {
  hasError: boolean;
  message: string;
}

/**
 * Catches any render-time JavaScript exceptions in its subtree and shows a
 * contained error card instead of a blank white screen.
 *
 * Wrap individual panels (or the whole app shell) so that one panel's failure
 * does not destroy neighbouring panels.
 */
export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, message: "" };
  }

  static getDerivedStateFromError(error: unknown): State {
    const message = error instanceof Error ? error.message : String(error);
    return { hasError: true, message };
  }

  componentDidCatch(error: unknown, info: { componentStack?: string | null }) {
    // Log to console so developers can see the full stack in browser devtools.
    console.error("[ErrorBoundary] caught render error:", error, info.componentStack);
  }

  handleReload() {
    window.location.reload();
  }

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    const label = this.props.label ?? "This panel";
    return (
      <div className="error-boundary-fallback" role="alert">
        <div className="error-boundary-card">
          <h3 className="error-boundary-title">⚠ {label} encountered an error</h3>
          <p className="error-boundary-message">
            {this.state.message || "An unexpected error occurred."}
          </p>
          <p className="error-boundary-hint">
            Other panels are unaffected. You can{" "}
            <button type="button" className="link-button" onClick={this.handleReload.bind(this)}>
              reload the page
            </button>{" "}
            to restore this panel.
          </p>
        </div>
      </div>
    );
  }
}
