import { AppIcon } from "./AppIcon";

type ShellHeaderProps = {
  title: string;
  description: string;
  onRefresh: () => void;
  onOpenHelp: () => void;
  onToggleTheme: () => void;
  theme: "light" | "dark";
  onResetDemo?: () => void;
  staticDemoMode?: boolean;
};

export function ShellHeader({
  title,
  description,
  onRefresh,
  onOpenHelp,
  onToggleTheme,
  theme,
  onResetDemo,
  staticDemoMode = false
}: ShellHeaderProps) {
  const nextThemeLabel = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";

  return (
    <header className="shell-header" data-testid="shell-header">
      <div className="shell-titles">
        <h1 className="shell-title">{title}</h1>
        <p className="shell-subtitle">{description}</p>
      </div>
      {staticDemoMode ? (
        <span className="pill pill-accent" data-testid="static-demo-pill">
          Static demo
        </span>
      ) : null}
      <div className="shell-actions">
        {staticDemoMode && onResetDemo ? (
          <button
            type="button"
            className="ghost"
            data-testid="reset-demo-button"
            onClick={onResetDemo}
            title="Reset static demo"
          >
            <span className="button-with-icon">
              <AppIcon name="undo" className="app-icon-sm" />
              <span>Reset demo</span>
            </span>
          </button>
        ) : null}
        <button
          type="button"
          className="ghost icon-only-button"
          data-testid="refresh-button"
          onClick={onRefresh}
          aria-label="Refresh dashboard"
          title="Refresh dashboard"
        >
          <AppIcon name="refresh" />
        </button>
        <button
          type="button"
          className="ghost icon-only-button"
          data-testid="theme-toggle-button"
          onClick={onToggleTheme}
          aria-label={nextThemeLabel}
          title={nextThemeLabel}
        >
          <AppIcon name={theme === "dark" ? "sun" : "moon"} />
        </button>
        <button
          type="button"
          className="ghost icon-only-button"
          data-testid="open-help-button"
          onClick={onOpenHelp}
          aria-label="Open help hub"
          title="Open help hub"
        >
          <AppIcon name="help" />
        </button>
      </div>
    </header>
  );
}
