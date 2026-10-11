import type { ReactNode } from "react";

type RuleCardProps = {
  variant?: "base" | "network" | "url";
  className?: string;
  children: ReactNode;
  testId?: string;
};

export function RuleCard({ variant = "base", className, children, testId }: RuleCardProps) {
  return (
    <div
      className={`rule-card rule-card-${variant}${className ? ` ${className}` : ""}`}
      data-testid={testId}
    >
      {children}
    </div>
  );
}
