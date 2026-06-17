import type { ReactNode } from "react";

export function LoadingState({ label }: { label: string }) {
  return <div className="state-card">{label}...</div>;
}

export function ErrorState({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return <div className="state-card error">{message}</div>;
}

export function EmptyState({ title }: { title: string }) {
  return <div className="state-card muted">{title}</div>;
}

export function StatCard({ label, value, tone }: { label: string; value: ReactNode; tone?: "hot" }) {
  return (
    <article className={`stat-card ${tone ?? ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}
