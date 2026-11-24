import type { ReactNode } from "react";
import type { Loadable } from "@/lib/useApi";

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="stack" role="status" aria-live="polite">
      <span className="sr-only">{label}</span>
      <div className="skeleton" style={{ width: "60%" }} />
      <div className="skeleton" style={{ width: "85%" }} />
      <div className="skeleton" style={{ width: "40%" }} />
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="state state-error" role="alert">
      <p>Request failed: {message}</p>
      {onRetry && (
        <p style={{ marginTop: 12 }}>
          <button className="btn" onClick={onRetry}>
            Try again
          </button>
        </p>
      )}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="state">{children}</div>;
}

export function Load<T>({
  value,
  onRetry,
  children,
}: {
  value: Loadable<T>;
  onRetry?: () => void;
  children: (data: T) => ReactNode;
}) {
  if (value.state === "loading") return <Loading />;
  if (value.state === "error") return <ErrorState message={value.message} onRetry={onRetry} />;
  return <>{children(value.data)}</>;
}
