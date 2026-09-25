import { type ReactNode, useState } from "react";
import type { CodeToken } from "../bindings/CodeToken";
import type { Address } from "../bindings/Address";

export function CodeTokens({
  tokens,
  onNavigate,
}: {
  tokens: CodeToken[];
  onNavigate?: (address: Address, origin?: { x: number; y: number }) => void;
}): ReactNode {
  return tokens.map((token, index) => {
    const navigable = token.nav !== null && onNavigate !== undefined;
    return (
      <span
        key={index}
        className={`code-t-${token.kind}${navigable ? " nav" : ""}`}
        title={token.title ?? undefined}
        onClick={
          navigable
            ? (event) => {
              event.stopPropagation();
                onNavigate!(token.nav!, { x: event.clientX, y: event.clientY });
              }
            : undefined
        }
      >
        {token.text}
      </span>
    );
  });
}

export function Placeholder({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="placeholder">
      <div className="big">{title}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

export function Loading() {
  return (
    <div className="placeholder">
      <div className="spinner" />
    </div>
  );
}

export function QueryState({
  isLoading,
  error,
  empty,
  emptyTitle,
  children,
}: {
  isLoading: boolean;
  error: unknown;
  empty: boolean;
  emptyTitle: string;
  children: ReactNode;
}) {
  if (isLoading) return <Loading />;
  if (error) return <Placeholder title="request failed" hint={String((error as Error).message)} />;
  if (empty) return <Placeholder title={emptyTitle} />;
  return <>{children}</>;
}

interface DockTab {
  id: string;
  label: string;
  count?: number;
  content: ReactNode;
}

export function Dock({ tabs, initial }: { tabs: DockTab[]; initial?: string }) {
  const [active, setActive] = useState(initial ?? tabs[0]?.id);
  const current = tabs.find((tab) => tab.id === active) ?? tabs[0];
  return (
    <div className="pane">
      <div className="tabstrip">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            className={`tab${tab.id === current?.id ? " active" : ""}`}
            onClick={() => setActive(tab.id)}
          >
            {tab.label}
            {tab.count !== undefined && <span className="count">{tab.count}</span>}
          </button>
        ))}
      </div>
      <div className="pane-body">{current?.content}</div>
    </div>
  );
}
