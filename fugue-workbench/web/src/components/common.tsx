import { type ReactNode, useState } from "react";
import type { IlToken } from "../bindings/IlToken";
import type { Address } from "../bindings/Address";

export function IlTokens({
  tokens,
  onNavigate,
}: {
  tokens: IlToken[];
  onNavigate?: (address: Address) => void;
}): ReactNode {
  return tokens.map((token, index) => {
    const navigable = token.nav !== null && onNavigate !== undefined;
    return (
      <span
        key={index}
        className={`il-t-${token.kind}${navigable ? " nav" : ""}`}
        title={token.title ?? undefined}
        onClick={
          navigable
            ? (event) => {
                event.stopPropagation();
                onNavigate!(token.nav!);
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

const OPERAND_PATTERN = /(0x[0-9a-fA-F]+|[A-Z][A-Z0-9]*|[[\]{}(),.:+*-]|\s+|[^\s]+?)/g;

export function tokeniseOperands(text: string): ReactNode[] {
  const matches = text.match(OPERAND_PATTERN);
  if (!matches) return [text];
  return matches.map((token, index) => {
    if (/^0x[0-9a-fA-F]+$/.test(token)) {
      return (
        <span key={index} className="t-imm">
          {token}
        </span>
      );
    }
    if (/^[A-Z][A-Z0-9]*$/.test(token)) {
      return (
        <span key={index} className="t-reg">
          {token}
        </span>
      );
    }
    if (/^[[\]{}(),.:+*-]$/.test(token)) {
      return (
        <span key={index} className="t-punct">
          {token}
        </span>
      );
    }
    return <span key={index}>{token}</span>;
  });
}
