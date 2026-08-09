import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import type { MetricsResponse } from "../bindings/MetricsResponse";

const FIELDS: { key: keyof MetricsResponse; label: string }[] = [
  { key: "dispatches", label: "dispatches" },
  { key: "items_dispatched", label: "items dispatched" },
  { key: "retries", label: "retries" },
  { key: "retries_exhausted", label: "retries exhausted" },
];

export function MetricsPanel() {
  const { data } = useQuery({ queryKey: ["metrics"], queryFn: api.metrics, refetchInterval: 2000 });

  return (
    <div style={{ padding: "14px 16px", display: "grid", gap: 16, gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))" }}>
      {FIELDS.map((field) => (
        <div key={field.key}>
          <div className="micro-label">{field.label}</div>
          <div style={{ fontSize: 22, color: "var(--accent)", fontVariantNumeric: "tabular-nums" }}>
            {data ? Number(data[field.key]).toLocaleString() : "—"}
          </div>
        </div>
      ))}
    </div>
  );
}
