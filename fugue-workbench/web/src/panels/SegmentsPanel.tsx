import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { useSelection } from "../store";
import { VirtualList } from "../components/VirtualList";
import { QueryState } from "../components/common";
import { formatAddress } from "../format";
import type { SegmentRow } from "../bindings/SegmentRow";

function permission(segment: SegmentRow): string {
  return `${segment.readable ? "r" : "-"}${segment.writable ? "w" : "-"}${segment.executable ? "x" : "-"}`;
}

export function SegmentsPanel() {
  const { data, isLoading, error } = useQuery({ queryKey: ["segments"], queryFn: api.segments });
  const setCursor = useSelection((state) => state.setCursor);
  const rows = data ?? [];

  return (
    <QueryState
      isLoading={isLoading}
      error={error}
      empty={rows.length === 0}
      emptyTitle="no segments"
    >
      <VirtualList
        items={rows}
        rowHeight={24}
        row={(segment: SegmentRow) => (
          <div className="vrow" onClick={() => setCursor(segment.start)}>
            <span className="addr">{formatAddress(segment.start)}</span>
            <span className="name" style={{ color: "var(--tok-punct)" }}>
              {permission(segment)}
            </span>
            <span className="flags" style={{ color: "var(--text-3)" }}>
              {segment.size.toLocaleString()} B
            </span>
          </div>
        )}
      />
    </QueryState>
  );
}
