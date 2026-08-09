import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { useSelection } from "../store";
import { VirtualList } from "../components/VirtualList";
import { QueryState } from "../components/common";
import { formatAddress } from "../format";
import type { SwitchRow } from "../bindings/SwitchRow";

export function SwitchesPanel() {
  const { data, isLoading, error } = useQuery({ queryKey: ["switches"], queryFn: api.switches });
  const setCursor = useSelection((state) => state.setCursor);
  const rows = data ?? [];

  return (
    <QueryState isLoading={isLoading} error={error} empty={rows.length === 0} emptyTitle="no switches">
      <VirtualList
        items={rows}
        rowHeight={24}
        row={(row: SwitchRow) => (
          <div className="vrow" onClick={() => setCursor(row.branch)}>
            <span className="addr">{formatAddress(row.branch)}</span>
            <span className="name" style={{ color: "var(--text-2)" }}>
              {row.cases} case{row.cases === 1 ? "" : "s"}
            </span>
            <span className="flags">
              {row.has_default && <span className="chip">default</span>}
            </span>
          </div>
        )}
      />
    </QueryState>
  );
}
