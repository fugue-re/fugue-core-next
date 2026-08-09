import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { useSelection } from "../store";
import { VirtualList } from "../components/VirtualList";
import { QueryState } from "../components/common";
import { formatAddress } from "../format";
import type { SymbolRow } from "../bindings/SymbolRow";

export function SymbolsPanel() {
  const { data, isLoading, error } = useQuery({ queryKey: ["symbols"], queryFn: api.symbols });
  const setCursor = useSelection((state) => state.setCursor);
  const [filter, setFilter] = useState("");

  const rows = useMemo(() => {
    const all = data ?? [];
    if (!filter.trim()) return all;
    const needle = filter.toLowerCase();
    return all.filter(
      (sym) => sym.name.toLowerCase().includes(needle) || sym.address.includes(needle),
    );
  }, [data, filter]);

  return (
    <div className="pane" style={{ border: "none" }}>
      <div className="searchbar">
        <input
          placeholder="filter symbols…"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
        />
      </div>
      <div className="pane-body">
        <QueryState
          isLoading={isLoading}
          error={error}
          empty={rows.length === 0}
          emptyTitle={data && data.length ? "no matches" : "no symbols"}
        >
          <VirtualList
            items={rows}
            rowHeight={24}
            row={(sym: SymbolRow) => (
              <div className="vrow" onClick={() => setCursor(sym.address)}>
                <span className="addr">{formatAddress(sym.address)}</span>
                <span className="name">{sym.name}</span>
                <span className="flags">
                  {sym.import && <span className="chip extern">imp</span>}
                  {sym.export && <span className="chip thunk">exp</span>}
                  {sym.data && <span className="chip data">data</span>}
                </span>
              </div>
            )}
          />
        </QueryState>
      </div>
    </div>
  );
}
