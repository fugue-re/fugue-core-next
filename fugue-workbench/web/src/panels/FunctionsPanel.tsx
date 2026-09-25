import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { useSelection } from "../store";
import { useCommands } from "../commands";
import { useMutations } from "../mutations";
import { VirtualList } from "../components/VirtualList";
import { QueryState } from "../components/common";
import { formatAddress, offsetOf } from "../format";
import type { FunctionRow } from "../bindings/FunctionRow";

export function FunctionsPanel() {
  const { data, isLoading, error } = useQuery({ queryKey: ["functions"], queryFn: api.functions });
  const selected = useSelection((state) => state.functionEntry);
  const select = useSelection((state) => state.selectFunction);
  const openMenu = useCommands((state) => state.openMenu);
  const openPrompt = useCommands((state) => state.openPrompt);
  const mutations = useMutations();
  const [filter, setFilter] = useState("");

  const rows = useMemo(() => {
    const all = data ?? [];
    if (!filter.trim()) return all;
    const needle = filter.toLowerCase();
    return all.filter(
      (fn) => fn.entry.includes(needle) || (fn.name ?? "").toLowerCase().includes(needle),
    );
  }, [data, filter]);

  return (
    <div className="pane" style={{ border: "none" }}>
      <div className="searchbar">
        <input
          placeholder="filter functions…"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
        />
      </div>
      <div className="pane-body">
        <QueryState
          isLoading={isLoading}
          error={error}
          empty={rows.length === 0}
          emptyTitle={data && data.length ? "no matches" : "no functions"}
        >
          <VirtualList
            items={rows}
            rowHeight={24}
            row={(fn: FunctionRow) => (
              <div
                className={`vrow${fn.entry === selected ? " active" : ""}`}
                onClick={() => select(fn.entry, fn.name)}
                onContextMenu={(event) => {
                  event.preventDefault();
                  select(fn.entry, fn.name);
                  openMenu(event.clientX, event.clientY, [
                    {
                      label: "Rename…",
                      run: () =>
                        openPrompt({
                          title: `rename ${formatAddress(fn.entry)}`,
                          initial: fn.name ?? "",
                          placeholder: "function name",
                          submitLabel: "Rename",
                          onSubmit: (name) => mutations.rename(fn.entry, name),
                        }),
                    },
                    {
                      label: "Undefine function",
                      danger: true,
                      run: () => mutations.undefineFunction(fn.entry),
                    },
                  ]);
                }}
              >
                <span className="addr">{formatAddress(fn.entry)}</span>
                <span className={`name${fn.name ? "" : " unnamed"}`}>
                  {fn.name ?? "sub_" + offsetOf(fn.entry).replace("0x", "")}
                </span>
                <span className="flags">
                  {fn.external && <span className="chip extern">ext</span>}
                  {fn.thunk && <span className="chip thunk">thunk</span>}
                  {fn.non_returning && <span className="chip noret">noret</span>}
                </span>
              </div>
            )}
          />
        </QueryState>
      </div>
    </div>
  );
}
