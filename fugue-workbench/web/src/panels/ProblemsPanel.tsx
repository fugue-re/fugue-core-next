import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { useSelection } from "../store";
import { VirtualList } from "../components/VirtualList";
import { QueryState } from "../components/common";
import { formatAddress } from "../format";
import type { ProblemRow } from "../bindings/ProblemRow";

export function ProblemsPanel() {
  const { data, isLoading, error } = useQuery({ queryKey: ["problems"], queryFn: api.problems });
  const setCursor = useSelection((state) => state.setCursor);
  const rows = data ?? [];

  return (
    <QueryState
      isLoading={isLoading}
      error={error}
      empty={rows.length === 0}
      emptyTitle="no problems reported"
    >
      <VirtualList
        items={rows}
        rowHeight={24}
        row={(problem: ProblemRow) => (
          <div
            className="vrow"
            onClick={() => problem.address && setCursor(problem.address)}
          >
            <span className="addr">{problem.address ? formatAddress(problem.address) : "—"}</span>
            <span className="name">{problem.kind}</span>
            <span className="flags">
              {problem.attempts > 0 && <span className="chip">×{problem.attempts}</span>}
            </span>
          </div>
        )}
      />
    </QueryState>
  );
}
