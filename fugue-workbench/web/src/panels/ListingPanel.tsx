import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { useSelection } from "../store";
import { useCommands } from "../commands";
import { useMutations } from "../mutations";
import { VirtualList } from "../components/VirtualList";
import { QueryState, Placeholder, tokeniseOperands } from "../components/common";
import { formatAddress } from "../format";
import type { ListingLine } from "../bindings/ListingLine";

export function ListingPanel() {
  const entry = useSelection((state) => state.functionEntry);
  const cursor = useSelection((state) => state.cursor);
  const hover = useSelection((state) => state.hover);
  const setCursor = useSelection((state) => state.setCursor);
  const setHover = useSelection((state) => state.setHover);
  const openMenu = useCommands((state) => state.openMenu);
  const openPrompt = useCommands((state) => state.openPrompt);
  const mutations = useMutations();

  const { data, isLoading, error } = useQuery({
    queryKey: ["listing", entry],
    queryFn: () => api.listing(entry!),
    enabled: entry !== null,
  });

  if (!entry) {
    return <Placeholder title="no function selected" hint="Pick a function to disassemble." />;
  }

  const lines = data ?? [];
  const activeIndex = cursor === null ? -1 : lines.findIndex((line) => line.address === cursor);

  return (
    <QueryState isLoading={isLoading} error={error} empty={lines.length === 0} emptyTitle="not mapped">
      <VirtualList
        items={lines}
        rowHeight={24}
        activeIndex={activeIndex}
        row={(line: ListingLine) => {
          const active = line.address === cursor;
          const linked = !active && line.address === hover;
          return (
            <div
              className={`listing-row${line.decoded ? "" : " undecoded"}${active ? " active" : ""}${linked ? " linked" : ""}`}
              onMouseEnter={() => setHover(line.address)}
              onMouseLeave={() => setHover(null)}
              onClick={() => setCursor(line.address)}
              onContextMenu={(event) => {
                event.preventDefault();
                setCursor(line.address);
                openMenu(event.clientX, event.clientY, [
                  {
                    label: "Rename…",
                    run: () =>
                      openPrompt({
                        title: `rename ${formatAddress(line.address)}`,
                        placeholder: "symbol name",
                        submitLabel: "Rename",
                        onSubmit: (name) => mutations.rename(line.address, name),
                      }),
                  },
                  {
                    label: "Define function here",
                    run: () => mutations.defineFunction(line.address),
                  },
                  {
                    label: "Patch bytes…",
                    run: () =>
                      openPrompt({
                        title: `patch ${formatAddress(line.address)}`,
                        initial: line.bytes,
                        placeholder: "hex bytes",
                        submitLabel: "Patch",
                        onSubmit: (bytes) => mutations.patch(line.address, bytes),
                      }),
                  },
                ]);
              }}
            >
              <span className="l-addr">{line.address.split(":").pop()}</span>
              <span className="l-bytes">{line.bytes}</span>
              <span className="l-mnem">{line.mnemonic}</span>
              <span className="l-ops">{tokeniseOperands(line.operands)}</span>
            </div>
          );
        }}
      />
    </QueryState>
  );
}
