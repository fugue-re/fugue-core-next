import { useCallback } from "react";
import { api } from "./api";
import { useCommands } from "./commands";
import { formatAddress } from "./format";
import { useSelection } from "./store";
import type { Address } from "./bindings/Address";

interface NavigationOrigin {
  x: number;
  y: number;
}

export function useAddressNavigation(): (
  address: Address,
  origin?: NavigationOrigin,
) => void {
  const functionEntry = useSelection((state) => state.functionEntry);
  const functionName = useSelection((state) => state.functionName);
  const navigate = useSelection((state) => state.navigate);
  const openMenu = useCommands((state) => state.openMenu);
  const notify = useCommands((state) => state.notify);

  return useCallback(
    (address: Address, origin?: NavigationOrigin) => {
      void api
        .navigation(address)
        .then((target) => {
          const selected =
            target.functions.find((fn) => fn.entry === address) ??
            target.functions.find((fn) => fn.entry === functionEntry) ??
            (target.functions.length === 1 ? target.functions[0] : null);
          if (selected) {
            navigate(selected.entry, selected.name, target.address);
          } else if (target.functions.length > 1) {
            openMenu(
              origin?.x ?? window.innerWidth / 2,
              origin?.y ?? window.innerHeight / 2,
              target.functions.map((fn) => ({
                label: fn.name ?? `function ${formatAddress(fn.entry)}`,
                run: () => navigate(fn.entry, fn.name, target.address),
              })),
            );
          } else {
            navigate(functionEntry, functionName, target.address);
          }
        })
        .catch((error) => notify("err", (error as Error).message));
    },
    [functionEntry, functionName, navigate, notify, openMenu],
  );
}
