import { useQueryClient } from "@tanstack/react-query";
import { mutate } from "./api";
import { useCommands } from "./commands";
import type { Address } from "./bindings/Address";

export function useMutations() {
  const queryClient = useQueryClient();
  const notify = useCommands((state) => state.notify);

  const run = async (label: string, action: () => Promise<unknown>) => {
    try {
      await action();
      queryClient.invalidateQueries();
      notify("ok", label);
    } catch (error) {
      notify("err", (error as Error).message);
    }
  };

  return {
    rename: (address: Address, name: string) =>
      run(`renamed ${address} → ${name}`, () => mutate.rename(address, name)),
    defineFunction: (address: Address) =>
      run(`defined function at ${address}`, () => mutate.defineFunction(address)),
    undefineFunction: (address: Address) =>
      run(`removed function at ${address}`, () => mutate.undefineFunction(address)),
    patch: (address: Address, bytes: string) =>
      run(`patched ${address}`, () => mutate.patch(address, bytes)),
  };
}
