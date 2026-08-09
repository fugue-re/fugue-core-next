import { useQueryClient } from "@tanstack/react-query";
import { openBinary } from "./api";
import { useCommands } from "./commands";

export function useOpenBinary() {
  const queryClient = useQueryClient();
  const notify = useCommands((state) => state.notify);

  return async (file: File) => {
    try {
      const meta = await openBinary(file);
      queryClient.invalidateQueries();
      notify("ok", `opened ${file.name} · ${meta.arch}`);
    } catch (error) {
      notify("err", (error as Error).message);
    }
  };
}
