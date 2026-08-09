import { create } from "zustand";
import type { Address } from "./bindings/Address";

interface Selection {
  functionEntry: Address | null;
  functionName: string | null;
  cursor: Address | null;
  hover: Address | null;
  ilForm: string;
  selectFunction: (entry: Address, name: string | null) => void;
  setCursor: (address: Address | null) => void;
  setHover: (address: Address | null) => void;
  setIlForm: (form: string) => void;
}

export const useSelection = create<Selection>((set) => ({
  functionEntry: null,
  functionName: null,
  cursor: null,
  hover: null,
  ilForm: "fugue.ecode.cfg",
  selectFunction: (entry, name) => set({ functionEntry: entry, functionName: name, cursor: entry }),
  setCursor: (address) => set({ cursor: address }),
  setHover: (address) => set({ hover: address }),
  setIlForm: (form) => set({ ilForm: form }),
}));
