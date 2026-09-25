import { create } from "zustand";
import type { Address } from "./bindings/Address";

interface Selection {
  functionEntry: Address | null;
  functionName: string | null;
  cursor: Address | null;
  hover: Address | null;
  ilForm: string;
  previousLocations: NavigationLocation[];
  nextLocations: NavigationLocation[];
  selectFunction: (entry: Address, name: string | null) => void;
  navigate: (entry: Address | null, name: string | null, cursor: Address) => void;
  navigateBack: () => void;
  navigateForward: () => void;
  setCursor: (address: Address | null) => void;
  setHover: (address: Address | null) => void;
  setIlForm: (form: string) => void;
}

interface NavigationLocation {
  functionEntry: Address | null;
  functionName: string | null;
  cursor: Address;
}

function location(state: Selection): NavigationLocation | null {
  if (state.cursor === null) return null;
  return {
    functionEntry: state.functionEntry,
    functionName: state.functionName,
    cursor: state.cursor,
  };
}

function sameLocation(left: NavigationLocation | null, right: NavigationLocation): boolean {
  return left?.functionEntry === right.functionEntry && left.cursor === right.cursor;
}

function navigate(state: Selection, target: NavigationLocation): Partial<Selection> {
  const current = location(state);
  if (sameLocation(current, target)) return {};
  return {
    ...target,
    previousLocations: current
      ? [...state.previousLocations, current]
      : state.previousLocations,
    nextLocations: [],
  };
}

export const useSelection = create<Selection>((set) => ({
  functionEntry: null,
  functionName: null,
  cursor: null,
  hover: null,
  ilForm: "fugue.ecode.cfg",
  previousLocations: [],
  nextLocations: [],
  selectFunction: (entry, name) =>
    set((state) => navigate(state, { functionEntry: entry, functionName: name, cursor: entry })),
  navigate: (entry, name, cursor) =>
    set((state) => navigate(state, { functionEntry: entry, functionName: name, cursor })),
  navigateBack: () =>
    set((state) => {
      const target = state.previousLocations.at(-1);
      if (!target) return {};
      const current = location(state);
      return {
        ...target,
        previousLocations: state.previousLocations.slice(0, -1),
        nextLocations: current ? [current, ...state.nextLocations] : state.nextLocations,
      };
    }),
  navigateForward: () =>
    set((state) => {
      const [target, ...nextLocations] = state.nextLocations;
      if (!target) return {};
      const current = location(state);
      return {
        ...target,
        previousLocations: current
          ? [...state.previousLocations, current]
          : state.previousLocations,
        nextLocations,
      };
    }),
  setCursor: (address) => set({ cursor: address }),
  setHover: (address) => set({ hover: address }),
  setIlForm: (form) => set({ ilForm: form }),
}));
