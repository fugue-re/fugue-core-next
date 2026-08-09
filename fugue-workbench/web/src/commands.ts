import { create } from "zustand";

export interface MenuItem {
  label: string;
  danger?: boolean;
  run: () => void;
}

export interface PromptConfig {
  title: string;
  initial?: string;
  placeholder?: string;
  submitLabel?: string;
  onSubmit: (value: string) => void;
}

export interface Toast {
  id: number;
  kind: "ok" | "err";
  message: string;
}

interface CommandsState {
  menu: { x: number; y: number; items: MenuItem[] } | null;
  prompt: PromptConfig | null;
  toasts: Toast[];
  openMenu: (x: number, y: number, items: MenuItem[]) => void;
  closeMenu: () => void;
  openPrompt: (config: PromptConfig) => void;
  closePrompt: () => void;
  notify: (kind: "ok" | "err", message: string) => void;
  dismiss: (id: number) => void;
}

let toastSeq = 0;

export const useCommands = create<CommandsState>((set) => ({
  menu: null,
  prompt: null,
  toasts: [],
  openMenu: (x, y, items) => set({ menu: { x, y, items } }),
  closeMenu: () => set({ menu: null }),
  openPrompt: (config) => set({ prompt: config, menu: null }),
  closePrompt: () => set({ prompt: null }),
  notify: (kind, message) => {
    const id = ++toastSeq;
    set((state) => ({ toasts: [...state.toasts, { id, kind, message }] }));
    window.setTimeout(() => set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) })), 4200);
  },
  dismiss: (id) => set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) })),
}));
