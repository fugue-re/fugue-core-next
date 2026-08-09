import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { Address } from "./bindings/Address";
import type { ChangeEvent } from "./bindings/ChangeEvent";
import type { CfgResponse } from "./bindings/CfgResponse";
import type { FormInfo } from "./bindings/FormInfo";
import type { FunctionRow } from "./bindings/FunctionRow";
import type { IlResponse } from "./bindings/IlResponse";
import type { ListingLine } from "./bindings/ListingLine";
import type { MetaResponse } from "./bindings/MetaResponse";
import type { MetricsResponse } from "./bindings/MetricsResponse";
import type { MutationResponse } from "./bindings/MutationResponse";
import type { ProblemRow } from "./bindings/ProblemRow";
import type { SegmentRow } from "./bindings/SegmentRow";
import type { SwitchRow } from "./bindings/SwitchRow";
import type { SymbolRow } from "./bindings/SymbolRow";
import type { XrefRow } from "./bindings/XrefRow";

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(path);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error ?? `request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error ?? `request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  meta: () => fetchJson<MetaResponse>("/api/meta"),
  functions: () => fetchJson<FunctionRow[]>("/api/functions"),
  symbols: () => fetchJson<SymbolRow[]>("/api/symbols"),
  problems: () => fetchJson<ProblemRow[]>("/api/problems"),
  switches: () => fetchJson<SwitchRow[]>("/api/switches"),
  segments: () => fetchJson<SegmentRow[]>("/api/segments"),
  forms: () => fetchJson<FormInfo[]>("/api/forms"),
  metrics: () => fetchJson<MetricsResponse>("/api/metrics"),
  listing: (entry: Address) =>
    fetchJson<ListingLine[]>(`/api/listing?entry=${encodeURIComponent(entry)}`),
  il: (entry: Address, form: string) =>
    fetchJson<IlResponse>(`/api/function/${encodeURIComponent(entry)}/il/${encodeURIComponent(form)}`),
  cfg: (entry: Address) => fetchJson<CfgResponse>(`/api/function/${encodeURIComponent(entry)}/cfg`),
  xrefsTo: (address: Address) => fetchJson<XrefRow[]>(`/api/xrefs/to/${encodeURIComponent(address)}`),
  xrefsFrom: (address: Address) =>
    fetchJson<XrefRow[]>(`/api/xrefs/from/${encodeURIComponent(address)}`),
};

export async function openBinary(file: File): Promise<MetaResponse> {
  const form = new FormData();
  form.append("file", file);
  const response = await fetch("/api/open", { method: "POST", body: form });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error ?? `open failed: ${response.status}`);
  }
  return response.json() as Promise<MetaResponse>;
}

export const mutate = {
  rename: (address: Address, name: string) =>
    postJson<MutationResponse>("/api/mutate/rename", { address, name }),
  defineFunction: (address: Address) =>
    postJson<MutationResponse>("/api/mutate/define-function", { address }),
  undefineFunction: (address: Address) =>
    postJson<MutationResponse>("/api/mutate/undefine-function", { address }),
  patch: (address: Address, bytes: string) =>
    postJson<MutationResponse>("/api/mutate/patch", { address, bytes }),
};

const LIVE_KEYS = ["functions", "symbols", "problems", "switches", "segments", "metrics"];

export interface LiveState {
  revision: number;
  connected: boolean;
  lastKinds: string[];
}

export function useLiveChanges(): LiveState {
  const queryClient = useQueryClient();
  const [state, setState] = useState<LiveState>({ revision: 0, connected: false, lastKinds: [] });
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    const url = `${scheme}://${window.location.host}/api/changes`;
    let closed = false;

    const connect = () => {
      const socket = new WebSocket(url);
      socketRef.current = socket;
      socket.onopen = () => setState((prev) => ({ ...prev, connected: true }));
      socket.onclose = () => {
        setState((prev) => ({ ...prev, connected: false }));
        if (!closed) window.setTimeout(connect, 1200);
      };
      socket.onmessage = (event) => {
        const change = JSON.parse(event.data) as ChangeEvent;
        setState({
          revision: Number(change.revision),
          connected: true,
          lastKinds: change.kinds,
        });
        for (const key of LIVE_KEYS) queryClient.invalidateQueries({ queryKey: [key] });
        queryClient.invalidateQueries({ queryKey: ["listing"] });
        queryClient.invalidateQueries({ queryKey: ["il"] });
        queryClient.invalidateQueries({ queryKey: ["cfg"] });
      };
    };

    connect();
    return () => {
      closed = true;
      socketRef.current?.close();
    };
  }, [queryClient]);

  return state;
}
