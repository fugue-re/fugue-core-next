import { Suspense, lazy, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";
import { api, useLiveChanges, type LiveState } from "./api";
import { useSelection } from "./store";
import { useOpenBinary } from "./open";
import { formatAddress } from "./format";
import { Dock, Loading } from "./components/common";
import { CommandLayer } from "./components/CommandLayer";
import { OpenOverlay } from "./components/OpenOverlay";
import { FunctionsPanel } from "./panels/FunctionsPanel";
import { SymbolsPanel } from "./panels/SymbolsPanel";
import { ListingPanel } from "./panels/ListingPanel";
import { IlPanel } from "./panels/IlPanel";
import { XrefsPanel } from "./panels/XrefsPanel";
import { ProblemsPanel } from "./panels/ProblemsPanel";
import { SegmentsPanel } from "./panels/SegmentsPanel";
import { SwitchesPanel } from "./panels/SwitchesPanel";
import { MetricsPanel } from "./panels/MetricsPanel";

const CfgPanel = lazy(() =>
  import("./panels/CfgPanel").then((module) => ({ default: module.CfgPanel })),
);

function TopBar({ live }: { live: LiveState }) {
  const meta = useQuery({ queryKey: ["meta"], queryFn: api.meta });
  const functions = useQuery({
    queryKey: ["functions"],
    queryFn: api.functions,
    enabled: !!meta.data,
  });
  const revision = live.revision || Number(meta.data?.revision ?? 0);
  const open = useOpenBinary();
  const fileRef = useRef<HTMLInputElement>(null);

  return (
    <div className="topbar">
      <div className="brand">
        <span className="mark">fugue</span>
        <span className="sub">workbench</span>
      </div>
      <div className="topbar-facts">
        <div className="fact">
          <span className="k">architecture</span>
          <span className="v accent">{meta.data?.arch ?? "…"}</span>
        </div>
        <div className="fact">
          <span className="k">entry</span>
          <span className="v">
            {meta.data?.entry_point ? formatAddress(meta.data.entry_point) : "—"}
          </span>
        </div>
        <div className="fact">
          <span className="k">functions</span>
          <span className="v">{functions.data?.length ?? "—"}</span>
        </div>
      </div>
      <div className="topbar-spacer" />
      <input
        ref={fileRef}
        type="file"
        style={{ display: "none" }}
        onChange={(event) => event.target.files?.[0] && open(event.target.files[0])}
      />
      <button className="topbar-open" onClick={() => fileRef.current?.click()}>
        Open
      </button>
      <div className="rev-pill">
        <span key={revision} className={`dot${live.connected ? " pulse" : ""}`} style={{ background: live.connected ? undefined : "var(--text-3)", boxShadow: live.connected ? undefined : "none" }} />
      </div>
    </div>
  );
}

function StatusBar({ live }: { live: LiveState }) {
  const meta = useQuery({ queryKey: ["meta"], queryFn: api.meta });
  const functionName = useSelection((state) => state.functionName);
  const functionEntry = useSelection((state) => state.functionEntry);
  const cursor = useSelection((state) => state.cursor);

  return (
    <div className="statusbar">
      <div className="seg">
        function <b>{functionName ?? (functionEntry ? formatAddress(functionEntry) : "—")}</b>
      </div>
      <div className="seg">
        cursor <span className="addr">{cursor ? formatAddress(cursor) : "—"}</span>
      </div>
      <div className="seg" style={{ marginLeft: "auto" }}>
        {meta.data?.language ?? ""}
      </div>
      <div className="seg">{live.connected ? "live" : "offline"}</div>
    </div>
  );
}

export function App() {
  const live = useLiveChanges();
  const meta = useQuery({ queryKey: ["meta"], queryFn: api.meta });
  const showOpen = !meta.isLoading && !meta.data;
  return (
    <div className="app">
      <TopBar live={live} />
      <div className="workspace">
        {showOpen ? (
          <OpenOverlay />
        ) : (
          <PanelGroup direction="vertical">
          <Panel defaultSize={82} minSize={40}>
            <PanelGroup direction="horizontal">
              <Panel defaultSize={22} minSize={12}>
                <Dock
                  tabs={[
                    { id: "functions", label: "Functions", content: <FunctionsPanel /> },
                    { id: "symbols", label: "Symbols", content: <SymbolsPanel /> },
                  ]}
                />
              </Panel>
              <PanelResizeHandle />
              <Panel defaultSize={46} minSize={24}>
                <Dock
                  tabs={[
                    { id: "listing", label: "Listing", content: <ListingPanel /> },
                    {
                      id: "graph",
                      label: "Graph",
                      content: (
                        <Suspense fallback={<Loading />}>
                          <CfgPanel />
                        </Suspense>
                      ),
                    },
                  ]}
                />
              </Panel>
              <PanelResizeHandle />
              <Panel defaultSize={32} minSize={16}>
                <Dock
                  tabs={[
                    { id: "il", label: "Intermediate", content: <IlPanel /> },
                    { id: "xrefs", label: "Cross-refs", content: <XrefsPanel /> },
                  ]}
                />
              </Panel>
            </PanelGroup>
          </Panel>
          <PanelResizeHandle />
          <Panel defaultSize={18} minSize={6}>
            <Dock
              tabs={[
                { id: "problems", label: "Problems", content: <ProblemsPanel /> },
                { id: "segments", label: "Segments", content: <SegmentsPanel /> },
                { id: "switches", label: "Switches", content: <SwitchesPanel /> },
                { id: "metrics", label: "Metrics", content: <MetricsPanel /> },
              ]}
            />
          </Panel>
          </PanelGroup>
        )}
      </div>
      <StatusBar live={live} />
      <CommandLayer />
    </div>
  );
}
