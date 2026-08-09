import { useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { useSelection } from "../store";
import { QueryState, Placeholder, IlTokens } from "../components/common";
import { formatAddress } from "../format";
import type { FormInfo } from "../bindings/FormInfo";
import type { FunctionRow } from "../bindings/FunctionRow";
import type { Address } from "../bindings/Address";

function formLabel(id: string): string {
  return id.replace(/^fugue\./, "").replace(/\./g, "·").toUpperCase();
}

export function IlPanel() {
  const entry = useSelection((state) => state.functionEntry);
  const cursor = useSelection((state) => state.cursor);
  const hover = useSelection((state) => state.hover);
  const ilForm = useSelection((state) => state.ilForm);
  const setIlForm = useSelection((state) => state.setIlForm);
  const setCursor = useSelection((state) => state.setCursor);
  const setHover = useSelection((state) => state.setHover);
  const selectFunction = useSelection((state) => state.selectFunction);

  const forms = useQuery({ queryKey: ["forms"], queryFn: api.forms });
  const functions = useQuery({ queryKey: ["functions"], queryFn: api.functions });
  const il = useQuery({
    queryKey: ["il", entry, ilForm],
    queryFn: () => api.il(entry!, ilForm),
    enabled: entry !== null,
  });

  const navigate = (address: Address) => {
    const target = (functions.data ?? []).find((fn: FunctionRow) => fn.entry === address);
    if (target) {
      selectFunction(target.entry, target.name);
    } else {
      setCursor(address);
    }
  };

  const activeRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    activeRef.current?.scrollIntoView({ block: "nearest" });
  }, [cursor, il.data]);

  return (
    <div className="pane" style={{ border: "none" }}>
      <div className="il-toolbar">
        {(forms.data ?? []).map((form: FormInfo) => (
          <button
            key={form.id}
            className={`seg-btn${form.id === ilForm ? " active" : ""}`}
            disabled={!form.renderable}
            title={form.id}
            onClick={() => setIlForm(form.id)}
          >
            {formLabel(form.id)}
          </button>
        ))}
      </div>
      <div className="pane-body">
        {!entry ? (
          <Placeholder title="no function selected" hint="Pick a function to lift." />
        ) : (
          <QueryState
            isLoading={il.isLoading}
            error={il.error}
            empty={(il.data?.lines.length ?? 0) === 0}
            emptyTitle="no il"
          >
            <div className="il-body">
              {(il.data?.lines ?? []).map((line, index) => {
                const active = line.address === cursor;
                const linked = !active && line.address === hover;
                const lead = index === 0 || il.data!.lines[index - 1].address !== line.address;
                return (
                  <div
                    key={index}
                    ref={active && lead ? activeRef : undefined}
                    className={`il-line${active ? " active" : ""}${linked ? " linked" : ""}`}
                    onMouseEnter={() => setHover(line.address)}
                    onMouseLeave={() => setHover(null)}
                    onClick={() => setCursor(line.address)}
                  >
                    <span className="il-addr">{lead ? formatAddress(line.address) : ""}</span>
                    <span className="il-text">
                      <IlTokens tokens={line.tokens} onNavigate={navigate} />
                    </span>
                  </div>
                );
              })}
            </div>
          </QueryState>
        )}
      </div>
    </div>
  );
}
