import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { useSelection } from "../store";
import { Placeholder } from "../components/common";
import type { XrefRow } from "../bindings/XrefRow";

function kind(xref: XrefRow): string {
  if (xref.call) return "call";
  if (xref.jump) return "jump";
  if (xref.data) return "data";
  return "flow";
}

export function XrefsPanel() {
  const cursor = useSelection((state) => state.cursor);
  const setCursor = useSelection((state) => state.setCursor);

  const incoming = useQuery({
    queryKey: ["xrefs", "to", cursor],
    queryFn: () => api.xrefsTo(cursor!),
    enabled: cursor !== null,
  });
  const outgoing = useQuery({
    queryKey: ["xrefs", "from", cursor],
    queryFn: () => api.xrefsFrom(cursor!),
    enabled: cursor !== null,
  });

  if (!cursor) {
    return <Placeholder title="no address selected" hint="Select an instruction to see its cross-references." />;
  }

  const section = (label: string, rows: XrefRow[], other: (xref: XrefRow) => string) => (
    <>
      <div className="micro-label" style={{ padding: "8px 12px 4px" }}>
        {label} <span style={{ color: "var(--text-2)" }}>{rows.length}</span>
      </div>
      {rows.map((xref, index) => (
        <div className="vrow" key={index} onClick={() => setCursor(other(xref))}>
          <span className="addr">{other(xref).split(":").pop()}</span>
          <span className="name" style={{ color: "var(--text-2)" }}>
            {other(xref)}
          </span>
          <span className="flags">
            <span className={`chip${xref.call ? " thunk" : xref.data ? " data" : ""}`}>{kind(xref)}</span>
          </span>
        </div>
      ))}
    </>
  );

  return (
    <div className="vtable">
      {section("references to", incoming.data ?? [], (xref) => xref.from)}
      {section("references from", outgoing.data ?? [], (xref) => xref.to)}
    </div>
  );
}
