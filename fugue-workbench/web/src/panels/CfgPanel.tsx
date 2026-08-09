import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import ELK from "elkjs/lib/elk.bundled.js";
import { api } from "../api";
import { useSelection } from "../store";
import { Placeholder, Loading } from "../components/common";
import type { CfgResponse } from "../bindings/CfgResponse";
import type { CfgBlock } from "../bindings/CfgBlock";

const elk = new ELK();

const CHAR_WIDTH = 6.9;
const LINE_HEIGHT = 15;
const HEADER_HEIGHT = 22;
const MAX_NODE_LINES = 14;
const MAX_NODE_WIDTH = 540;

interface Point {
  x: number;
  y: number;
}

interface LaidOutNode {
  block: CfgBlock;
  x: number;
  y: number;
  width: number;
  height: number;
}

interface LaidOutEdge {
  points: Point[];
  taken: boolean;
  fallThrough: boolean;
  computed: boolean;
}

interface Layout {
  nodes: LaidOutNode[];
  edges: LaidOutEdge[];
  width: number;
  height: number;
}

function blockText(block: CfgBlock): string[] {
  return block.lines
    .slice(0, MAX_NODE_LINES)
    .map((line) => `${line.address.split(":").pop()}  ${line.mnemonic} ${line.operands}`.trim());
}

function nodeSize(block: CfgBlock): { width: number; height: number } {
  const texts = blockText(block);
  const longest = texts.reduce((max, text) => Math.max(max, text.length), 8);
  const extra = block.lines.length > MAX_NODE_LINES ? 1 : 0;
  const width = Math.min(MAX_NODE_WIDTH, Math.max(140, longest * CHAR_WIDTH + 26));
  const height = HEADER_HEIGHT + (texts.length + extra) * LINE_HEIGHT + 10;
  return { width, height };
}

async function layout(cfg: CfgResponse): Promise<Layout> {
  const sized = new Map(cfg.blocks.map((block) => [block.id, nodeSize(block)]));
  const graph = {
    id: "root",
    layoutOptions: {
      "elk.algorithm": "layered",
      "elk.direction": "DOWN",
      "elk.layered.spacing.nodeNodeBetweenLayers": "36",
      "elk.spacing.nodeNode": "28",
      "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
    },
    children: cfg.blocks.map((block) => ({ id: String(block.id), ...sized.get(block.id)! })),
    edges: cfg.edges.map((edge, index) => ({
      id: `e${index}`,
      sources: [String(edge.from)],
      targets: [String(edge.to)],
    })),
  };

  const result = (await elk.layout(graph as never)) as never as {
    width: number;
    height: number;
    children: { id: string; x: number; y: number; width: number; height: number }[];
    edges: { sections?: { startPoint: Point; endPoint: Point; bendPoints?: Point[] }[] }[];
  };

  const byId = new Map(cfg.blocks.map((block) => [String(block.id), block]));
  const nodes = result.children.map((child) => ({
    block: byId.get(child.id)!,
    x: child.x,
    y: child.y,
    width: child.width,
    height: child.height,
  }));

  const edges = result.edges.map((edge, index) => {
    const section = edge.sections?.[0];
    const points = section
      ? [section.startPoint, ...(section.bendPoints ?? []), section.endPoint]
      : [];
    return {
      points,
      taken: cfg.edges[index].taken,
      fallThrough: cfg.edges[index].fall_through,
      computed: cfg.edges[index].computed,
    };
  });

  return { nodes, edges, width: result.width, height: result.height };
}

function edgeColour(edge: LaidOutEdge): string {
  if (edge.taken) return "var(--accent-edge)";
  if (edge.computed) return "var(--link)";
  return "var(--hair-2)";
}

export function CfgPanel() {
  const entry = useSelection((state) => state.functionEntry);
  const cursor = useSelection((state) => state.cursor);
  const setCursor = useSelection((state) => state.setCursor);

  const { data, isLoading } = useQuery({
    queryKey: ["cfg", entry],
    queryFn: () => api.cfg(entry!),
    enabled: entry !== null,
  });

  const [result, setResult] = useState<Layout | null>(null);
  const [view, setView] = useState({ x: 40, y: 40, k: 1 });
  const drag = useRef<{ x: number; y: number } | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!data) {
      setResult(null);
      return;
    }
    let cancelled = false;
    layout(data).then((laid) => {
      if (!cancelled) setResult(laid);
    });
    return () => {
      cancelled = true;
    };
  }, [data]);

  const fit = (laid: Layout) => {
    const wrap = wrapRef.current;
    if (!wrap) return;
    const w = wrap.clientWidth;
    const h = wrap.clientHeight;
    const k = Math.max(0.2, Math.min(1.3, (w - 56) / laid.width, (h - 56) / laid.height));
    setView({
      k,
      x: Math.max(28, (w - laid.width * k) / 2),
      y: Math.max(28, (h - laid.height * k) / 2),
    });
  };

  useEffect(() => {
    if (result) fit(result);
  }, [result]);

  const activeBlock = useMemo(() => {
    if (!result || !cursor) return null;
    const found = result.nodes.find((node) => node.block.lines.some((line) => line.address === cursor));
    return found ? found.block.id : null;
  }, [result, cursor]);

  if (!entry) return <Placeholder title="no function selected" hint="Pick a function to graph." />;
  if (isLoading || !result) return <Loading />;

  const onWheel = (event: React.WheelEvent) => {
    event.preventDefault();
    const factor = event.deltaY < 0 ? 1.12 : 0.89;
    setView((prev) => {
      const k = Math.min(2.4, Math.max(0.2, prev.k * factor));
      const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
      const px = event.clientX - rect.left;
      const py = event.clientY - rect.top;
      return {
        k,
        x: px - ((px - prev.x) * k) / prev.k,
        y: py - ((py - prev.y) * k) / prev.k,
      };
    });
  };

  return (
    <div
      className="cfg-wrap"
      ref={wrapRef}
      onWheel={onWheel}
      onMouseDown={(event) => (drag.current = { x: event.clientX - view.x, y: event.clientY - view.y })}
      onMouseMove={(event) => {
        if (drag.current)
          setView((prev) => ({ ...prev, x: event.clientX - drag.current!.x, y: event.clientY - drag.current!.y }));
      }}
      onMouseUp={() => (drag.current = null)}
      onMouseLeave={() => (drag.current = null)}
    >
      <svg width="100%" height="100%">
        <defs>
          <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill="var(--text-3)" />
          </marker>
        </defs>
        <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
          {result.edges.map((edge, index) => (
            <polyline
              key={index}
              points={edge.points.map((point) => `${point.x},${point.y}`).join(" ")}
              fill="none"
              stroke={edgeColour(edge)}
              strokeWidth={1.2}
              strokeDasharray={edge.computed ? "4 3" : undefined}
              markerEnd="url(#arrow)"
            />
          ))}
          {result.nodes.map((node) => {
            const texts = blockText(node.block);
            const overflow = node.block.lines.length - texts.length;
            const isEntry = node.block.entry_block;
            const isActive = node.block.id === activeBlock;
            return (
              <g
                key={node.block.id}
                transform={`translate(${node.x},${node.y})`}
                onClick={() => node.block.lines[0] && setCursor(node.block.lines[0].address)}
                style={{ cursor: "pointer" }}
              >
                <rect
                  className={`cfg-node${isEntry ? " entry" : ""}`}
                  width={node.width}
                  height={node.height}
                  rx={5}
                  stroke={isActive ? "var(--accent)" : undefined}
                  strokeWidth={isActive ? 1.6 : undefined}
                />
                <rect className="cfg-node-head" width={node.width} height={HEADER_HEIGHT} rx={5} />
                <text x={9} y={15} fill={isEntry ? "var(--accent)" : "var(--text-2)"} fontWeight={600}>
                  {node.block.entry.split(":").pop()}
                  {isEntry ? "  ⏻ entry" : ""}
                </text>
                {texts.map((text, line) => (
                  <text
                    key={line}
                    x={9}
                    y={HEADER_HEIGHT + 12 + line * LINE_HEIGHT}
                    fill="var(--text)"
                  >
                    {text.length > 74 ? text.slice(0, 73) + "…" : text}
                  </text>
                ))}
                {overflow > 0 && (
                  <text
                    x={9}
                    y={HEADER_HEIGHT + 12 + texts.length * LINE_HEIGHT}
                    fill="var(--text-3)"
                  >
                    +{overflow} more
                  </text>
                )}
              </g>
            );
          })}
        </g>
      </svg>
      <div className="cfg-hud">
        <button onClick={() => setView((v) => ({ ...v, k: Math.min(2.4, v.k * 1.15) }))}>+</button>
        <button onClick={() => setView((v) => ({ ...v, k: Math.max(0.2, v.k * 0.87) }))}>−</button>
        <button onClick={() => fit(result)}>⤢</button>
      </div>
    </div>
  );
}
