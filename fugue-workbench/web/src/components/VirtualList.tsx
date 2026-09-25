import { useEffect, useRef, type ReactNode } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

interface VirtualListProps<T> {
  items: T[];
  rowHeight: number;
  row: (item: T, index: number) => ReactNode;
  activeIndex?: number;
}

export function VirtualList<T>({ items, rowHeight, row, activeIndex }: VirtualListProps<T>) {
  const parentRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan: 16,
  });

  useEffect(() => {
    if (activeIndex !== undefined && activeIndex >= 0) {
      virtualizer.scrollToIndex(activeIndex, { align: "auto" });
    }
  }, [activeIndex, virtualizer]);

  return (
    <div ref={parentRef} className="vtable">
      <div style={{ height: virtualizer.getTotalSize(), position: "relative", width: "100%" }}>
        {virtualizer.getVirtualItems().map((virtual) => (
          <div
            key={virtual.key}
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              width: "100%",
              height: virtual.size,
              transform: `translateY(${virtual.start}px)`,
            }}
          >
            {row(items[virtual.index], virtual.index)}
          </div>
        ))}
      </div>
    </div>
  );
}
