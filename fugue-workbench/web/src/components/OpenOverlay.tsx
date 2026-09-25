import { useRef, useState } from "react";
import { useOpenBinary } from "../open";

export function OpenOverlay() {
  const open = useOpenBinary();
  const inputRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [drag, setDrag] = useState(false);

  const handle = async (file: File | null | undefined) => {
    if (!file) return;
    setBusy(true);
    await open(file);
    setBusy(false);
  };

  return (
    <div
      className={`open-overlay${drag ? " drag" : ""}`}
      onClick={() => inputRef.current?.click()}
      onDragOver={(event) => {
        event.preventDefault();
        setDrag(true);
      }}
      onDragLeave={() => setDrag(false)}
      onDrop={(event) => {
        event.preventDefault();
        setDrag(false);
        handle(event.dataTransfer.files[0]);
      }}
    >
      <input
        ref={inputRef}
        type="file"
        style={{ display: "none" }}
        onChange={(event) => handle(event.target.files?.[0])}
      />
      {busy ? (
        <div className="spinner" />
      ) : (
        <>
          <div className="open-glyph">⊕</div>
          <div className="open-title">open a binary</div>
          <div className="open-hint">drop an ELF, PE, or Mach-O here, or click to browse</div>
        </>
      )}
    </div>
  );
}
