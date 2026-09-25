import { useEffect, useState } from "react";
import { useCommands } from "../commands";

function PromptModal() {
  const prompt = useCommands((state) => state.prompt);
  const closePrompt = useCommands((state) => state.closePrompt);
  const [value, setValue] = useState("");

  useEffect(() => {
    setValue(prompt?.initial ?? "");
  }, [prompt]);

  if (!prompt) return null;

  const submit = () => {
    const trimmed = value.trim();
    if (trimmed) prompt.onSubmit(trimmed);
    closePrompt();
  };

  return (
    <div className="modal-scrim" onMouseDown={closePrompt}>
      <div className="modal" onMouseDown={(event) => event.stopPropagation()}>
        <div className="title">{prompt.title}</div>
        <input
          autoFocus
          value={value}
          placeholder={prompt.placeholder}
          onChange={(event) => setValue(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") submit();
            if (event.key === "Escape") closePrompt();
          }}
        />
        <div className="actions">
          <button className="btn" onClick={closePrompt}>
            Cancel
          </button>
          <button className="btn primary" onClick={submit}>
            {prompt.submitLabel ?? "Apply"}
          </button>
        </div>
      </div>
    </div>
  );
}

function ContextMenu() {
  const menu = useCommands((state) => state.menu);
  const closeMenu = useCommands((state) => state.closeMenu);

  useEffect(() => {
    if (!menu) return;
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && closeMenu();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [menu, closeMenu]);

  if (!menu) return null;

  const x = Math.min(menu.x, window.innerWidth - 184);
  const y = Math.min(menu.y, window.innerHeight - menu.items.length * 32 - 16);

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 1000 }} onMouseDown={closeMenu} onContextMenu={(event) => { event.preventDefault(); closeMenu(); }}>
      <div className="ctx-menu" style={{ left: x, top: y }} onMouseDown={(event) => event.stopPropagation()}>
        {menu.items.map((item, index) => (
          <button
            key={index}
            className={`ctx-item${item.danger ? " danger" : ""}`}
            onClick={() => {
              item.run();
              closeMenu();
            }}
          >
            {item.label}
          </button>
        ))}
      </div>
    </div>
  );
}

function Toasts() {
  const toasts = useCommands((state) => state.toasts);
  const dismiss = useCommands((state) => state.dismiss);
  return (
    <div className="toast-stack">
      {toasts.map((toast) => (
        <div key={toast.id} className={`toast ${toast.kind}`} onClick={() => dismiss(toast.id)}>
          {toast.message}
        </div>
      ))}
    </div>
  );
}

export function CommandLayer() {
  return (
    <>
      <ContextMenu />
      <PromptModal />
      <Toasts />
    </>
  );
}
