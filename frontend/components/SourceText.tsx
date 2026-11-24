import type { Material } from "@/lib/types";

/** Renders attacker-controlled text as inert text (React escapes it); injected lines are marked. */
export function SourceText({ material }: { material: Material }) {
  const injected = new Set(material.injected_lines);
  const lines = material.text.split("\n");
  return (
    <figure style={{ margin: 0 }}>
      <figcaption className="row" style={{ marginBottom: 8 }}>
        <code>{material.resource}</code>
        {injected.size > 0 && <span className="chip chip-attack">{injected.size} injected instruction(s)</span>}
      </figcaption>
      <pre className="source">
        {lines.map((line, i) => (
          <span key={i}>
            {injected.has(line) ? <mark title="attacker-controlled instruction">{line}</mark> : line}
            {i < lines.length - 1 ? "\n" : ""}
          </span>
        ))}
      </pre>
    </figure>
  );
}
