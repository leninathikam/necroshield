export interface ParetoPoint {
  name: string;
  x: number; // policy complexity (lower is simpler)
  y: number; // task completion, 0..1
  feasible: boolean;
  frontier: boolean;
  selected: boolean;
}

const W = 560;
const H = 300;
const PAD = { l: 52, r: 18, t: 16, b: 44 };

/** Security-utility trade-off. Every point is a real evaluated candidate; rejected candidates
 * (forbidden effects still occurred) are drawn as crosses so they cannot be mistaken for options. */
export function ParetoChart({ points, caption }: { points: ParetoPoint[]; caption: string }) {
  const maxX = Math.max(10, ...points.map((p) => p.x)) * 1.08;
  const px = (x: number) => PAD.l + (x / maxX) * (W - PAD.l - PAD.r);
  const py = (y: number) => H - PAD.b - y * (H - PAD.t - PAD.b);
  // Points with identical coordinates are fanned out so none hides another.
  const seen = new Map<string, number>();
  const placed = points.map((p) => {
    const key = `${p.x.toFixed(2)}:${p.y.toFixed(3)}`;
    const n = seen.get(key) ?? 0;
    seen.set(key, n + 1);
    return { ...p, dx: n * 11, dy: -n * 9 };
  });
  return (
    <figure style={{ margin: 0 }}>
      <svg viewBox={`0 0 ${W} ${H}`} className="pareto" role="img" aria-label={caption}>
        {[0, 0.25, 0.5, 0.75, 1].map((t) => (
          <g key={t}>
            <line x1={PAD.l} x2={W - PAD.r} y1={py(t)} y2={py(t)} className="pareto-grid" />
            <text x={PAD.l - 8} y={py(t) + 4} textAnchor="end" className="pareto-tick">
              {Math.round(t * 100)}%
            </text>
          </g>
        ))}
        <text x={(PAD.l + W - PAD.r) / 2} y={H - 8} textAnchor="middle" className="pareto-axis">
          policy complexity (grants + pinned values, mean) → simpler is left
        </text>
        <text transform={`translate(14 ${(PAD.t + H - PAD.b) / 2}) rotate(-90)`} textAnchor="middle" className="pareto-axis">
          legitimate tasks completed
        </text>
        {placed.map((p) => {
          const cx = px(p.x) + p.dx;
          const cy = py(p.y) + p.dy;
          const label = `${p.name}: complexity ${p.x}, completion ${Math.round(p.y * 100)}%, ${
            p.feasible ? (p.frontier ? "on the Pareto frontier" : "feasible, dominated") : "rejected: forbidden effects occurred"
          }${p.selected ? ", suggested" : ""}`;
          return (
            <g key={p.name}>
              <title>{label}</title>
              {p.selected && <circle cx={cx} cy={cy} r={11} className="pareto-selected" />}
              {p.feasible ? (
                <circle cx={cx} cy={cy} r={6} className={p.frontier ? "pareto-front" : "pareto-dominated"} />
              ) : (
                <path d={`M${cx - 5} ${cy - 5}L${cx + 5} ${cy + 5}M${cx + 5} ${cy - 5}L${cx - 5} ${cy + 5}`} className="pareto-rejected" />
              )}
              <text x={cx + 10} y={cy - 8} className="pareto-label">
                {p.name}
              </text>
            </g>
          );
        })}
      </svg>
      <figcaption className="faint">
        Filled: non-dominated. Hollow: feasible but dominated. Cross: rejected by the mandatory constraint. Ring: the fixed
        tie-break&apos;s suggestion, not a proven optimum.
      </figcaption>
    </figure>
  );
}
