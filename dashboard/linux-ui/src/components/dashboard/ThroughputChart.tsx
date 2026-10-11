import { memo, useMemo, useState } from "react";
import type { StatsBucket } from "../../dashboardTypes";

const WIDTH = 640;
const HEIGHT = 200;
const SERIES = [
  { key: "allow", label: "Allow", className: "series-allow" },
  { key: "deny", label: "Deny", className: "series-deny" },
  { key: "observe", label: "Observe", className: "series-observe" }
] as const;

type SeriesKey = (typeof SERIES)[number]["key"];

// Round the axis up so its three gridline intervals land on whole, readable numbers.
function niceMax(value: number): number {
  const raw = Math.max(value, 3) / 3;
  const magnitude = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 5, 10].map((m) => m * magnitude).find((s) => s >= raw) ?? 10 * magnitude;
  return Math.ceil(step) * 3;
}

// Catmull-Rom → cubic Bézier so the series read as smooth trends rather than zig-zags.
function smoothPath(points: Array<[number, number]>): string {
  if (!points.length) return "";
  if (points.length === 1) {
    // A single bucket has no trend yet: draw it as a flat line across the plot.
    return `M0,${points[0][1].toFixed(1)} L${WIDTH},${points[0][1].toFixed(1)}`;
  }
  let d = `M${points[0][0].toFixed(1)},${points[0][1].toFixed(1)}`;
  for (let i = 0; i < points.length - 1; i += 1) {
    const p0 = points[Math.max(0, i - 1)];
    const p1 = points[i];
    const p2 = points[i + 1];
    const p3 = points[Math.min(points.length - 1, i + 2)];
    const c1x = p1[0] + (p2[0] - p0[0]) / 6;
    const c1y = Math.min(HEIGHT, p1[1] + (p2[1] - p0[1]) / 6);
    const c2x = p2[0] - (p3[0] - p1[0]) / 6;
    const c2y = Math.min(HEIGHT, p2[1] - (p3[1] - p1[1]) / 6);
    d += ` C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
  }
  return d;
}

function minuteLabel(minute: string): string {
  const date = new Date(minute);
  if (Number.isNaN(date.getTime())) return minute;
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export const ThroughputChart = memo(function ThroughputChart({
  buckets
}: {
  buckets: StatsBucket[];
}) {
  const [hovered, setHovered] = useState<number | null>(null);

  const model = useMemo(() => {
    const peak = Math.max(1, ...buckets.map((b) => Math.max(b.allow, b.deny, b.observe)));
    const max = niceMax(peak);
    const x = (index: number) =>
      buckets.length <= 1 ? WIDTH / 2 : (index / (buckets.length - 1)) * WIDTH;
    const y = (value: number) => HEIGHT - (value / max) * HEIGHT;
    const paths = Object.fromEntries(
      SERIES.map((series) => {
        const pts = buckets.map((b, i) => [x(i), y(b[series.key])] as [number, number]);
        const line = smoothPath(pts);
        const area = line ? `${line} L${WIDTH},${HEIGHT} L0,${HEIGHT} Z` : "";
        return [series.key, { line, area }];
      })
    ) as Record<SeriesKey, { line: string; area: string }>;
    const labelIndexes = buckets.length
      ? [...new Set([0, Math.round((buckets.length - 1) / 2), buckets.length - 1])]
      : [];
    return { max, x, y, paths, labelIndexes };
  }, [buckets]);

  if (!buckets.length) {
    return (
      <div className="chart-empty" data-testid="throughput-empty">
        No decisions recorded yet. The chart fills in as agents run.
      </div>
    );
  }

  const hoveredBucket = hovered == null ? null : buckets[hovered];
  const ticks = [model.max, (model.max * 2) / 3, model.max / 3, 0];
  const formatTick = (tick: number) => (Number.isInteger(tick) ? tick : tick.toFixed(1));

  return (
    <div className="chart">
      <div className="chart-y-axis" aria-hidden="true">
        {ticks.map((tick) => (
          <span key={tick}>{formatTick(tick)}</span>
        ))}
      </div>
      <div
        className="chart-plot"
        onMouseLeave={() => setHovered(null)}
        onMouseMove={(event) => {
          const rect = event.currentTarget.getBoundingClientRect();
          const ratio = (event.clientX - rect.left) / Math.max(rect.width, 1);
          setHovered(
            Math.min(buckets.length - 1, Math.max(0, Math.round(ratio * (buckets.length - 1))))
          );
        }}
      >
        <svg
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          preserveAspectRatio="none"
          className="chart-svg"
          role="img"
          aria-label="Allow, deny and observe decisions per minute"
        >
          {[0, 1, 2, 3].map((i) => (
            <line
              key={i}
              x1={0}
              x2={WIDTH}
              y1={(HEIGHT / 3) * i}
              y2={(HEIGHT / 3) * i}
              className={i === 3 ? "chart-grid chart-grid-base" : "chart-grid"}
              vectorEffect="non-scaling-stroke"
            />
          ))}
          {SERIES.filter((s) => s.key !== "observe").map((series) => (
            <path
              key={`${series.key}-area`}
              d={model.paths[series.key].area}
              className={`chart-area ${series.className}`}
            />
          ))}
          {SERIES.map((series) => (
            <path
              key={`${series.key}-line`}
              d={model.paths[series.key].line}
              className={`chart-line ${series.className}`}
              vectorEffect="non-scaling-stroke"
            />
          ))}
          {hovered != null ? (
            <line
              x1={model.x(hovered)}
              x2={model.x(hovered)}
              y1={0}
              y2={HEIGHT}
              className="chart-guide"
              vectorEffect="non-scaling-stroke"
            />
          ) : null}
        </svg>
        {hoveredBucket && hovered != null ? (
          <div
            className="chart-tooltip"
            style={{
              left: `${(model.x(hovered) / WIDTH) * 100}%`,
              transform: `translateX(${hovered > buckets.length / 2 ? "calc(-100% - 12px)" : "12px"})`
            }}
          >
            <p className="chart-tooltip-title">{minuteLabel(hoveredBucket.minute)}</p>
            {SERIES.map((series) => (
              <p key={series.key} className="chart-tooltip-row">
                <span className={`legend-swatch ${series.className}`} />
                <span>{series.label}</span>
                <strong>{hoveredBucket[series.key]}</strong>
              </p>
            ))}
          </div>
        ) : null}
        <div className="chart-x-axis" aria-hidden="true">
          {model.labelIndexes.map((index) => (
            <span key={index} style={{ left: `${(model.x(index) / WIDTH) * 100}%` }}>
              {index === buckets.length - 1 ? "Now" : minuteLabel(buckets[index].minute)}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
});

export function ChartLegend({ totals }: { totals: Record<SeriesKey, number> }) {
  return (
    <div className="chart-legend">
      {SERIES.map((series) => (
        <span key={series.key} className="chart-legend-item">
          <span className={`legend-swatch ${series.className}`} />
          <span>{series.label}</span>
          <strong>{totals[series.key].toLocaleString()}</strong>
        </span>
      ))}
    </div>
  );
}
