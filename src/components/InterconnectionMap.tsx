import { useMemo } from "react";
import { motion } from "framer-motion";
import type { DataAsset } from "../lib/types";

interface Props {
  assets: DataAsset[];
  selected: string | null;
  onSelect: (id: string) => void;
}

/**
 * Force-free radial layout: the most-connected asset sits at the center
 * (highest "blast radius"), everything else orbits it.
 */
export function InterconnectionMap({ assets, selected, onSelect }: Props) {
  const W = 460;
  const H = 360;

  const { center, orbit } = useMemo(() => {
    const sorted = [...assets].sort((a, b) => b.connections.length - a.connections.length);
    return { center: sorted[0], orbit: sorted.slice(1) };
  }, [assets]);

  const pos = useMemo(() => {
    const map: Record<string, { x: number; y: number }> = {};
    map[center.id] = { x: W / 2, y: H / 2 };
    const R = 130;
    orbit.forEach((a, i) => {
      const angle = (i / orbit.length) * Math.PI * 2 - Math.PI / 2;
      map[a.id] = { x: W / 2 + R * Math.cos(angle), y: H / 2 + R * Math.sin(angle) };
    });
    return map;
  }, [center, orbit]);

  const edges = useMemo(() => {
    const seen = new Set<string>();
    const list: [string, string][] = [];
    assets.forEach((a) =>
      a.connections.forEach((c) => {
        if (!pos[c]) return;
        const key = [a.id, c].sort().join("-");
        if (seen.has(key)) return;
        seen.add(key);
        list.push([a.id, c]);
      })
    );
    return list;
  }, [assets, pos]);

  const isActive = (id: string) => selected === null || selected === id;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full">
      {edges.map(([a, b], i) => {
        const active = selected === null || selected === a || selected === b;
        return (
          <motion.line
            key={i}
            x1={pos[a].x}
            y1={pos[a].y}
            x2={pos[b].x}
            y2={pos[b].y}
            stroke={active ? "rgba(139,92,246,0.55)" : "rgba(255,255,255,0.08)"}
            strokeWidth={active ? 2 : 1}
            initial={{ pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: 1 }}
            transition={{ duration: 0.6, delay: i * 0.05 }}
          />
        );
      })}

      {assets.map((a, i) => {
        const p = pos[a.id];
        const big = a.id === center.id;
        const rad = big ? 40 : 30;
        const active = isActive(a.id);
        const ring = a.exposed ? "var(--color-risk-crit)" : "var(--color-risk-low)";
        return (
          <motion.g
            key={a.id}
            onClick={() => onSelect(a.id)}
            style={{ cursor: "pointer" }}
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: active ? 1 : 0.92, opacity: active ? 1 : 0.4 }}
            transition={{ delay: 0.2 + i * 0.06, type: "spring", stiffness: 200 }}
          >
            {a.exposed && (
              <motion.circle
                cx={p.x}
                cy={p.y}
                r={rad}
                fill="none"
                stroke={ring}
                strokeWidth={1.5}
                animate={{ r: [rad, rad + 10], opacity: [0.5, 0] }}
                transition={{ duration: 1.8, repeat: Infinity }}
              />
            )}
            <circle
              cx={p.x}
              cy={p.y}
              r={rad}
              fill={selected === a.id ? "rgba(139,92,246,0.25)" : "rgba(20,20,40,0.92)"}
              stroke={ring}
              strokeWidth={selected === a.id ? 3 : 2}
            />
            <text x={p.x} y={p.y - 2} textAnchor="middle" fontSize={big ? 22 : 18}>
              {a.icon}
            </text>
            <text
              x={p.x}
              y={p.y + rad + 14}
              textAnchor="middle"
              fontSize="10"
              fill="var(--color-fg)"
              fontWeight={600}
            >
              {a.name.length > 18 ? a.name.split(" ")[0] : a.name}
            </text>
          </motion.g>
        );
      })}

      <text x={W / 2} y={H / 2 + 56} textAnchor="middle" fontSize="9" fill="var(--color-muted)">
        ◀ highest blast radius
      </text>
    </svg>
  );
}
