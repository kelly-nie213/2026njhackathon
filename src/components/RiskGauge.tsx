import { motion } from "framer-motion";

/** Semicircular gauge. score 0-100 (higher = worse). */
export function RiskGauge({ score, label }: { score: number; label: string }) {
  const r = 80;
  const cx = 100;
  const cy = 100;
  const circumference = Math.PI * r; // semicircle
  const pct = Math.min(100, Math.max(0, score)) / 100;

  const color =
    score >= 75
      ? "var(--color-risk-crit)"
      : score >= 50
        ? "var(--color-risk-high)"
        : score >= 28
          ? "var(--color-risk-med)"
          : "var(--color-risk-low)";

  const arc = (start: number, end: number) => {
    const a0 = Math.PI + start * Math.PI;
    const a1 = Math.PI + end * Math.PI;
    return `M ${cx + r * Math.cos(a0)} ${cy + r * Math.sin(a0)} A ${r} ${r} 0 0 1 ${
      cx + r * Math.cos(a1)
    } ${cy + r * Math.sin(a1)}`;
  };

  return (
    <div className="relative w-full max-w-[260px]">
      <svg viewBox="0 0 200 120" className="w-full">
        {/* track segments (green → red) */}
        <path d={arc(0, 1)} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="14" strokeLinecap="round" />
        <motion.path
          d={arc(0, 1)}
          fill="none"
          stroke={color}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: circumference * (1 - pct) }}
          transition={{ duration: 1.1, ease: "easeOut" }}
        />
      </svg>
      <div className="absolute inset-x-0 bottom-1 flex flex-col items-center">
        <motion.span
          className="text-5xl font-extrabold tabular-nums"
          style={{ color }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
        >
          {score}
        </motion.span>
        <span className="text-xs text-muted">out of 100</span>
        <span
          className="mt-1 rounded-full px-3 py-0.5 text-xs font-semibold"
          style={{ color, background: "rgba(255,255,255,0.06)" }}
        >
          {label} risk
        </span>
      </div>
    </div>
  );
}
