export function Brand({ size = 28 }: { size?: number }) {
  return (
    <div className="flex items-center gap-2.5">
      <div
        className="grid place-items-center rounded-xl bg-gradient-to-br from-brand-500 to-accent-500 shadow-lg shadow-brand-600/40"
        style={{ width: size + 12, height: size + 12 }}
      >
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
          <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="white" />
          <path
            d="m9 12 2 2 4-4"
            stroke="#7c3aed"
            strokeWidth="2.2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </div>
      <div className="leading-none">
        <div className="text-lg font-bold tracking-tight">Aegis</div>
        <div className="text-[11px] text-muted">Cyber Health for Nonprofits</div>
      </div>
    </div>
  );
}
