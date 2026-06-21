export function Brand({ size = 28 }: { size?: number }) {
  const box = size + 12;
  return (
    <div className="flex items-center gap-2.5">
      <div className="relative" style={{ width: box, height: box }}>
        {/* Soft indigo glow */}
        <div
          className="absolute inset-0 rounded-xl bg-gradient-to-br from-brand-500 to-accent-500 opacity-50 blur-md"
          style={{ transform: "scale(1.25)" }}
        />
        <div
          className="relative grid place-items-center rounded-xl bg-gradient-to-br from-brand-500 to-accent-500 shadow-lg shadow-brand-600/50"
          style={{ width: box, height: box }}
        >
          <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
            <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="white" />
            <path
              d="m9 12 2 2 4-4"
              stroke="#4f46e5"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
      </div>

      <div className="leading-none">
        <div className="text-lg font-bold tracking-tight bg-gradient-to-r from-brand-300 via-brand-400 to-accent-400 bg-clip-text text-transparent">
          Aegis
        </div>
        <div className="text-[11px] text-muted">Cyber Health for Nonprofits & Small Businesses</div>
      </div>
    </div>
  );
}
