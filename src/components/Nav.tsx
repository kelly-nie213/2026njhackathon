import { useNavigate, useLocation } from "react-router-dom";
import { Brand } from "./Brand";

const NAV_ITEMS = [
  { path: "/",           label: "Breach Detector",  icon: "🔍" },
  { path: "/phishing",   label: "Phishing Checker", icon: "✉️" },
  { path: "/triage",     label: "Incident Triage",  icon: "⚡" },
  { path: "/code-audit", label: "Code Auditor",     icon: "</>" },
  { path: "/learn",      label: "Learn & Protect",  icon: "🛡️" },
];

export function Nav() {
  const nav = useNavigate();
  const { pathname } = useLocation();

  return (
    <header className="glass-nav sticky top-0 z-50">
      <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-3.5">
        <Brand />

        <nav className="flex items-center gap-1 rounded-2xl border border-white/8 bg-white/[0.03] p-1 backdrop-blur-sm">
          {NAV_ITEMS.map((item) => {
            const active = pathname === item.path;
            const isLearn = item.path === "/learn";
            return (
              <button
                key={item.path}
                onClick={() => nav(item.path)}
                className={`rounded-xl px-3 py-1.5 text-xs font-medium transition-all duration-200 ${
                  active
                    ? isLearn
                      ? "bg-gradient-to-r from-accent-500 to-brand-500 text-white shadow-md shadow-accent-600/40"
                      : "bg-gradient-to-r from-brand-500 to-accent-500 text-white shadow-md shadow-brand-600/40"
                    : "text-muted hover:text-fg hover:bg-white/[0.07]"
                }`}
              >
                <span className="hidden lg:inline">{item.icon} {item.label}</span>
                <span className="lg:hidden">{item.icon}</span>
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
