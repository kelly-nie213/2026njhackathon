import { createContext, useContext, useState, type ReactNode } from "react";
import type { ScanInput, ScanResult } from "./lib/types";
import { runScan } from "./lib/scan";

interface ScanStore {
  input: ScanInput | null;
  result: ScanResult | null;
  start: (input: ScanInput) => void;
  reset: () => void;
}

const Ctx = createContext<ScanStore | null>(null);

export function ScanProvider({ children }: { children: ReactNode }) {
  const [input, setInput] = useState<ScanInput | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  const start = (next: ScanInput) => {
    setInput(next);
    setResult(runScan(next));
  };
  const reset = () => {
    setInput(null);
    setResult(null);
  };

  return <Ctx.Provider value={{ input, result, start, reset }}>{children}</Ctx.Provider>;
}

export function useScan(): ScanStore {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useScan must be used within ScanProvider");
  return ctx;
}
