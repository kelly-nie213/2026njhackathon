import { createContext, useContext, useState, type ReactNode } from "react";
import type { ScanInput, ScanResult, LiveScanData } from "./lib/types";
import { runScan } from "./lib/scan";

interface ScanStore {
  input: ScanInput | null;
  result: ScanResult | null;
  liveData: LiveScanData | null;
  liveStatus: "idle" | "scanning" | "done" | "error";
  start: (input: ScanInput) => void;
  reset: () => void;
}

const Ctx = createContext<ScanStore | null>(null);

export function ScanProvider({ children }: { children: ReactNode }) {
  const [input, setInput] = useState<ScanInput | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [liveData, setLiveData] = useState<LiveScanData | null>(null);
  const [liveStatus, setLiveStatus] = useState<ScanStore["liveStatus"]>("idle");

  const start = (next: ScanInput) => {
    setInput(next);
    setResult(runScan(next));
    setLiveData(null);
    setLiveStatus("scanning");

    fetch("/api/security-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: next.domain }),
    })
      .then(async (r) => {
        if (r.ok) {
          setLiveData(await r.json());
          setLiveStatus("done");
        } else {
          setLiveStatus("error");
        }
      })
      .catch(() => setLiveStatus("error"));
  };

  const reset = () => {
    setInput(null);
    setResult(null);
    setLiveData(null);
    setLiveStatus("idle");
  };

  return (
    <Ctx.Provider value={{ input, result, liveData, liveStatus, start, reset }}>
      {children}
    </Ctx.Provider>
  );
}

export function useScan(): ScanStore {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useScan must be used within ScanProvider");
  return ctx;
}
