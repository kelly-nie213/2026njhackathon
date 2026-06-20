import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Brand } from "../components/Brand";
import { useScan } from "../store";

const STEPS = [
  "Checking your domain for spoofing protection…",
  "Searching breach databases for staff emails…",
  "Scanning dark-web paste sites for mentions…",
  "Testing AI-phishing susceptibility…",
  "Mapping your data and its blast radius…",
  "Writing your plain-language action plan…",
];

export default function Scanning() {
  const nav = useNavigate();
  const { input } = useScan();
  const [step, setStep] = useState(0);

  useEffect(() => {
    if (!input) {
      nav("/");
      return;
    }
    const perStep = 700;
    const id = setInterval(() => {
      setStep((s) => {
        if (s >= STEPS.length - 1) {
          clearInterval(id);
          setTimeout(() => nav("/dashboard"), 650);
          return s;
        }
        return s + 1;
      });
    }, perStep);
    return () => clearInterval(id);
  }, [input, nav]);

  return (
    <div className="bg-aurora grid min-h-full place-items-center px-6">
      <div className="w-full max-w-md text-center">
        <div className="mb-10 flex justify-center">
          <Brand size={32} />
        </div>

        {/* radar */}
        <div className="relative mx-auto mb-10 h-44 w-44">
          {[0, 1, 2].map((i) => (
            <motion.span
              key={i}
              className="absolute inset-0 rounded-full border border-brand-500/40"
              animate={{ scale: [0.4, 1.6], opacity: [0.7, 0] }}
              transition={{ duration: 2.4, repeat: Infinity, delay: i * 0.8, ease: "easeOut" }}
            />
          ))}
          <div className="absolute inset-0 grid place-items-center">
            <motion.div
              className="grid h-20 w-20 place-items-center rounded-2xl bg-gradient-to-br from-brand-500 to-accent-500 shadow-xl shadow-brand-600/40"
              animate={{ rotate: [0, 4, -4, 0] }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              <svg width="38" height="38" viewBox="0 0 24 24" fill="none">
                <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="white" />
              </svg>
            </motion.div>
          </div>
        </div>

        <p className="text-sm text-muted">
          Scanning <span className="font-semibold text-fg">{input?.domain}</span>
        </p>

        <div className="mt-6 h-12">
          <AnimatePresence mode="wait">
            <motion.p
              key={step}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="text-[15px] font-medium"
            >
              {STEPS[step]}
            </motion.p>
          </AnimatePresence>
        </div>

        <div className="mx-auto mt-4 h-1.5 w-64 overflow-hidden rounded-full bg-white/10">
          <motion.div
            className="h-full rounded-full bg-gradient-to-r from-brand-500 to-accent-500"
            animate={{ width: `${((step + 1) / STEPS.length) * 100}%` }}
            transition={{ ease: "easeOut" }}
          />
        </div>
      </div>
    </div>
  );
}
