import { Routes, Route, Navigate } from "react-router-dom";
import BreachDetector from "./screens/BreachDetector";
import PhishingChecker from "./screens/PhishingChecker";
import IncidentTriage from "./screens/IncidentTriage";
import CodeAuditor from "./screens/CodeAuditor";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<BreachDetector />} />
      <Route path="/phishing" element={<PhishingChecker />} />
      <Route path="/triage" element={<IncidentTriage />} />
      <Route path="/code-audit" element={<CodeAuditor />} />
      {/* legacy path → home */}
      <Route path="/breachdetector" element={<Navigate to="/" replace />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
