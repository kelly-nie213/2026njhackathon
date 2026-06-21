import { Routes, Route, Navigate } from "react-router-dom";
import BreachDetector from "./screens/BreachDetector";
import PhishingChecker from "./screens/PhishingChecker";
import IncidentTriage from "./screens/IncidentTriage";
import LearnMore from "./screens/LearnMore";
import TiamScreen from "./screens/TiamScreen";
import CredentialChecker from "./screens/CredentialChecker";

export default function App() {
  return (
    <div className="bg-aurora min-h-full" data-p-theme="darkmode">
      <Routes>
        <Route path="/"             element={<BreachDetector />} />
        <Route path="/phishing"     element={<PhishingChecker />} />
        <Route path="/triage"       element={<IncidentTriage />} />
        <Route path="/tiam"         element={<TiamScreen />} />
        <Route path="/credentials"  element={<CredentialChecker />} />
        <Route path="/learn"        element={<LearnMore />} />
        {/* code audit now lives inside the breach scan — keep the path working */}
        <Route path="/code-audit"   element={<Navigate to="/" replace />} />
        <Route path="/breachdetector" element={<Navigate to="/" replace />} />
        <Route path="*"           element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  );
}
