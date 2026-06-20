import { Routes, Route } from "react-router-dom";
import { ScanProvider } from "./store";
import Onboarding from "./screens/Onboarding";
import Scanning from "./screens/Scanning";
import Dashboard from "./screens/Dashboard";
import PhishingChecker from "./screens/PhishingChecker";
import IncidentTriage from "./screens/IncidentTriage";

export default function App() {
  return (
    <ScanProvider>
      <Routes>
        <Route path="/" element={<Onboarding />} />
        <Route path="/scanning" element={<Scanning />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/phishing" element={<PhishingChecker />} />
        <Route path="/triage" element={<IncidentTriage />} />
      </Routes>
    </ScanProvider>
  );
}
