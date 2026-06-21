export type OrgType =
  | "food-bank"
  | "donation-center"
  | "youth-nonprofit"
  | "community-org"
  | "other";

export interface ScanInput {
  orgName: string;
  domain: string;
  emails: string[];
  orgType: OrgType;
}

export type Severity = "low" | "medium" | "high" | "critical";

export type FindingCategory =
  | "domain-exposure"
  | "breached-credentials"
  | "ai-phishing"
  | "dark-web"
  | "email-security";

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  detail: string;
  evidence: string;
}

/** A category of data the org holds — used for the consequence + interconnection map. */
export interface DataAsset {
  id: string;
  name: string;
  icon: string;
  /** 0-100 how sensitive/damaging if leaked */
  sensitivity: number;
  /** ids of other assets a breach of this one cascades into */
  connections: string[];
  /** plain-language "what happens if this leaks" */
  consequence: string;
  exposed: boolean;
}

export interface ActionStep {
  priority: number;
  title: string;
  why: string;
  effort: "5 min" | "30 min" | "1 hour" | "ongoing";
  steps: string[];
}

export interface LikelyAttack {
  type: string;
  description: string;
  whoAtRisk: string[];
}

/** A finding produced by the live 7-source security scan (no simulation). */
export interface LiveFinding {
  id: string;
  category: string;
  severity: Severity;
  title: string;
  detail: string;
  evidence: string;
  source: string;
}

export interface LiveScanMeta {
  emailProvider: string | null;
  ip: string | null;
  domainExpiryDays: number | null;
  subdomainCount: number;
  sensitiveSubdomains: string[];
  openPorts: number[];
  cves: string[];
  exposedPaths: { path: string; label: string }[];
  isHTTPS: boolean;
}

export interface LiveScanData {
  domain: string;
  scannedAt: string;
  findings: LiveFinding[];
  meta: LiveScanMeta;
}

export interface ScanResult {
  input: ScanInput;
  scannedAt: string;
  riskScore: number; // 0-100, higher = worse
  riskLabel: "Low" | "Moderate" | "High" | "Critical";
  findings: Finding[];
  dataAssets: DataAsset[];
  likelyAttack: LikelyAttack;
  actionPlan: ActionStep[];
  stats: {
    breachedAccounts: number;
    exposedRecords: number;
    domainAgeDays: number;
    phishingSusceptibility: number; // 0-100
  };
}
