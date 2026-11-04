// Mirrors backend/app/schemas (camelCase on the wire).
export interface Page<T> { items: T[]; nextCursor: string | null; total: number }

export interface Problem { type: string; title: string; status: number; detail?: string; correlationId?: string;
  errors?: { field: string; message: string }[] }

export interface Zone { id: string; name: string; cidr: string; defaultLevel: string; safeMode: boolean;
  scannable: boolean; description: string }

export interface WorkflowStep { seq: number; name: string; status: "PENDING" | "RUNNING" | "OK" | "FAILED" | "SKIPPED";
  detail: string; progress: number | null; data: Record<string, any>; startedAt: string | null; finishedAt: string | null }

export interface DiscoveryJob { id: string; targets: string[]; methods: string[]; safeMode: boolean; status: string;
  progress: number; phase: string | null; devicesFound: number; newAssets: number; rogueCount: number;
  requestedBy: string; error: string | null; correlationId: string; createdAt: string; startedAt: string | null;
  finishedAt: string | null; steps: WorkflowStep[]; actions: Record<string, ActionState> }

export interface DiscoveryMethod { method: string; label: string; implementation: string; simulated: boolean;
  description: string }

export interface Observation { id: string; assetId: string | null; ip: string; mac: string | null; method: string;
  responded: boolean; result: Record<string, any>; observedAt: string }

export interface AssetSummary { id: string; ip: string; mac: string | null; hostname: string | null;
  sysName: string | null; displayName: string; type: string | null; os: string | null; level: string;
  criticality: string | null; status: string; isRogue: boolean; agentState: string; eligibility: string;
  eligibilityReason: string; discoveredBy: string[]; firstSeen: string; lastSeen: string; lastProbeAt: string | null }

export interface FieldValue { path: string; value: any; source: string; sourceLabel: string; stage: string;
  collectedAt: string }

export interface Classification { type: string; confidence: number;
  evidence: { signal: string; field: string; value: any; weight: number }[] }

export interface ActionState { enabled: boolean; reason: string }

export interface Relationship { kind: string; direction: string; peerAssetId: string; peerName: string;
  protocol: string; port: number | null; source: string }

export interface AssetDetail extends AssetSummary { zone: Zone | null; classification: Classification | null;
  groups: Record<string, FieldValue[]>; relationships: Relationship[]; deployAgent: ActionState;
  agentless: ActionState; lastProbeId: string | null; maintenanceWindowRequired: boolean;
  currentAgentId: string | null; compliance: Compliance | null; notes: string[] }

export interface ProbeResult { protocol: string; status: string; data: Record<string, any>;
  stages: { name: string; status: string; detail: string; at: string | null }[]; latencyMs: number | null;
  errorCode: string | null; errorDetail: string | null; collectedAt: string }

export interface ProbeRun { id: string; assetId: string; assetName: string | null; status: string; requestedBy: string;
  classification: Classification | null; eligibility: string | null; eligibilityReason: string | null;
  error: string | null; correlationId: string; createdAt: string; startedAt: string | null; finishedAt: string | null;
  steps: WorkflowStep[]; results: ProbeResult[] }

export interface AuditEvent { seq: number; at: string; actorType: string; actorId: string | null; actorName: string;
  action: string; entityKind: string; entityId: string | null; correlationId: string | null;
  details: Record<string, any>; hash: string }

export interface TopologyNode { id: string; kind: "zone" | "server" | "conduit" | "asset"; parent: string | null;
  label: string; state: string | null; assetId: string | null; ip: string | null; type: string | null;
  order: number | null; tier: "infrastructure" | "host" | null }
export interface TopologyEdge { id: string; source: string; target: string; kind: string; protocol: string | null;
  port: number | null }
export interface Topology { nodes: TopologyNode[]; edges: TopologyEdge[] }

export interface VaultProfile { name: string; protocol: string; username: string; secret: string; secretSet: boolean }

export interface DashboardSummary { assets: Record<string, number>; assetsByLevel: Record<string, number>;
  eligibility: Record<string, number>; rogue: number; lastDiscovery: DiscoveryJob | null;
  recentEvents: AuditEvent[]; adapters: { protocol: string; implementation: string; simulated: boolean; label: string }[];
  openFindings: Record<string, number>; complianceAvg: number | null; unknownTotal: number; monitoring: MonitoringRow[];
  recentDrift: DriftEvent[]; recentChanges: { assetId: string; assetName: string | null; path: string; before: any;
    after: any; detectedAt: string; runId: string }[]; assetsByLevelType: Record<string, Record<string, number>>;
  pendingApprovals: number; agents: Record<string, number> }

export interface SseEvent { id: number; type: string; ts: string; correlationId: string | null;
  entity: { kind: string; id: string | null }; data: Record<string, any> }

export interface User { id: string; username: string; displayName: string; role: string; permissions: string[] }

export interface Package { id: string; name: string; version: string; architecture: string; sha256: string;
  sizeBytes: number; supportedOs: string[]; status: string; releaseNotes: string; createdAt: string }

export interface MaintenanceWindow { start: string; end: string }

export interface Approval { id: string; subjectKind: string; subjectId: string; targetAssetId: string;
  targetName: string | null; requestedBy: string; purpose: string; criticality: string | null;
  maintenanceWindow: MaintenanceWindow | null; status: string; decidedBy: string | null; decidedAt: string | null;
  reason: string | null; createdAt: string; actions: Record<string, ActionState> }

export interface PrecheckResult { runNo: number; seq: number; check: string; status: string; detail: string;
  checkedAt: string }

export interface Deployment { id: string; assetId: string; assetName: string | null; package: Package | null;
  credentialProfile: string; status: string; purpose: string; requestedBy: string; approval: Approval | null;
  precheckRunNo: number; precheckPassedAt: string | null; precheck: PrecheckResult[]; steps: WorkflowStep[];
  agentId: string | null; failureCode: string | null; failureDetail: string | null; retryOfId: string | null;
  correlationId: string; createdAt: string; deployStartedAt: string | null; enrollingSince: string | null;
  finishedAt: string | null; actions: Record<string, ActionState> }

export interface Agent { id: string; assetId: string; assetName: string | null; deploymentId: string; status: string;
  version: string; credentialPrefix: string | null; installedAt: string; enrolledAt: string | null;
  lastHeartbeatAt: string | null; secondsSinceHeartbeat: number | null; missedHeartbeats: number;
  heartbeatIntervalSec: number; revokedAt: string | null; removedAt: string | null;
  actions: Record<string, ActionState>; removalId: string | null }

export interface HeartbeatRecord { seq: number; receivedAt: string; agentTime: string | null;
  payload: Record<string, any> }

export interface DemoDevice { deviceId: string; ip: string; hostname: string; type: string; level: string;
  powered: boolean; online: boolean; agentInstalled: boolean; faults: string[]; config: Record<string, string> }
export interface DemoState { devices: DemoDevice[]; availableFaults: Record<string, string>;
  configControls: Record<string, string[]> }

export interface RuleResult { seq: number; ruleId: string; ruleVersion: string; title: string; status: string;
  severity: string; evidencePath: string; observed: any; expected: string; message: string | null;
  previousStatus: string | null; references: string[] }

export interface DriftEvent { id: string; assetId: string; assetName: string | null; runId: string;
  previousRunId: string; ruleId: string; fromStatus: string; toStatus: string; evidencePath: string; before: any;
  after: any; findingId: string | null; detectedAt: string }

export interface EvidenceChange { path: string; before: any; after: any; detectedAt: string }

export interface AssessmentRun { id: string; assetId: string; assetName: string | null; agentId: string | null;
  policyKey: string; policyVersion: string; source: string; trigger: string; status: string; requestedBy: string;
  score: number | null; counts: Record<string, number>; previousRunId: string | null; error: string | null;
  correlationId: string; createdAt: string; startedAt: string | null; finishedAt: string | null;
  evidence: Record<string, any> | null; results: RuleResult[]; driftEvents: DriftEvent[];
  evidenceChanges: EvidenceChange[] }

export interface Compliance { score: number | null; counts: Record<string, number>; source: string | null;
  lastRunId: string | null; lastAssessmentAt: string | null; lastDeepStatus: string | null;
  nextAssessmentAt: string | null; openFindings: number; runAction: ActionState }

export interface FindingEvent { fromStatus: string | null; toStatus: string; runId: string | null; actor: string;
  reason: string | null; at: string }

export interface Finding { id: string; assetId: string; assetName: string | null; assetIp: string | null;
  ruleId: string; title: string; severity: string; status: string; resultStatus: string; source: string;
  observed: any; expected: string; references: string[]; remediation: string | null; firstSeen: string;
  lastSeen: string; resolvedAt: string | null; reopenCount: number; acceptedBy: string | null;
  acceptedReason: string | null; acceptedAt: string | null; acceptedUntil: string | null; lastRunId: string | null;
  actions: Record<string, ActionState>; events: FindingEvent[]; driftEvents: DriftEvent[] }

export interface CompareCell { level: string; value: any; source: string | null; detail: string | null }
export interface Comparison { assetId: string; assetName: string; hasDeepEvidence: boolean;
  rows: { capability: string; agentless: CompareCell; deep: CompareCell }[] }

export interface MonitoringRow { assetId: string; assetName: string; agentId: string; agentStatus: string;
  secondsSinceHeartbeat: number | null; lastAssessmentAt: string | null; nextAssessmentAt: string | null;
  score: number | null; unknown: number; openFindings: number }

export interface Removal { id: string; assetId: string; assetName: string | null; agentId: string; status: string;
  purpose: string; requestedBy: string; approval: Approval | null; failureCode: string | null;
  failureDetail: string | null; correlationId: string; createdAt: string; startedAt: string | null;
  finishedAt: string | null; steps: WorkflowStep[]; actions: Record<string, ActionState> }

export interface TelemetryTopic { topic: string; clientId: string; assetId: string | null; assetName: string | null;
  lastPayload: any; lastAt: string; messages: number; openFindings: string[];
  recent: { at: string; payload: Record<string, any> }[] }

export interface DemoResetResult { status: string; cleared: Record<string, number>; discoveryHistory: string;
  agentsRevoked: number }

export interface NavCounts { pendingApprovals: number; openFindings: number; criticalFindings: number;
  agentsAttention: number; rogueAssets: number; runningWorkflows: number }

export interface Environment { mode: "LIVE" | "SIMULATED"; banner: string; severity: "info" | "warning" | "danger";
  armed: boolean; safeMode: boolean; scope: string[] }

export interface ScanScope { id: string; cidr: string; kind: "INCLUDE" | "EXCLUDE"; profile: "IT" | "OT_SENSITIVE";
  level: string; label: string; authorization: string; plugins: string[]; createdBy: string; createdAt: string;
  disabledAt: string | null }

export interface SafetyView { live: boolean; armed: boolean; safeMode: boolean; changedBy: string | null;
  changedAt: string | null; reason: string; scopeConfigured: boolean; includes: string[]; excludes: string[];
  runningWorkflows: string[]; traffic: { sent: number; byOperation: Record<string, number>;
    blocked: Record<string, number>; rateLimitedSec: number } | null }
