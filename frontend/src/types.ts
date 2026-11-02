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
  agentless: ActionState; lastProbeId: string | null; notes: string[] }

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
  recentEvents: AuditEvent[]; adapters: { protocol: string; implementation: string; simulated: boolean; label: string }[] }

export interface SseEvent { id: number; type: string; ts: string; correlationId: string | null;
  entity: { kind: string; id: string | null }; data: Record<string, any> }
