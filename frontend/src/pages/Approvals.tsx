import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiAction, apiGet } from "../api";
import { ErrorBox, Pill, time } from "../components/ui";
import type { Approval, Page } from "../types";

export function Approvals() {
  const [status, setStatus] = useState("PENDING");
  const q = useQuery({ queryKey: ["approvals", status], queryFn: () => apiGet<Page<Approval>>("/approvals", { status, limit: 100 }) });
  return (
    <div className="page">
      <h1>Approvals</h1>
      <div className="toolbar">
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="PENDING">Pending</option><option value="">All</option><option>APPROVED</option>
          <option>REJECTED</option><option>EXPIRED</option>
        </select>
        <span className="hint">A requester can never approve their own request (enforced by the API for every role).</span>
      </div>
      <ErrorBox error={q.error} />
      <table className="dense">
        <thead><tr><th>Requested</th><th>Type</th><th>Target</th><th>Requester</th><th>Purpose</th><th>Criticality</th>
          <th>Window</th><th>Status</th><th>Decision</th></tr></thead>
        <tbody>{q.data?.items.map((a) => <Row key={a.id} a={a} />)}
          {q.data?.items.length === 0 && <tr><td colSpan={9} className="muted">Nothing here.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function Row({ a }: { a: Approval }) {
  const qc = useQueryClient();
  const [reason, setReason] = useState("");
  const decide = useMutation({
    mutationFn: (verb: "approve" | "reject") => apiAction<Approval>(`/approvals/${a.id}/${verb}`, { reason: reason || null }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["approvals"] }); qc.invalidateQueries({ queryKey: ["deployments"] }); },
  });
  const can = a.actions.approve;
  return (
    <tr>
      <td className="mono">{time(a.createdAt)}</td><td>{a.subjectKind}</td>
      <td><Link to={`/assets/${a.targetAssetId}`}>{a.targetName}</Link>{" "}
        <Link to={a.subjectKind === "DEPLOYMENT" ? `/deployments/${a.subjectId}` : `/removals/${a.subjectId}`}
          className="small">request →</Link></td>
      <td>{a.requestedBy}</td><td>{a.purpose}</td><td><Pill value={a.criticality} /></td>
      <td className="small">{a.maintenanceWindow ? `${time(a.maintenanceWindow.start)} – ${time(a.maintenanceWindow.end)}` : "—"}</td>
      <td><Pill value={a.status} /></td>
      <td>
        {a.status === "PENDING" ? (
          <div className="decide">
            <input placeholder="Reason" value={reason} onChange={(e) => setReason(e.target.value)} disabled={!can.enabled} />
            <button className="btn btn-sm btn-primary" disabled={!can.enabled || decide.isPending} title={can.reason}
              onClick={() => decide.mutate("approve")}>Approve</button>
            <button className="btn btn-sm" disabled={!can.enabled || decide.isPending} title={can.reason}
              onClick={() => decide.mutate("reject")}>Reject</button>
            {!can.enabled && <div className="reason">{can.reason}</div>}
            <ErrorBox error={decide.error} />
          </div>
        ) : <span>{a.decidedBy} · {a.reason ?? "no reason given"}</span>}
      </td>
    </tr>
  );
}
