import type { Problem } from "./types";

export class ApiError extends Error {
  constructor(public problem: Problem) {
    super(problem.detail || problem.title);
  }
}

async function handle<T>(res: Response): Promise<T> {
  if (res.ok) return (await res.json()) as T;
  let problem: Problem;
  try {
    problem = await res.json();
  } catch {
    problem = { type: "about:blank", title: res.statusText, status: res.status };
  }
  throw new ApiError(problem);
}

export function apiGet<T>(path: string, params?: Record<string, string | number | undefined | null>): Promise<T> {
  const qs = new URLSearchParams();
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
  });
  const q = qs.toString();
  return fetch(`/api/v1${path}${q ? `?${q}` : ""}`).then((r) => handle<T>(r));
}

/** Action POSTs always carry a fresh Idempotency-Key (the API requires one). */
export function apiAction<T>(path: string, body?: unknown): Promise<T> {
  return fetch(`/api/v1${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
    body: body === undefined ? undefined : JSON.stringify(body),
  }).then((r) => handle<T>(r));
}
