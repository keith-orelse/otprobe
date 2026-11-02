import { useQuery } from "@tanstack/react-query";
import type { User } from "./types";

const KEY = "otprobe.token";

export function getToken(): string | null {
  try { return sessionStorage.getItem(KEY); } catch { return null; }
}

export function setToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(KEY, token);
    else sessionStorage.removeItem(KEY);
  } catch { /* storage unavailable: the session lasts until reload */ }
}

export function logout(): void {
  setToken(null);
  window.location.assign("/login");
}

export function useMe() {
  return useQuery({ queryKey: ["me"], queryFn: () => import("./api").then((m) => m.apiGet<User>("/auth/me")),
    staleTime: Infinity });
}

export function can(user: User | undefined, permission: string): boolean {
  return !!user?.permissions.includes(permission);
}
