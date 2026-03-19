import type { Route } from 'next';

export function approvalRoutePath(approvalId: string): Route {
  return `/approvals/${encodeURIComponent(approvalId)}` as Route;
}

export function daemonRoutePath(daemonId: string): Route {
  return `/daemons/${encodeURIComponent(daemonId)}` as Route;
}
