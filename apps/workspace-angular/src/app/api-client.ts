/** Same-origin JSON API boundary for the authenticated workspace.
 *
 * Keep credentials on this origin; do not put bearer tokens in browser code.
 * The server is authoritative for OAuth scopes and device permission grants.
 * Do not silently retry mutations or redirect on 401 here: callers handle UI state.
 */
export async function request<T = any>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const error = new Error(
      String(data.detail || data.message || "HTTP " + res.status),
    );
    (error as any).status = res.status;
    throw error;
  }
  return data as T;
}
