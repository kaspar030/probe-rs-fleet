// The `fetch` wrapper. Every call to `/api/v1` goes through here.
//
// What it does and does not carry:
//
//   * `credentials: 'same-origin'` so the `HttpOnly` `prfs_session` cookie
//     rides along. The token itself is never visible to this code, which is the
//     whole trade `docs/web-ui.md` D1 takes.
//   * On any non-GET, the `prfs_csrf` cookie (deliberately not `HttpOnly`) is
//     echoed in `X-Fleet-Csrf`. The coordinator emits no CORS headers anywhere,
//     so a custom header cannot be sent cross-origin at all — that is the
//     second, independent control.
//   * **Nothing is ever written to any client-side storage API.** Not the
//     session, not a CSRF token, not a minted auth key. `tests/ui_assets.rs`
//     lints the shipped tree for the names of all of them (web storage, the
//     indexed database, the legacy web SQL entry point), so this is a checked
//     property rather than a promise — which is also why this comment spells
//     none of them out.
//
// The acting org. A session is not bound to one org: the user acts in their
// personal org by default, or in any org they are a member of via
// `?org=<path-or-id>` on every `/api/v1` call (`src/http.rs` `acting_subject`).
// The UI sends the org *path* from its `/<org>/<page>` URL. The choice lives in
// this module (set by `app.mjs` from the page URL) and is appended here, in
// the one place every call passes through, so no page can forget it. The
// server re-checks membership on every request; this is plumbing, not policy.
//
// Sign-in itself is forgs' `/auth/*` (plain browser navigations, not fetches),
// so nothing here special-cases it.

/** Read one cookie value, or null. */
export function cookie(name, jar) {
  const raw = jar === undefined ? (typeof document === 'undefined' ? '' : document.cookie) : jar;
  for (const pair of String(raw).split(';')) {
    const at = pair.indexOf('=');
    if (at < 0) continue;
    if (pair.slice(0, at).trim() === name) return pair.slice(at + 1).trim();
  }
  return null;
}

let actingOrg = null;

/** Set the org (path or id) every `/api/v1` call acts in (`null`: the server's default, the personal org). */
export function setOrg(org) {
  actingOrg = org ? String(org) : null;
}

/** The org `/api/v1` calls currently act in, or null. */
export function currentOrg() {
  return actingOrg;
}

/** `path` with `org=<path-or-id>` appended to its query, or unchanged when `org` is empty. */
export function withOrg(path, org) {
  if (!org) return path;
  const sep = path.includes('?') ? '&' : '?';
  return `${path}${sep}org=${encodeURIComponent(org)}`;
}

/** An API error carrying the HTTP status and the server's `error` code. */
export class ApiError extends Error {
  constructor(status, code, message) {
    super(message || code || `HTTP ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

/** Human copy for the coarse error codes the API returns. */
export function describe(err) {
  if (!(err instanceof ApiError)) return String(err && err.message ? err.message : err);
  switch (err.code) {
    case 'forbidden':
      return 'Refused: your role does not allow that, or the object is not yours.';
    case 'not_found':
      return 'Not found. (The API deliberately cannot tell "no such object" from "not yours".)';
    case 'invalid_request':
      return 'The server rejected the request as malformed.';
    case 'conflict':
      return 'Conflict: something changed underneath. Reload and try again.';
    case 'last_admin':
      return 'Refused: that would leave the org with no admin. Promote someone else first.';
    case 'name_taken':
      return 'That name is already taken by an org or a user.';
    case 'invalid_name':
      return 'Invalid name: use lowercase letters, digits and single dashes, not starting or ending with a dash.';
    case 'org_creation_disabled':
      return 'This coordinator does not allow creating orgs.';
    case 'personal_org':
      return 'Your personal org follows your username; it cannot be renamed or deleted.';
    case 'org_not_empty':
      return 'The org still has hardware or sharing: remove its nodes, release its leases and revoke its grants first.';
    case 'node_name_taken':
      return 'The target org already has a node with that name.';
    case 'node_leased':
      return 'Some of its boards are leased: release them, or tick "revoke active leases".';
    case 'org_limit_reached':
      return 'You have reached the limit on how many orgs you may create.';
    case 'server_error':
      return 'The coordinator failed to handle that. Check its log.';
    case 'upstream_error':
      return 'The identity provider could not be reached.';
    default:
      return err.message;
  }
}

// Set by `app.mjs`, called when any request comes back 401.
let onUnauthorized = () => {};

/** Register the "session is gone" transition. */
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn;
}

/**
 * Issue one API request.
 *
 * `fetchImpl` and `jar` exist so `web-tests/api.test.mjs` can drive this with
 * no browser; production callers pass neither. `options.org` overrides the
 * acting org for this one call (`null` sends none); absent, the module's
 * acting org is used. Only `/api/v1/` paths carry it.
 */
export async function request(method, path, body, options = {}) {
  const fetchImpl = options.fetch || (typeof fetch === 'function' ? fetch : null);
  if (!fetchImpl) throw new Error('no fetch implementation available');
  const headers = { Accept: 'application/json' };
  if (body !== undefined && body !== null) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && method !== 'HEAD') {
    const csrf = cookie('prfs_csrf', options.jar);
    if (csrf) headers['X-Fleet-Csrf'] = csrf;
  }
  const org = 'org' in options ? options.org : actingOrg;
  const url = String(path).startsWith('/api/v1/') ? withOrg(path, org) : path;
  const response = await fetchImpl(url, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined || body === null ? undefined : JSON.stringify(body),
  });
  if (response.status === 401) {
    if (!options.quiet) onUnauthorized();
    throw new ApiError(401, 'unauthorized', 'Your session has expired. Sign in again.');
  }
  if (response.status === 204) return null;
  const text = await response.text();
  let parsed = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
  }
  if (!response.ok) {
    const code = parsed && typeof parsed.error === 'string' ? parsed.error : 'server_error';
    throw new ApiError(response.status, code, null);
  }
  return parsed;
}

export const get = (path, options) => request('GET', path, null, options);
export const post = (path, body, options) => request('POST', path, body ?? {}, options);
export const patch = (path, body, options) => request('PATCH', path, body ?? {}, options);
export const del = (path, options) => request('DELETE', path, null, options);
