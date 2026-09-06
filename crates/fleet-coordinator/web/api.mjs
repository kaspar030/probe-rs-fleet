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
// The two device-login routes (`POST /api/v1/session/device/{start,poll}`) are
// unauthenticated brokering routes: they live in the coordinator's
// `browser_auth::api_routes()` and call neither `mutating_auth` nor `csrf_ok`,
// because no session credential is involved yet. Sending the header anyway is
// harmless (there is no cookie to read), and this module does not special-case
// them.

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
    case 'server_error':
      return 'The coordinator failed to handle that. Check its log.';
    case 'upstream_error':
      return 'GitHub could not be reached.';
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
 * no browser; production callers pass neither.
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
  const response = await fetchImpl(path, {
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
