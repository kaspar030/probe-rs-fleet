// Reading `GET /api/v1/session`'s body.
//
// The shape (`src/api.rs` `SessionView`):
//
//   { user_id, username, memberships: [{id, name, role, personal}],
//     org: {id, name, role, personal} | null, expires, can_create_orgs }
//
// `personal` marks the user's personal org, which follows the username and
// cannot be renamed or deleted as an org.
//
// `org` is the org this session is acting in (the `?org=` the request carried,
// default the personal org), with the caller's role *there*; it is `null` when
// the requested org is not one the user belongs to. Every helper here is UX
// only: the server checks role and ownership on every request.

/** The signed-in user's immutable id (ULID), or null. */
export function userId(session) {
  return (session && session.user_id) || null;
}

/** The role in the acting org (`admin` / `member`), or null. */
export function role(session) {
  return (session && session.org && session.org.role) || null;
}

/** Whether the session is an admin of the org it is acting in. */
export function isAdmin(session) {
  return role(session) === 'admin';
}

/** Whether the acting org is the user's personal org. */
export function isPersonal(session) {
  return Boolean(session && session.org && session.org.personal);
}

/** Every membership, as the server listed it (never null). */
export function memberships(session) {
  return (session && Array.isArray(session.memberships) && session.memberships) || [];
}

/** A membership's display name: its path, else its id. */
export function orgLabel(org) {
  if (!org) return '—';
  return org.name || org.id;
}

/** The display name of the org with id `id`, from the session's memberships. */
export function orgName(session, id) {
  const hit = memberships(session).find((m) => m.id === id);
  return hit ? orgLabel(hit) : id || '—';
}
