# RealWorld API — Security Audit

A security review of the [RealWorld](https://github.com/gothinkster/realworld) Node/Express/Prisma
reference implementation: four vulnerabilities identified, remediated, and pinned by
regression tests that fail if the fix is ever reverted.

> **Provenance.** The application code is the upstream
> [`node-express-realworld-example-app`](https://github.com/gothinkster/realworld-example-apps),
> not my work. My contribution is the audit — the findings below, the fixes in
> `src/app/`, and the regression suites in `src/tests/security/`.

## Findings

| ID | Severity | Class | Location |
|----|----------|-------|----------|
| C1 | Critical | Forgeable authentication tokens | `routes/auth/token.utils.ts` |
| C2 | Critical | ORM operator injection | `routes/article/article.service.ts` |
| H3 | High | Unbounded pagination → memory exhaustion | `routes/article/article.service.ts` |
| M5 | Medium | Stored URL-scheme injection (XSS) | `routes/auth/auth.service.ts` |

---

### C1 — Hardcoded JWT secret fallback

**Before.** Token signing resolved its key as `process.env.JWT_SECRET || 'superSecret'`.

Any deployment where the environment variable was absent — a misconfigured container, a
missing CI secret, a new staging box — would silently fall back to a string published in
a public repository. An attacker forges a token for any `user.id` and takes over the
account. There is no error, no log line, and no observable difference from correct
operation.

**After.** Secret resolution throws at call time when `JWT_SECRET` is missing, so the
process fails closed rather than serving forgeable tokens. `NODE_ENV === 'test'` is the
single permitted exception, since the unit suite mocks Prisma and never round-trips a
token through a real verifier.

### C2 — Prisma operator injection through the query string

**Before.** Filter values were read straight off `req.query` into Prisma `where` clauses.

Express's extended query parser expands bracket syntax into objects: `?tag[not]=x`
arrives as `{ tag: { not: 'x' } }`. Dropped into a filter position unmodified, that
becomes `{ name: { not: 'x' } }` — a *valid Prisma operator* that inverts the filter.
The same shape reaches `contains` and `startsWith`, so an attacker rewrites query
semantics from the URL without ever touching SQL.

**After.** An `asString()` coercion accepts primitive strings and rejects anything else,
so an object can no longer reach an operator position.

### H3 — Unbounded pagination

**Before.** `limit` was passed to Prisma as supplied.

Each article row hydrates its `favoritedBy` relation — full `User` records. A single
request with a large enough `limit` pulls the entire table and every associated user
into memory. One unauthenticated request, one process down.

**After.** `limit` is clamped to 100 and `offset` floored at 0, with non-numeric input
falling back to defaults rather than `NaN`.

### M5 — Stored URL-scheme injection in profile images

**Before.** `createUser` and `updateUser` persisted the `image` field verbatim.

RealWorld front-ends render that value into navigable contexts — an `<a href>` on the
settings page. A stored `javascript:` or `data:` URI therefore becomes persistent XSS,
served to every visitor of that profile, from a field that looks like plain user data.

**After.** Schemes are allow-listed to `http` and `https`, rejecting anything else with
a 422. Empty and absent values still pass through so the Prisma schema default applies.

---

## Regression tests

Each fix is locked in by a test that asserts the *vulnerable* behaviour is gone, rather
than only that the happy path still works:

```
src/tests/security/
├── token.utils.security.test.ts       # C1 — fails closed without JWT_SECRET
├── article.query.security.test.ts     # C2 + H3 — inspects args reaching mocked Prisma
└── image.validation.security.test.ts  # M5 — scheme allow-list
```

The C2 and H3 tests work by asserting against the arguments the **mocked Prisma client**
receives, so they verify that malicious payloads are neutralised *before* the database
call is constructed — not merely that the endpoint returns a tidy-looking response.

```bash
npm install
npx prisma generate
npm test
```

Requires `DATABASE_URL` and `JWT_SECRET` in `.env`. Per C1, the application will refuse
to start without the latter — that is the fix working.

## Notes for reviewers

- Severity labels follow a simple exploitability × impact reading; C1 and C2 are marked
  critical because both are unauthenticated and yield full account or data compromise.
- The audit covers authentication, query construction, and stored-value rendering. It is
  not a full review — rate limiting, CORS policy, and dependency currency were out of
  scope.
