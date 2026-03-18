/**
 * Regression tests for C2 (CRITICAL) + H3 (HIGH):
 *
 *   C2 — Prisma operator injection via req.query.
 *        Express's extended query parser turns `?tag[not]=x` into
 *        `{ tag: { not: 'x' } }`. If that object reaches a Prisma filter
 *        position unmodified, it becomes `{ name: { not: 'x' } }` — a valid
 *        Prisma operator that inverts/bypasses the intended filter.
 *
 *   H3 — Unbounded `limit` lets a client request the entire table, which
 *        hydrates every `favoritedBy` relation (full User rows) into memory.
 *
 * These tests assert that malicious payloads are neutralised before the
 * Prisma call is made, by inspecting the arguments the mocked client receives.
 */

/* eslint-disable @typescript-eslint/no-explicit-any --
   Inspecting jest-mock-extended call arguments over Prisma's recursively
   self-referential generic types is intractable without `any` shims; this
   matches the pattern in the existing service test files. */

// MUST be first: registers the jest.mock before article.service loads prisma.
import prismaMock from '../prisma-mock';
import { getArticles } from '../../app/routes/article/article.service';

describe('Article query hardening (C2 / H3 regression)', () => {
  beforeEach(() => {
    // @ts-expect-error — jest-mock-extended deep-mock vs Prisma recursive generics
    prismaMock.article.count.mockResolvedValue(0);
    // findMany returns [] so the mapper loop is a no-op
    prismaMock.article.findMany.mockResolvedValue([]);
  });

  const lastFindManyArgs = (callIndex = 0): any =>
    prismaMock.article.findMany.mock.calls[callIndex][0];

  test('C2: object-valued `tag` (operator injection) is dropped, not forwarded to Prisma', async () => {
    // Simulates: GET /api/articles?tag[not]=__nonexistent__
    const maliciousQuery = { tag: { not: '__nonexistent__' } };

    await getArticles(maliciousQuery, undefined);

    const callArgs = lastFindManyArgs();
    const andClauses: any[] = callArgs?.where?.AND ?? [];

    // No clause should reference tagList when the tag param was not a string.
    const hasTagClause = andClauses.some(
      (clause) =>
        clause && Object.prototype.hasOwnProperty.call(clause, 'tagList')
    );
    expect(hasTagClause).toBe(false);

    // Belt-and-braces: the injected operator object must not appear anywhere
    // in the serialised query.
    expect(JSON.stringify(callArgs)).not.toContain('__nonexistent__');
  });

  test('C2: object-valued `author` is dropped; string `author` still works', async () => {
    // Malicious: { author: { not: '' } } — dropped
    await getArticles({ author: { not: '' } }, undefined);
    let authorAnd: any[] =
      lastFindManyArgs(0)?.where?.AND?.[0]?.author?.AND ?? [];
    expect(authorAnd).toHaveLength(0);

    // Legitimate: string author — preserved
    await getArticles({ author: 'alice' }, undefined);
    authorAnd = lastFindManyArgs(1)?.where?.AND?.[0]?.author?.AND ?? [];
    expect(authorAnd).toEqual([{ username: { equals: 'alice' } }]);
  });

  test('H3: `limit` is clamped to a safe upper bound', async () => {
    await getArticles({ limit: '9999999' }, undefined);

    const callArgs = lastFindManyArgs();
    expect(callArgs?.take).toBeLessThanOrEqual(100);
    expect(callArgs?.take).toBeGreaterThan(0);
  });

  test('H3: non-numeric / NaN `limit` falls back to the default, not 0 or NaN', async () => {
    await getArticles({ limit: { injected: true } }, undefined);

    const callArgs = lastFindManyArgs();
    expect(Number.isFinite(callArgs?.take)).toBe(true);
    expect(callArgs?.take).toBe(10);
  });

  test('H3: negative `offset` is clamped to 0', async () => {
    await getArticles({ offset: '-50' }, undefined);

    const callArgs = lastFindManyArgs();
    expect(callArgs?.skip).toBe(0);
  });
});
