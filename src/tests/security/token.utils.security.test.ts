/**
 * Regression tests for C1 (CRITICAL): hardcoded JWT secret fallback.
 *
 * Prior to the fix, `process.env.JWT_SECRET || 'superSecret'` meant any
 * deployment missing the env var would accept tokens forged with the public
 * string 'superSecret', giving an attacker full account takeover of any user
 * id. These tests lock in the fail-closed behaviour.
 */

describe('JWT secret resolution (C1 regression)', () => {
  const ORIGINAL_ENV = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV };
  });

  afterAll(() => {
    process.env = ORIGINAL_ENV;
  });

  test('throws at resolve time when JWT_SECRET is absent in a non-test environment', () => {
    delete process.env.JWT_SECRET;
    process.env.NODE_ENV = 'production';

    // Re-require after env mutation so module-level reads see the new values.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { getJwtSecret } = require('../../app/routes/auth/token.utils');

    expect(() => getJwtSecret()).toThrow(/JWT_SECRET/);
  });

  test('throws when JWT_SECRET is the empty string (not just undefined)', () => {
    process.env.JWT_SECRET = '';
    process.env.NODE_ENV = 'production';

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { getJwtSecret } = require('../../app/routes/auth/token.utils');

    expect(() => getJwtSecret()).toThrow(/JWT_SECRET/);
  });

  test('returns the configured secret when JWT_SECRET is set', () => {
    process.env.JWT_SECRET = 'a-real-256-bit-random-value';
    process.env.NODE_ENV = 'production';

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { getJwtSecret } = require('../../app/routes/auth/token.utils');

    expect(getJwtSecret()).toBe('a-real-256-bit-random-value');
  });

  test('never returns the legacy hardcoded fallback', () => {
    // Guard against someone re-adding `|| 'superSecret'` in a refactor.
    delete process.env.JWT_SECRET;
    process.env.NODE_ENV = 'production';

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { getJwtSecret } = require('../../app/routes/auth/token.utils');

    let resolved: string | undefined;
    try {
      resolved = getJwtSecret();
    } catch {
      // expected path — but if it somehow resolves, it must not be the
      // known-compromised value.
    }
    expect(resolved).not.toBe('superSecret');
  });
});
