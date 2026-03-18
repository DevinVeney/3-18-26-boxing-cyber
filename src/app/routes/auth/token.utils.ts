import * as jwt from 'jsonwebtoken';

/**
 * Resolves the JWT signing/verification secret.
 *
 * SECURITY: This intentionally throws at call time (effectively module-load
 * time for auth.ts) when JWT_SECRET is missing. The previous hardcoded
 * fallback ('superSecret') allowed anyone to forge valid tokens for any user
 * id if the env var was absent in a deployed environment.
 *
 * The only permitted fallback is under NODE_ENV === 'test', where the unit
 * suite mocks Prisma and never round-trips tokens through a real verifier.
 */
export const getJwtSecret = (): string => {
  const secret = process.env.JWT_SECRET;
  if (secret && secret.length > 0) {
    return secret;
  }
  if (process.env.NODE_ENV === 'test') {
    return 'test-only-secret-not-for-production';
  }
  throw new Error(
    'FATAL: JWT_SECRET environment variable is not set. Refusing to start with a forgeable signing key.'
  );
};

const generateToken = (id: number): string =>
  jwt.sign({ user: { id } }, getJwtSecret(), {
    expiresIn: '60d',
  });

export default generateToken;
