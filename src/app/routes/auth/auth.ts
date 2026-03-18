import { expressjwt as jwt } from 'express-jwt';
import * as express from 'express';
import { getJwtSecret } from './token.utils';

const getTokenFromHeaders = (req: express.Request): string | null => {
  if (
    (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Token') ||
    (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer')
  ) {
    return req.headers.authorization.split(' ')[1];
  }
  return null;
};

// Resolve once at module load. If JWT_SECRET is missing in a non-test
// environment, getJwtSecret() throws and the process refuses to start
// rather than silently accepting forgeable tokens.
const secret = getJwtSecret();

const auth = {
  required: jwt({
    secret,
    getToken: getTokenFromHeaders,
    algorithms: ['HS256'],
  }),
  optional: jwt({
    secret,
    credentialsRequired: false,
    getToken: getTokenFromHeaders,
    algorithms: ['HS256'],
  }),
};

export default auth;
