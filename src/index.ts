import { jwtVerify, JWK, errors, importJWK } from 'jose';
import decode from './decode';
import { JwtInvalidError } from './errors';
import { JwtCognitoClaimValidationError, JwtVerificationError, JwksNoMatchingKeyError } from './errors';

export type AWS_JWK = {
  kid: string;
  alg: string;
  kty: string;
  e: string;
  n: string;
  use: string;
};

function handleVerificationError(e: Error) {
  if (
    e instanceof errors.JOSEError &&
    ['ERR_JWT_CLAIM_INVALID', 'ERR_JWT_EXPIRED', 'ERR_JWT_MALFORMED'].includes(e.code)
  ) {
    throw new JwtVerificationError(e);
  }

  if (isNoMatchingKeyError(e)) {
    throw new JwksNoMatchingKeyError(e);
  }

  throw e;
}

function isNoMatchingKeyError(e: Error) {
  return e instanceof errors.JOSEError && e.code === 'ERR_JWKS_NO_MATCHING_KEY';
}

function validateTokenUseClaim(payload: any, tokenType: 'id' | 'access') {
  if (!payload.token_use || payload.token_use !== tokenType) {
    const originalError = new JwtCognitoClaimValidationError(
      'token_use',
      `expected "${tokenType}", got "${payload.token_use}"`,
    );

    throw new JwtVerificationError(originalError);
  }
}

const jwkCache: { [key: string]: JWK } = {};

export async function getJwkByKid(iss: string, kid: string) {
  if (kid in jwkCache) {
    return jwkCache[kid];
  }
  const jwksEndpoint = iss + '/.well-known/jwks.json';
  const result = await fetch(jwksEndpoint, {
    cf: {
      cacheEverything: true,
      cacheTtlByStatus: {
        '200-299': 864000, // 10 days
        404: 1,
        '500-599': 0,
      },
    },
  });
  const { keys } = (await result.json()) as {
     keys: (JWK & AWS_JWK)[]
  };

  for (const key of keys) {
    jwkCache[key.kid] = key;
  }
  return jwkCache[kid];
}

export function getJwt(str: string) {
  if (!str || str.substring(0, 6) !== 'Bearer') {
    return null;
  }
  return str.substring(6).trim();
}

export function getVerifier({
  awsRegion,
  userPoolId,
  appClientId,
  tokenType,
}: {
  awsRegion: string;
  userPoolId: string;
  appClientId: string;
  tokenType: 'id' | 'access';
}) {
  if (!crypto || !crypto.subtle) throw new Error('Crypto not supported, are you deploying to Cloudflare Worker?');

  return {
    verify: async (authHeader: string) => {
      const token = getJwt(authHeader);
      if (!token) throw new JwtInvalidError();
      const { header, payload } = decode(token);
      const { kid } = header;

      if (!payload.iss || !kid) throw new JwtInvalidError();

      const jwk = await getJwkByKid(payload.iss, kid);

      try {
        const joseOptions = {
          profile: tokenType === 'id' ? 'id_token' : undefined,
          audience: tokenType === 'id' ? appClientId : undefined,
          issuer: `https://cognito-idp.${awsRegion}.amazonaws.com/${userPoolId}`,
        };

        const key = await importJWK(jwk);
        const result = await jwtVerify(token, key, joseOptions);
        validateTokenUseClaim(payload, tokenType);

        return result;
      } catch (e) {
        handleVerificationError(e as Error);
      }
    },
  };
}

export function isJwtError(e: Error) {
  if (e instanceof JwksNoMatchingKeyError || e instanceof JwtVerificationError || e instanceof JwtInvalidError || e instanceof JwtCognitoClaimValidationError) {
    return true
  }
  return false;
}

export {
  JwtCognitoClaimValidationError,
  JwtVerificationError,
  JwksNoMatchingKeyError,
  JwtInvalidError,
} from './errors';
export * as decode from './decode';
export type { JWK, JWTPayload, JWTVerifyResult } from 'jose';
