# cloudflare-cognito-jwt-verifier
A lightweight JWT verifier for AWS Cognito running on Cloudflare Workers.
This lib fetches, caches JWKS from AWS Cognito, and verifies the JWT token.


## Why
Cloudflare Workers runtime doesn't support Node.js core modules, which means we cannot use common libs like `jsonwebtoken`.

## Install
```shell
npm i --save cloudflare-cognito-jwt-verifier
```
```shell
yarn add cloudflare-cognito-jwt-verifier
```
## Usage
```javascript
import { getVerifier, JwtInvalidError } from 'cloudflare-cognito-jwt-verifier';

const { verify } = getVerifier({
  appClientId: COGNITO_USER_POOL_CLIENT_ID,
  awsRegion: 'us-east-1',
  // see auth tokens
  // https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
  tokenType: 'access',
  userPoolId: COGNITO_USER_POOL_ID,
});

export async function verifyAuth(request: Request) {
  const header = request.headers.get('Authorization');
  if (!header) {
    throw new JwtInvalidError();
  }
  return await verify(header);
}

addEventListener('fetch', (event) => {
  event.passThroughOnException();
  event.respondWith(async (event) => {
    const auth = await verifyAuth(request);
    const userId = auth?.payload.sub;
    return new Response({});
  });
});
```
