export class JwksNoMatchingKeyError extends Error {
  public originalError: Error;
  constructor(originalError: Error) {
    super(`Cannot find matching key in key set`);

    this.name = this.constructor.name;
    this.originalError = originalError;
    this.stack = new Error().stack;
  }
}

export class JwtCognitoClaimValidationError extends Error {
  public claim: string;
  constructor(claim: string, message: string) {
    super(`Claim "${claim}" validation failed: ${message}`);

    this.name = this.constructor.name;
    this.claim = claim;
    this.stack = new Error().stack;
  }
}

export class JwtVerificationError extends Error {
  public originalError: Error;
  constructor(originalError: Error) {
    super(`JWT verification failed: ${originalError.message}`);

    this.name = this.constructor.name;
    this.originalError = originalError;
    this.stack = new Error().stack;
  }
}

export class JwtInvalidError extends Error {
  constructor() {
    super('JWT is invalid.');
    this.name = this.constructor.name;
    this.stack = new Error().stack;
  }
}
