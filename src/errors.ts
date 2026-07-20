export class PolicyError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'PolicyError';
    this.code = code;
  }
}
