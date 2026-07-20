export interface VerifyPublicationOptions {
  origin?: string;
  siteDirectory?: string;
  fetchImpl?: typeof fetch;
}

export interface PublicationVerification {
  origin: string;
  files: number;
}

export function verifyPublication(
  options?: VerifyPublicationOptions
): Promise<PublicationVerification>;
