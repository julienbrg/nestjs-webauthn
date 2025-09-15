import type {
  AuthenticatorTransportFuture,
  CredentialDeviceType,
  Base64URLString,
} from '@simplewebauthn/server';

export interface User {
  id: string; // Ethereum address
  username: string;
  email: string;
  authenticators: Authenticator[];
}

export interface Authenticator {
  credentialID: Base64URLString;
  credentialPublicKey: Uint8Array;
  counter: number;
  credentialDeviceType: CredentialDeviceType;
  credentialBackedUp: boolean;
  transports?: AuthenticatorTransportFuture[];
}
