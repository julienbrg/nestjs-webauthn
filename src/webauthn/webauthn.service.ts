import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  VerifiedRegistrationResponse,
} from '@simplewebauthn/server';
import type {
  GenerateRegistrationOptionsOpts,
  GenerateAuthenticationOptionsOpts,
  VerifyRegistrationResponseOpts,
  VerifyAuthenticationResponseOpts,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import { User, Authenticator } from './interfaces/user.interface';

@Injectable()
export class WebAuthnService {
  private readonly rpID: string;
  private readonly rpName: string;
  private readonly origin: string;

  // In-memory storage for demo - replace with your database
  private users: Map<string, User> = new Map();
  private challenges: Map<string, string> = new Map();

  constructor(private configService: ConfigService) {
    this.rpID = this.configService.get('WEBAUTHN_RP_ID') || 'localhost';
    this.rpName = this.configService.get('WEBAUTHN_RP_NAME') || 'WebAuthn Demo';
    this.origin =
      this.configService.get('WEBAUTHN_ORIGIN') || 'http://localhost:3000';

    console.log('=== WebAuthn Service Configuration ===');
    console.log('Origin:', this.origin);
    console.log('RP ID:', this.rpID);
    console.log('RP Name:', this.rpName);
    console.log('=====================================');
  }

  async generateRegistrationOptions(
    userId: string,
    username: string,
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const user = this.users.get(userId) || {
      id: userId,
      username,
      email: `${username}@example.com`,
      authenticators: [],
    };

    const opts: GenerateRegistrationOptionsOpts = {
      rpName: this.rpName,
      rpID: this.rpID,
      userName: user.username,
      attestationType: 'none',
      excludeCredentials: user.authenticators.map((authenticator) => ({
        id: authenticator.credentialID,
        transports: authenticator.transports,
      })),
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
        requireResidentKey: true,
      },
      supportedAlgorithmIDs: [-7, -257],
    };

    const options = await generateRegistrationOptions(opts);

    // Store challenge for verification
    this.challenges.set(userId, options.challenge);

    // Store user if new
    if (!this.users.has(userId)) {
      this.users.set(userId, user);
    }

    console.log('Generated registration options for user:', userId);
    console.log('Challenge stored:', options.challenge);

    return options;
  }

  async verifyRegistration(
    userId: string,
    response: RegistrationResponseJSON,
  ): Promise<{ verified: boolean; user?: User }> {
    const expectedChallenge = this.challenges.get(userId);
    const user = this.users.get(userId);

    console.log('Verifying registration for user:', userId);
    console.log('Expected challenge:', expectedChallenge);
    console.log('Expected origin:', this.origin);
    console.log('Expected RP ID:', this.rpID);

    if (!expectedChallenge || !user) {
      throw new Error('User or challenge not found');
    }

    let verification: VerifiedRegistrationResponse;
    try {
      const opts: VerifyRegistrationResponseOpts = {
        response,
        expectedChallenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpID,
      };

      verification = await verifyRegistrationResponse(opts);
    } catch (error) {
      console.error('Registration verification failed:', error);
      return { verified: false };
    }

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      const { credential, credentialDeviceType, credentialBackedUp } =
        registrationInfo;

      const newAuthenticator: Authenticator = {
        credentialID: credential.id,
        credentialPublicKey: credential.publicKey,
        counter: credential.counter,
        credentialDeviceType,
        credentialBackedUp,
        transports: credential.transports,
      };

      user.authenticators.push(newAuthenticator);
      this.users.set(userId, user);

      // Clean up challenge
      this.challenges.delete(userId);

      console.log('Registration successful for user:', userId);
      console.log('Authenticator count:', user.authenticators.length);

      return { verified: true, user };
    }

    console.log('Registration verification failed for user:', userId);
    return { verified: false };
  }

  async generateAuthenticationOptions(
    userId: string,
  ): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const user = this.users.get(userId);

    if (!user) {
      throw new Error('User not found');
    }

    const opts: GenerateAuthenticationOptionsOpts = {
      rpID: this.rpID,
      // For true cross-device support, leave allowCredentials empty
      // This allows any passkey for this RP to authenticate
      allowCredentials: [],
      userVerification: 'required',
    };

    const options = await generateAuthenticationOptions(opts);
    this.challenges.set(userId, options.challenge);

    console.log('Generated authentication options for cross-device support');
    console.log('Allowing any credential for RP:', this.rpID);

    return options;
  }

  async verifyAuthentication(
    userId: string,
    response: AuthenticationResponseJSON,
  ): Promise<{ verified: boolean; user?: User }> {
    const expectedChallenge = this.challenges.get(userId);
    const user = this.users.get(userId);

    console.log('Verifying authentication for user:', userId);
    console.log('Response credential ID:', response.id);

    if (!expectedChallenge || !user) {
      throw new Error('User or challenge not found');
    }

    // Try to find existing authenticator
    const existingAuthenticator = user.authenticators.find(
      (auth) => auth.credentialID === response.id,
    );

    if (existingAuthenticator) {
      // Same-device authentication
      try {
        const opts: VerifyAuthenticationResponseOpts = {
          response,
          expectedChallenge,
          expectedOrigin: this.origin,
          expectedRPID: this.rpID,
          credential: {
            id: existingAuthenticator.credentialID,
            publicKey: existingAuthenticator.credentialPublicKey,
            counter: existingAuthenticator.counter,
            transports: existingAuthenticator.transports,
          },
        };

        const verification = await verifyAuthenticationResponse(opts);

        if (verification.verified) {
          existingAuthenticator.counter =
            verification.authenticationInfo.newCounter;
          this.users.set(userId, user);
          this.challenges.delete(userId);
          console.log('Authentication successful');
          return { verified: true, user };
        }
      } catch (error) {
        console.error('Authentication verification failed:', error);
      }
    } else {
      console.log('Credential ID not found - authentication failed');
      console.log(
        'Available credentials:',
        user.authenticators.map((auth) => auth.credentialID),
      );
      console.log('Received credential ID:', response.id);
    }

    console.log('Authentication verification failed for user:', userId);
    return { verified: false };
  }

  // Helper method to get user by ID
  getUser(userId: string): User | undefined {
    return this.users.get(userId);
  }

  // Helper method to check if user exists
  userExists(userId: string): boolean {
    return this.users.has(userId);
  }

  // Debug methods - remove in production
  getAllUsers(): Map<string, User> {
    return this.users;
  }

  getAllChallenges(): Map<string, string> {
    return this.challenges;
  }

  clearAllData(): void {
    this.users.clear();
    this.challenges.clear();
    console.log('All user data and challenges cleared');
  }
}
