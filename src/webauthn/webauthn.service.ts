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
import { JsonStorageService } from './services/json-storage.service';

@Injectable()
export class WebAuthnService {
  private readonly rpID: string;
  private readonly rpName: string;
  private readonly origin: string;

  constructor(
    private configService: ConfigService,
    private storageService: JsonStorageService,
  ) {
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
    const existingUser = await this.storageService.getUserById(userId);

    const user = existingUser || {
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
    await this.storageService.saveChallenge(userId, options.challenge);

    // Store user if new
    if (!existingUser) {
      await this.storageService.saveUser(user);
    }

    console.log('Generated registration options for user:', userId);
    console.log('Challenge stored:', options.challenge);

    return options;
  }

  async verifyRegistration(
    userId: string,
    response: RegistrationResponseJSON,
  ): Promise<{ verified: boolean; user?: User }> {
    const expectedChallenge = await this.storageService.getChallenge(userId);
    const user = await this.storageService.getUserById(userId);

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
      await this.storageService.saveUser(user);

      // Clean up challenge
      await this.storageService.deleteChallenge(userId);

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
    const user = await this.storageService.getUserById(userId);

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
    await this.storageService.saveChallenge(userId, options.challenge);

    console.log('Generated authentication options for cross-device support');
    console.log('Allowing any credential for RP:', this.rpID);

    return options;
  }

  async verifyAuthentication(
    userId: string,
    response: AuthenticationResponseJSON,
  ): Promise<{ verified: boolean; user?: User }> {
    const expectedChallenge = await this.storageService.getChallenge(userId);
    const user = await this.storageService.getUserById(userId);

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
          await this.storageService.saveUser(user);
          await this.storageService.deleteChallenge(userId);
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

  async generateUsernamelessAuthenticationOptions(): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const opts: GenerateAuthenticationOptionsOpts = {
      rpID: this.rpID,
      // Empty allowCredentials enables usernameless/discoverable credential authentication
      allowCredentials: [],
      userVerification: 'required',
    };

    const options = await generateAuthenticationOptions(opts);

    // Store challenge with a special key for usernameless auth
    await this.storageService.saveChallenge('usernameless', options.challenge);

    console.log('Generated usernameless authentication options');
    console.log('Challenge stored for usernameless authentication');

    return options;
  }

  async verifyUsernamelessAuthentication(
    response: AuthenticationResponseJSON,
  ): Promise<{ verified: boolean; user?: User }> {
    console.log('Starting usernameless authentication verification');
    console.log('Credential ID from response:', response.id);

    try {
      // Get the stored challenge for usernameless auth
      const expectedChallenge =
        await this.storageService.getChallenge('usernameless');

      if (!expectedChallenge) {
        throw new Error('No challenge found for usernameless authentication');
      }

      // Load all users and find the one with matching credential
      const data = await this.storageService.loadData();
      let matchingUser: User | undefined;
      let matchingAuthenticator: Authenticator | undefined;

      // Search through all users to find the matching credential
      for (const user of Object.values(data.users)) {
        const authenticator = user.authenticators.find(
          (auth) => auth.credentialID === response.id,
        );
        if (authenticator) {
          matchingUser = user;
          matchingAuthenticator = authenticator;
          break;
        }
      }

      if (!matchingUser || !matchingAuthenticator) {
        console.log(
          'No matching user/authenticator found for credential:',
          response.id,
        );
        console.log('Available credentials across all users:');
        for (const [userId, user] of Object.entries(data.users)) {
          console.log(
            `User ${userId}:`,
            user.authenticators.map((auth) => auth.credentialID),
          );
        }
        return { verified: false };
      }

      console.log('Found matching user:', matchingUser.id);

      // Verify the authentication response
      const opts: VerifyAuthenticationResponseOpts = {
        response,
        expectedChallenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpID,
        credential: {
          id: matchingAuthenticator.credentialID,
          publicKey: matchingAuthenticator.credentialPublicKey,
          counter: matchingAuthenticator.counter,
          transports: matchingAuthenticator.transports,
        },
        requireUserVerification: true,
      };

      const verification = await verifyAuthenticationResponse(opts);

      if (verification.verified) {
        // Update counter
        matchingAuthenticator.counter =
          verification.authenticationInfo.newCounter;
        await this.storageService.saveUser(matchingUser);

        // Clean up the usernameless challenge
        await this.storageService.deleteChallenge('usernameless');

        console.log(
          'Usernameless authentication successful for user:',
          matchingUser.id,
        );
        return { verified: true, user: matchingUser };
      }

      console.log('Usernameless authentication verification failed');
      return { verified: false };
    } catch (error) {
      console.error('Usernameless authentication error:', error);
      return { verified: false };
    }
  }

  // Helper method to get user by ID
  async getUser(userId: string): Promise<User | undefined> {
    return this.storageService.getUserById(userId);
  }

  // Helper method to check if user exists
  async userExists(userId: string): Promise<boolean> {
    const user = await this.storageService.getUserById(userId);
    return !!user;
  }

  // Debug methods - remove in production
  async getStorageStats() {
    return this.storageService.getStorageStats();
  }

  async clearAllData(): Promise<void> {
    await this.storageService.clearAll();
    console.log('All user data and challenges cleared');
  }
}
