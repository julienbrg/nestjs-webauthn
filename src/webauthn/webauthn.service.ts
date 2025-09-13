import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as ethers from 'ethers';
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
import { StoreService } from '../store/store.service';

@Injectable()
export class WebAuthnService {
  private readonly rpID: string;
  private readonly rpName: string;
  private readonly origin: string;

  constructor(
    private configService: ConfigService,
    private storageService: JsonStorageService,
    private storeService: StoreService, // Add StoreService dependency
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

  /**
   * Generate a new Ethereum wallet and return address and private key as strings
   */
  private generateEthereumWallet(): { address: string; privateKey: string } {
    /* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access */
    try {
      const wallet = ethers.Wallet.createRandom();
      return {
        address: wallet.address,
        privateKey: wallet.privateKey,
      };
    } catch (error) {
      console.error('Failed to create Ethereum wallet:', error);
      throw new Error('Failed to generate Ethereum wallet');
    }
  }

  async generateRegistrationOptions(
    _userId: string, // Ignored - we generate Ethereum address
    username: string,
  ): Promise<{
    options: PublicKeyCredentialCreationOptionsJSON;
    ethereumAddress: string;
    privateKey: string;
  }> {
    // Generate new Ethereum wallet
    const { address, privateKey } = this.generateEthereumWallet();

    console.log('Generated new Ethereum wallet:', address);

    // Check if user already exists (very unlikely collision)
    const existingUser = await this.storageService.getUserById(address);
    if (existingUser) {
      throw new Error('Wallet address collision detected. Please try again.');
    }

    const user: User = {
      id: address, // Ethereum address as string
      privateKey: privateKey, // Private key as string
      username,
      email: ``,
      authenticators: [],
    };

    // Simple WebAuthn options - let it generate its own userID internally
    const opts: GenerateRegistrationOptionsOpts = {
      rpName: this.rpName,
      rpID: this.rpID,
      userName: user.username,
      userDisplayName: `${username} (${address.substring(0, 8)}...)`,
      attestationType: 'none',
      excludeCredentials: [],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
        requireResidentKey: true,
      },
      supportedAlgorithmIDs: [-7, -257],
    };

    const options = await generateRegistrationOptions(opts);

    // Store challenge and user using Ethereum address as key
    await this.storageService.saveChallenge(address, options.challenge);
    await this.storageService.saveUser(user);

    console.log('Registration options generated for:', address);

    return {
      options,
      ethereumAddress: address,
      privateKey: privateKey,
    };
  }

  async verifyRegistration(
    ethereumAddress: string,
    response: RegistrationResponseJSON,
  ): Promise<{ verified: boolean; user?: User }> {
    const expectedChallenge =
      await this.storageService.getChallenge(ethereumAddress);
    const user = await this.storageService.getUserById(ethereumAddress);

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
      await this.storageService.deleteChallenge(ethereumAddress);

      // Create user directory for file storage
      try {
        await this.storeService.createUserDirectory(ethereumAddress);
        console.log('User directory created for:', ethereumAddress);
      } catch (error) {
        console.error('Failed to create user directory:', error);
        // Don't fail registration if directory creation fails
      }

      console.log('Registration successful for:', ethereumAddress);
      return { verified: true, user };
    }

    return { verified: false };
  }

  async generateAuthenticationOptions(
    ethereumAddress: string,
  ): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const user = await this.storageService.getUserById(ethereumAddress);
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
    await this.storageService.saveChallenge(ethereumAddress, options.challenge);

    return options;
  }

  async verifyAuthentication(
    ethereumAddress: string,
    response: AuthenticationResponseJSON,
  ): Promise<{ verified: boolean; user?: User }> {
    const expectedChallenge =
      await this.storageService.getChallenge(ethereumAddress);
    const user = await this.storageService.getUserById(ethereumAddress);

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
          await this.storageService.deleteChallenge(ethereumAddress);
          return { verified: true, user };
        }
      } catch (error) {
        console.error('Authentication verification failed:', error);
      }
    }

    return { verified: false };
  }

  async generateUsernamelessAuthenticationOptions(): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const opts: GenerateAuthenticationOptionsOpts = {
      rpID: this.rpID,
      allowCredentials: [],
      userVerification: 'required',
    };

    const options = await generateAuthenticationOptions(opts);
    await this.storageService.saveChallenge('usernameless', options.challenge);

    return options;
  }

  async verifyUsernamelessAuthentication(
    response: AuthenticationResponseJSON,
  ): Promise<{ verified: boolean; user?: User }> {
    try {
      const expectedChallenge =
        await this.storageService.getChallenge('usernameless');
      if (!expectedChallenge) {
        throw new Error('No challenge found');
      }

      const data = await this.storageService.loadData();
      let matchingUser: User | undefined;
      let matchingAuthenticator: Authenticator | undefined;

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
        return { verified: false };
      }

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
        matchingAuthenticator.counter =
          verification.authenticationInfo.newCounter;
        await this.storageService.saveUser(matchingUser);
        await this.storageService.deleteChallenge('usernameless');
        return { verified: true, user: matchingUser };
      }

      return { verified: false };
    } catch (error) {
      console.error('Usernameless authentication error:', error);
      return { verified: false };
    }
  }

  // Helper methods
  async getUser(ethereumAddress: string): Promise<User | undefined> {
    return this.storageService.getUserById(ethereumAddress);
  }

  async userExists(ethereumAddress: string): Promise<boolean> {
    const user = await this.storageService.getUserById(ethereumAddress);
    return !!user;
  }

  async getStorageStats() {
    return this.storageService.getStorageStats();
  }

  async clearAllData(): Promise<void> {
    await this.storageService.clearAll();
    console.log('All user data and challenges cleared');
  }
}
