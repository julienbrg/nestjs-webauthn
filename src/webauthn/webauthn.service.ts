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

interface DomainConfig {
  origin: string;
  rpId: string;
}

@Injectable()
export class WebAuthnService {
  private readonly rpName: string;
  private readonly domainConfigs: DomainConfig[];
  private readonly defaultConfig: DomainConfig;

  constructor(
    private configService: ConfigService,
    private storageService: JsonStorageService,
    private storeService: StoreService,
  ) {
    this.rpName = this.configService.get('WEBAUTHN_RP_NAME') || 'WebAuthn Demo';

    // Define domain-specific configurations
    this.domainConfigs = [
      {
        origin: 'http://localhost:3001',
        rpId: 'localhost',
      },
      {
        origin: 'https://genji-app.netlify.app',
        rpId: 'genji-app.netlify.app',
      },
      {
        origin: 'https://d2u.w3hc.org',
        rpId: 'd2u.w3hc.org',
      },
    ];

    // Default configuration (fallback)
    this.defaultConfig = {
      origin:
        this.configService.get('WEBAUTHN_ORIGIN') || 'http://localhost:3001',
      rpId: this.configService.get('WEBAUTHN_RP_ID') || 'localhost',
    };

    console.log('=== WebAuthn Service Configuration ===');
    console.log('RP Name:', this.rpName);
    console.log('Domain Configs:', this.domainConfigs);
    console.log('Default Config:', this.defaultConfig);
    console.log('=====================================');
  }

  /**
   * Get domain configuration based on origin
   */
  private getDomainConfig(origin?: string): DomainConfig {
    if (!origin) {
      return this.defaultConfig;
    }

    const config = this.domainConfigs.find(
      (config) => config.origin === origin,
    );
    if (config) {
      return config;
    }

    // If no exact match found, try to find by hostname
    try {
      const originUrl = new URL(origin);
      const foundConfig = this.domainConfigs.find((config) => {
        const configUrl = new URL(config.origin);
        return configUrl.hostname === originUrl.hostname;
      });

      if (foundConfig) {
        return foundConfig;
      }
    } catch (origin) {
      console.warn('Failed to parse origin URL:', origin);
    }

    console.warn(`No configuration found for origin: ${origin}, using default`);
    return this.defaultConfig;
  }

  /**
   * Validate if origin is allowed
   */
  private isValidOrigin(origin: string): boolean {
    return this.domainConfigs.some((config) => config.origin === origin);
  }

  /**
   * Generate a new Ethereum wallet and return address and private key as strings
   */
  private generateEthereumWallet(): { address: string; privateKey: string } {
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
    _userId: string,
    username: string,
    requestOrigin?: string,
  ): Promise<{
    options: PublicKeyCredentialCreationOptionsJSON;
    ethereumAddress: string;
    privateKey: string;
  }> {
    const domainConfig = this.getDomainConfig(requestOrigin);

    // Generate new Ethereum wallet
    const { address, privateKey } = this.generateEthereumWallet();

    console.log('Generated new Ethereum wallet:', address);
    console.log('Using domain config:', domainConfig);

    // Check if user already exists (very unlikely collision)
    const existingUser = await this.storageService.getUserById(address);
    if (existingUser) {
      throw new Error('Wallet address collision detected. Please try again.');
    }

    const user: User = {
      id: address,
      privateKey: privateKey,
      username,
      email: ``,
      authenticators: [],
    };

    const opts: GenerateRegistrationOptionsOpts = {
      rpName: this.rpName,
      rpID: domainConfig.rpId, // Use domain-specific RP ID
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
    console.log('Request origin:', requestOrigin);
    console.log('RP ID used:', domainConfig.rpId);

    return {
      options,
      ethereumAddress: address,
      privateKey: privateKey,
    };
  }

  async verifyRegistration(
    ethereumAddress: string,
    response: RegistrationResponseJSON,
    requestOrigin?: string,
  ): Promise<{ verified: boolean; user?: User }> {
    const domainConfig = this.getDomainConfig(requestOrigin);

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
        expectedOrigin: domainConfig.origin,
        expectedRPID: domainConfig.rpId, // Use domain-specific RP ID
      };

      console.log('Verifying registration with:', {
        expectedOrigin: domainConfig.origin,
        expectedRPID: domainConfig.rpId,
        requestOrigin,
      });

      verification = await verifyRegistrationResponse(opts);
    } catch (error) {
      console.error('Registration verification failed:', error);
      console.error('Domain config used:', domainConfig);
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
    requestOrigin?: string,
  ): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const domainConfig = this.getDomainConfig(requestOrigin);

    const user = await this.storageService.getUserById(ethereumAddress);
    if (!user) {
      throw new Error('User not found');
    }

    const opts: GenerateAuthenticationOptionsOpts = {
      rpID: domainConfig.rpId, // Use domain-specific RP ID
      allowCredentials: [],
      userVerification: 'required',
    };

    const options = await generateAuthenticationOptions(opts);
    await this.storageService.saveChallenge(ethereumAddress, options.challenge);

    console.log('Authentication options generated for:', ethereumAddress);
    console.log('Request origin:', requestOrigin);
    console.log('RP ID used:', domainConfig.rpId);

    return options;
  }

  async verifyAuthentication(
    ethereumAddress: string,
    response: AuthenticationResponseJSON,
    requestOrigin?: string,
  ): Promise<{ verified: boolean; user?: User }> {
    const domainConfig = this.getDomainConfig(requestOrigin);

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
      try {
        const opts: VerifyAuthenticationResponseOpts = {
          response,
          expectedChallenge,
          expectedOrigin: domainConfig.origin,
          expectedRPID: domainConfig.rpId, // Use domain-specific RP ID
          credential: {
            id: existingAuthenticator.credentialID,
            publicKey: existingAuthenticator.credentialPublicKey,
            counter: existingAuthenticator.counter,
            transports: existingAuthenticator.transports,
          },
        };

        console.log('Verifying authentication with:', {
          expectedOrigin: domainConfig.origin,
          expectedRPID: domainConfig.rpId,
          requestOrigin,
        });

        const verification = await verifyAuthenticationResponse(opts);

        if (verification.verified) {
          existingAuthenticator.counter =
            verification.authenticationInfo.newCounter;
          await this.storageService.saveUser(user);
          await this.storageService.deleteChallenge(ethereumAddress);
          console.log('Authentication successful for:', ethereumAddress);
          return { verified: true, user };
        }
      } catch (error) {
        console.error('Authentication verification failed:', error);
        console.error('Domain config used:', domainConfig);
      }
    }

    return { verified: false };
  }

  async generateUsernamelessAuthenticationOptions(
    requestOrigin?: string,
  ): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const domainConfig = this.getDomainConfig(requestOrigin);

    const opts: GenerateAuthenticationOptionsOpts = {
      rpID: domainConfig.rpId, // Use domain-specific RP ID
      allowCredentials: [],
      userVerification: 'required',
    };

    const options = await generateAuthenticationOptions(opts);
    await this.storageService.saveChallenge('usernameless', options.challenge);

    console.log('Usernameless authentication options generated');
    console.log('Request origin:', requestOrigin);
    console.log('RP ID used:', domainConfig.rpId);

    return options;
  }

  async verifyUsernamelessAuthentication(
    response: AuthenticationResponseJSON,
    requestOrigin?: string,
  ): Promise<{ verified: boolean; user?: User }> {
    const domainConfig = this.getDomainConfig(requestOrigin);

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
        expectedOrigin: domainConfig.origin,
        expectedRPID: domainConfig.rpId, // Use domain-specific RP ID
        credential: {
          id: matchingAuthenticator.credentialID,
          publicKey: matchingAuthenticator.credentialPublicKey,
          counter: matchingAuthenticator.counter,
          transports: matchingAuthenticator.transports,
        },
        requireUserVerification: true,
      };

      console.log('Verifying usernameless authentication with:', {
        expectedOrigin: domainConfig.origin,
        expectedRPID: domainConfig.rpId,
        requestOrigin,
      });

      const verification = await verifyAuthenticationResponse(opts);

      if (verification.verified) {
        matchingAuthenticator.counter =
          verification.authenticationInfo.newCounter;
        await this.storageService.saveUser(matchingUser);
        await this.storageService.deleteChallenge('usernameless');
        console.log(
          'Usernameless authentication successful for:',
          matchingUser.id,
        );
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

  // Utility methods
  getAllowedOrigins(): string[] {
    return this.domainConfigs.map((config) => config.origin);
  }

  getDomainConfigs(): DomainConfig[] {
    return [...this.domainConfigs];
  }
}
