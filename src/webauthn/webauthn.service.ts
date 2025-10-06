import { Injectable, Logger } from '@nestjs/common';
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
import { StoreService } from '../store/store.service';
import { OriginStorageData } from './interfaces/origin.interface';

interface DomainConfig {
  origin: string;
}

@Injectable()
export class WebAuthnService {
  private readonly rpName: string;
  private domainConfigs: DomainConfig[];
  private readonly defaultConfig: DomainConfig;

  constructor(
    private configService: ConfigService,
    private storageService: JsonStorageService,
    private storeService: StoreService,
  ) {
    // Start with empty array - all origins will come from origins.json
    this.domainConfigs = [];

    // Default configuration (fallback) - hardcode instead of using env
    this.defaultConfig = {
      origin: 'http://localhost:3001',
    };

    // Load dynamic origins from storage
    this.loadDynamicOrigins();
  }

  /**
   * Extract rpId from origin URL
   */
  private extractRpId(origin: string): string {
    try {
      const url = new URL(origin);
      return url.hostname;
    } catch {
      throw new Error('Invalid origin URL');
    }
  }

  /**
   * Load dynamic origins from storage on startup
   */
  private async loadDynamicOrigins(): Promise<void> {
    try {
      const originData = await this.storageService.loadOrigins();

      if (originData.origins && originData.origins.length > 0) {
        const dynamicConfigs = originData.origins.map((o) => ({
          origin: o.origin,
        }));

        this.domainConfigs.push(...dynamicConfigs);

        const originsList = dynamicConfigs.map((c) => c.origin).join(', ');
        const logger = new Logger(WebAuthnService.name);
        logger.log(
          `Loaded ${dynamicConfigs.length} dynamic origins: ${originsList}`,
        );
      } else {
        const logger = new Logger(WebAuthnService.name);
        logger.log('No dynamic origins found');
      }
    } catch (error) {
      const logger = new Logger(WebAuthnService.name);
      logger.log(
        'No existing origins file found (this is normal on first run)',
      );
      logger.log('error:', error);
    }
  }

  /**
   * Get domain configuration based on origin
   */
  private getDomainConfig(origin?: string): { origin: string; rpId: string } {
    if (!origin) {
      return {
        origin: this.defaultConfig.origin,
        rpId: this.extractRpId(this.defaultConfig.origin),
      };
    }

    const config = this.domainConfigs.find((c) => c.origin === origin);
    if (config) {
      return {
        origin: config.origin,
        rpId: this.extractRpId(config.origin),
      };
    }

    // If no exact match found, try to find by hostname
    try {
      const originUrl = new URL(origin);
      const foundConfig = this.domainConfigs.find((config) => {
        const configUrl = new URL(config.origin);
        return configUrl.hostname === originUrl.hostname;
      });

      if (foundConfig) {
        return {
          origin: foundConfig.origin,
          rpId: this.extractRpId(foundConfig.origin),
        };
      }
    } catch (error) {
      console.warn('Failed to parse origin URL:', error);
    }

    console.warn(`No configuration found for origin: ${origin}, using default`);
    return {
      origin: this.defaultConfig.origin,
      rpId: this.extractRpId(this.defaultConfig.origin),
    };
  }

  /**
   * Validate if origin is allowed
   */
  private isValidOrigin(origin: string): boolean {
    return this.domainConfigs.some((config) => config.origin === origin);
  }

  async generateRegistrationOptions(
    username: string,
    ethereumAddress: string,
    requestOrigin?: string,
  ): Promise<{
    options: PublicKeyCredentialCreationOptionsJSON;
  }> {
    const domainConfig = this.getDomainConfig(requestOrigin);

    console.log(
      'Generating registration for Ethereum address:',
      ethereumAddress,
    );
    console.log('Using domain config:', domainConfig);

    // Check if user already exists
    const existingUser = await this.storageService.getUserById(ethereumAddress);
    if (existingUser) {
      throw new Error('User with this Ethereum address already exists');
    }

    // Create user with provided Ethereum address as ID
    const user: User = {
      id: ethereumAddress,
      username,
      email: ``,
      authenticators: [],
    };

    const opts: GenerateRegistrationOptionsOpts = {
      rpName: this.rpName,
      rpID: domainConfig.rpId,
      userName: user.username,
      userDisplayName: `${username} (${ethereumAddress.substring(0, 8)}...)`,
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

    await this.storageService.saveChallenge(ethereumAddress, options.challenge);
    await this.storageService.saveUser(user);

    console.log('Registration options generated for:', ethereumAddress);
    console.log('Request origin:', requestOrigin);
    console.log('RP ID used:', domainConfig.rpId);

    return { options };
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
        expectedRPID: domainConfig.rpId,
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

      try {
        await this.storeService.createUserDirectory(ethereumAddress);
        console.log('User directory created for:', ethereumAddress);
      } catch (error) {
        console.error('Failed to create user directory:', error);
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
      rpID: domainConfig.rpId,
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

    const existingAuthenticator = user.authenticators.find(
      (auth) => auth.credentialID === response.id,
    );

    if (existingAuthenticator) {
      try {
        const opts: VerifyAuthenticationResponseOpts = {
          response,
          expectedChallenge,
          expectedOrigin: domainConfig.origin,
          expectedRPID: domainConfig.rpId,
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
      rpID: domainConfig.rpId,
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
        expectedRPID: domainConfig.rpId,
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

  // Admin methods for origin management
  async addOrigin(origin: string): Promise<void> {
    this.extractRpId(origin); // Will throw if invalid

    await this.storageService.addOrigin(origin);

    this.domainConfigs.push({ origin });

    console.log(
      `Origin ${origin} added with rpId: ${this.extractRpId(origin)}`,
    );
  }

  async removeOrigin(origin: string): Promise<boolean> {
    const removed = await this.storageService.removeOrigin(origin);

    if (removed) {
      this.domainConfigs = this.domainConfigs.filter(
        (c) => c.origin !== origin,
      );
      console.log(`Origin ${origin} removed from memory`);
    }

    return removed;
  }

  async listOrigins(): Promise<OriginStorageData> {
    return this.storageService.getAllOrigins();
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
