import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
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
export class WebAuthnService implements OnModuleInit {
  private readonly logger = new Logger(WebAuthnService.name);
  private rpID: string;
  private rpName: string = 'D2U WebAuthn';
  private expectedOrigin: string;

  constructor(
    private configService: ConfigService,
    private storageService: JsonStorageService,
    private storeService: StoreService,
  ) {
    this.rpID = this.configService.get('WEBAUTHN_RP_ID') || 'localhost';
    this.expectedOrigin =
      this.configService.get('WEBAUTHN_EXPECTED_ORIGIN') ||
      'http://localhost:3000';
  }

  async onModuleInit(): Promise<void> {
    this.logger.log(`WebAuthn service initialized`);
    this.logger.log(`RP ID: ${this.rpID}`);
    this.logger.log(`Expected Origin: ${this.expectedOrigin}`);
    return Promise.resolve();
  }

  /**
   * Extract rpId from origin URL
   */
  private extractRpId(origin: string): string {
    try {
      const url = new URL(origin);
      return url.hostname;
    } catch {
      return this.rpID; // fallback to configured RP ID
    }
  }

  async generateRegistrationOptions(
    username: string,
    ethereumAddress: string,
    requestOrigin?: string,
  ): Promise<{
    options: PublicKeyCredentialCreationOptionsJSON;
  }> {
    const rpId = requestOrigin ? this.extractRpId(requestOrigin) : this.rpID;

    this.logger.debug(
      `Generating registration for Ethereum address: ${ethereumAddress}`,
    );
    this.logger.debug(`Using RP ID: ${rpId}`);

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
      rpID: rpId,
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

    this.logger.debug(`Registration options generated for: ${ethereumAddress}`);

    return { options };
  }

  async verifyRegistration(
    ethereumAddress: string,
    response: RegistrationResponseJSON,
    requestOrigin?: string,
  ): Promise<{ verified: boolean; user?: User }> {
    const origin = requestOrigin || this.expectedOrigin;
    const rpId = this.extractRpId(origin);

    const expectedChallenge =
      await this.storageService.getChallenge(ethereumAddress);
    const user = await this.storageService.getUserById(ethereumAddress);

    if (!expectedChallenge || !user) {
      throw new Error('User or challenge not found');
    }

    try {
      const opts: VerifyRegistrationResponseOpts = {
        response,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpId,
      };

      this.logger.debug('Verifying registration with:', {
        expectedOrigin: origin,
        expectedRPID: rpId,
      });

      const verification = await verifyRegistrationResponse(opts);

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
          this.logger.log(`User directory created for: ${ethereumAddress}`);
        } catch (error) {
          this.logger.error('Failed to create user directory:', error);
        }

        this.logger.log(`Registration successful for: ${ethereumAddress}`);
        return { verified: true, user };
      }

      return { verified: false };
    } catch (error) {
      this.logger.error('Registration verification failed:', error);
      return { verified: false };
    }
  }

  async generateAuthenticationOptions(
    ethereumAddress: string,
    requestOrigin?: string,
  ): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const rpId = requestOrigin ? this.extractRpId(requestOrigin) : this.rpID;

    const user = await this.storageService.getUserById(ethereumAddress);
    if (!user) {
      throw new Error('User not found');
    }

    const opts: GenerateAuthenticationOptionsOpts = {
      rpID: rpId,
      allowCredentials: [],
      userVerification: 'required',
    };

    const options = await generateAuthenticationOptions(opts);
    await this.storageService.saveChallenge(ethereumAddress, options.challenge);

    this.logger.debug(
      `Authentication options generated for: ${ethereumAddress}`,
    );

    return options;
  }

  async verifyAuthentication(
    ethereumAddress: string,
    response: AuthenticationResponseJSON,
    requestOrigin?: string,
  ): Promise<{ verified: boolean; user?: User }> {
    const origin = requestOrigin || this.expectedOrigin;
    const rpId = this.extractRpId(origin);

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
          expectedOrigin: origin,
          expectedRPID: rpId,
          credential: {
            id: existingAuthenticator.credentialID,
            publicKey: existingAuthenticator.credentialPublicKey,
            counter: existingAuthenticator.counter,
            transports: existingAuthenticator.transports,
          },
        };

        this.logger.debug('Verifying authentication with:', {
          expectedOrigin: origin,
          expectedRPID: rpId,
        });

        const verification = await verifyAuthenticationResponse(opts);

        if (verification.verified) {
          existingAuthenticator.counter =
            verification.authenticationInfo.newCounter;
          await this.storageService.saveUser(user);
          await this.storageService.deleteChallenge(ethereumAddress);
          this.logger.log(`Authentication successful for: ${ethereumAddress}`);
          return { verified: true, user };
        }
      } catch (error) {
        this.logger.error('Authentication verification failed:', error);
      }
    }

    return { verified: false };
  }

  async generateUsernamelessAuthenticationOptions(
    requestOrigin?: string,
  ): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const rpId = requestOrigin ? this.extractRpId(requestOrigin) : this.rpID;

    const opts: GenerateAuthenticationOptionsOpts = {
      rpID: rpId,
      allowCredentials: [],
      userVerification: 'required',
    };

    const options = await generateAuthenticationOptions(opts);
    await this.storageService.saveChallenge('usernameless', options.challenge);

    this.logger.debug('Usernameless authentication options generated');

    return options;
  }

  async verifyUsernamelessAuthentication(
    response: AuthenticationResponseJSON,
    requestOrigin?: string,
  ): Promise<{ verified: boolean; user?: User }> {
    const origin = requestOrigin || this.expectedOrigin;
    const rpId = this.extractRpId(origin);

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
        expectedOrigin: origin,
        expectedRPID: rpId,
        credential: {
          id: matchingAuthenticator.credentialID,
          publicKey: matchingAuthenticator.credentialPublicKey,
          counter: matchingAuthenticator.counter,
          transports: matchingAuthenticator.transports,
        },
        requireUserVerification: true,
      };

      this.logger.debug('Verifying usernameless authentication with:', {
        expectedOrigin: origin,
        expectedRPID: rpId,
      });

      const verification = await verifyAuthenticationResponse(opts);

      if (verification.verified) {
        matchingAuthenticator.counter =
          verification.authenticationInfo.newCounter;
        await this.storageService.saveUser(matchingUser);
        await this.storageService.deleteChallenge('usernameless');
        this.logger.log(
          `Usernameless authentication successful for: ${matchingUser.id}`,
        );
        return { verified: true, user: matchingUser };
      }

      return { verified: false };
    } catch (error) {
      this.logger.error('Usernameless authentication error:', error);
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
    this.logger.log('All user data and challenges cleared');
  }
}
