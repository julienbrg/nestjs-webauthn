import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs/promises';
import * as path from 'path';
import type {
  CredentialDeviceType,
  AuthenticatorTransportFuture,
} from '@simplewebauthn/server';
import { User, Authenticator } from '../interfaces/user.interface';
import {
  IStorageService,
  StorageData,
  SerializableStorageData,
  SerializableUser,
  SerializableAuthenticator,
} from '../interfaces/storage.interface';
import { OriginStorageData } from '../interfaces/origin.interface';

@Injectable()
export class JsonStorageService implements IStorageService {
  private readonly logger = new Logger(JsonStorageService.name);
  private readonly dataFilePath: string;
  private readonly originsFilePath: string;
  private readonly dataDir: string;

  constructor(private configService: ConfigService) {
    this.dataDir = this.configService.get('WEBAUTHN_DATA_DIR') || './data';
    this.dataFilePath = path.join(this.dataDir, 'webauthn.json');
    this.originsFilePath = path.join(this.dataDir, 'origins.json');
    this.initializeStorage();
  }

  private async initializeStorage(): Promise<void> {
    try {
      // Ensure data directory exists
      await fs.mkdir(this.dataDir, { recursive: true });

      // Check if file exists, create empty one if not
      try {
        await fs.access(this.dataFilePath);
      } catch {
        const initialData: StorageData = {
          users: {},
          challenges: {},
        };
        await this.saveData(initialData);
        this.logger.log(`Created initial storage file at ${this.dataFilePath}`);
      }

      // Initialize origins file
      try {
        await fs.access(this.originsFilePath);
      } catch {
        const initialOrigins: OriginStorageData = {
          origins: [],
        };
        await this.saveOrigins(initialOrigins);
        this.logger.log(
          `Created initial origins file at ${this.originsFilePath}`,
        );
      }

      this.logger.log(`Storage initialized at ${this.dataFilePath}`);
    } catch (error) {
      this.logger.error('Failed to initialize storage:', error);
      throw error;
    }
  }

  private convertToSerializable(data: StorageData): SerializableStorageData {
    const serializable: SerializableStorageData = {
      users: {},
      challenges: { ...data.challenges },
    };

    // Convert users with proper typing (no privateKey field)
    for (const [userId, user] of Object.entries(data.users)) {
      const serializableUser: SerializableUser = {
        id: user.id, // Ethereum address
        username: user.username,
        email: user.email,
        authenticators: user.authenticators.map((auth) => {
          const serializableAuth: SerializableAuthenticator = {
            credentialID: auth.credentialID,
            credentialPublicKey: Array.from(auth.credentialPublicKey),
            counter: auth.counter,
            credentialDeviceType: auth.credentialDeviceType,
            credentialBackedUp: auth.credentialBackedUp,
            transports: auth.transports,
          };
          return serializableAuth;
        }),
      };
      serializable.users[userId] = serializableUser;
    }

    return serializable;
  }

  private convertFromSerializable(
    serializable: SerializableStorageData,
  ): StorageData {
    const data: StorageData = {
      users: {},
      challenges: { ...serializable.challenges },
    };

    // Convert users back with proper typing (no privateKey field)
    for (const [userId, serializableUser] of Object.entries(
      serializable.users,
    )) {
      const authenticators: Authenticator[] =
        serializableUser.authenticators.map((serializableAuth) => {
          const authenticator: Authenticator = {
            credentialID: serializableAuth.credentialID,
            credentialPublicKey: new Uint8Array(
              serializableAuth.credentialPublicKey,
            ),
            counter: serializableAuth.counter,
            credentialDeviceType:
              serializableAuth.credentialDeviceType as CredentialDeviceType,
            credentialBackedUp: serializableAuth.credentialBackedUp,
          };

          // Only add transports if it exists
          if (serializableAuth.transports) {
            authenticator.transports =
              serializableAuth.transports as AuthenticatorTransportFuture[];
          }

          return authenticator;
        });

      const user: User = {
        id: serializableUser.id, // Ethereum address
        username: serializableUser.username,
        email: serializableUser.email,
        authenticators: authenticators,
      };

      data.users[userId] = user;
    }

    return data;
  }

  private isValidSerializableStorageData(
    obj: unknown,
  ): obj is SerializableStorageData {
    if (!obj || typeof obj !== 'object') return false;

    const data = obj as Record<string, unknown>;

    // Check if it has the required structure
    if (!data.users || typeof data.users !== 'object') return false;
    if (!data.challenges || typeof data.challenges !== 'object') return false;

    return true;
  }

  async loadData(): Promise<StorageData> {
    try {
      const fileContent = await fs.readFile(this.dataFilePath, 'utf8');

      // Parse with unknown type first
      const parsed: unknown = JSON.parse(fileContent);

      // Type guard to ensure it's valid
      if (!this.isValidSerializableStorageData(parsed)) {
        this.logger.warn(
          'Invalid data structure in storage file, returning empty data',
        );
        return { users: {}, challenges: {} };
      }

      return this.convertFromSerializable(parsed);
    } catch (error) {
      this.logger.error('Failed to load data:', error);
      // Return empty data structure if file is corrupted
      return { users: {}, challenges: {} };
    }
  }

  async saveData(data: StorageData): Promise<void> {
    try {
      const serializableData = this.convertToSerializable(data);
      const jsonString = JSON.stringify(serializableData, null, 2);
      await fs.writeFile(this.dataFilePath, jsonString, 'utf8');
      this.logger.debug('Data saved successfully');
    } catch (error) {
      this.logger.error('Failed to save data:', error);
      throw error;
    }
  }

  async getUserById(userId: string): Promise<User | undefined> {
    const data = await this.loadData();
    return data.users[userId];
  }

  async saveUser(user: User): Promise<void> {
    const data = await this.loadData();
    data.users[user.id] = user;
    await this.saveData(data);
    this.logger.debug(`User ${user.id} saved`);
  }

  async deleteUser(userId: string): Promise<boolean> {
    const data = await this.loadData();
    if (data.users[userId]) {
      delete data.users[userId];
      // Also clean up any challenges for this user
      delete data.challenges[userId];
      await this.saveData(data);
      this.logger.debug(`User ${userId} deleted`);
      return true;
    }
    return false;
  }

  async getChallenge(userId: string): Promise<string | undefined> {
    const data = await this.loadData();
    return data.challenges[userId];
  }

  async saveChallenge(userId: string, challenge: string): Promise<void> {
    const data = await this.loadData();
    data.challenges[userId] = challenge;
    await this.saveData(data);
    this.logger.debug(`Challenge saved for user ${userId}`);
  }

  async deleteChallenge(userId: string): Promise<boolean> {
    const data = await this.loadData();
    if (data.challenges[userId]) {
      delete data.challenges[userId];
      await this.saveData(data);
      this.logger.debug(`Challenge deleted for user ${userId}`);
      return true;
    }
    return false;
  }

  async clearAll(): Promise<void> {
    const emptyData: StorageData = {
      users: {},
      challenges: {},
    };
    await this.saveData(emptyData);
    this.logger.log('All data cleared');
  }

  // Origin management methods
  async loadOrigins(): Promise<OriginStorageData> {
    try {
      const fileContent = await fs.readFile(this.originsFilePath, 'utf8');
      const parsed: unknown = JSON.parse(fileContent);

      // Type guard to validate structure
      if (
        parsed &&
        typeof parsed === 'object' &&
        'origins' in parsed &&
        Array.isArray(parsed.origins)
      ) {
        const validatedData = parsed as {
          origins: Array<{ origin: string; addedAt: string }>;
        };

        return {
          origins: validatedData.origins.map((o) => ({
            origin: o.origin,
            addedAt: new Date(o.addedAt),
          })),
        };
      }

      this.logger.warn('Invalid origins data structure, returning empty');
      return { origins: [] };
    } catch (error) {
      this.logger.error('Failed to load origins:', error);
      return { origins: [] };
    }
  }

  async saveOrigins(data: OriginStorageData): Promise<void> {
    try {
      const jsonString = JSON.stringify(data, null, 2);
      await fs.writeFile(this.originsFilePath, jsonString, 'utf8');
      this.logger.debug('Origins saved successfully');
    } catch (error) {
      this.logger.error('Failed to save origins:', error);
      throw error;
    }
  }

  async addOrigin(origin: string): Promise<void> {
    const data = await this.loadOrigins();

    // Check if origin already exists
    const exists = data.origins.some((o) => o.origin === origin);
    if (exists) {
      throw new Error('Origin already exists');
    }

    data.origins.push({
      origin,
      addedAt: new Date(),
    });

    await this.saveOrigins(data);
    this.logger.log(`Origin added: ${origin}`);
  }

  async removeOrigin(origin: string): Promise<boolean> {
    const data = await this.loadOrigins();
    const initialLength = data.origins.length;

    data.origins = data.origins.filter((o) => o.origin !== origin);

    if (data.origins.length < initialLength) {
      await this.saveOrigins(data);
      this.logger.log(`Origin removed: ${origin}`);
      return true;
    }

    return false;
  }

  async getAllOrigins(): Promise<OriginStorageData> {
    return this.loadOrigins();
  }

  // Utility method for debugging
  async getStorageStats(): Promise<{
    userCount: number;
    challengeCount: number;
    filePath: string;
    ethereumAddresses: string[];
  }> {
    const data = await this.loadData();
    return {
      userCount: Object.keys(data.users).length,
      challengeCount: Object.keys(data.challenges).length,
      filePath: this.dataFilePath,
      ethereumAddresses: Object.keys(data.users), // Ethereum addresses
    };
  }
}
