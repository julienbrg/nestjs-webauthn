import { User } from './user.interface';

export interface StorageData {
  users: Record<string, User>;
  challenges: Record<string, string>;
}

// Serializable versions for JSON storage (Uint8Array -> number[])
export interface SerializableAuthenticator {
  credentialID: string; // Base64URLString is just string anyway
  credentialPublicKey: number[]; // Array instead of Uint8Array
  counter: number;
  credentialDeviceType: string; // Serialized as string
  credentialBackedUp: boolean;
  transports?: string[]; // Serialized as string array
}

export interface SerializableUser {
  id: string; // Ethereum address
  privateKey: string; // Private key
  username: string;
  email: string;
  authenticators: SerializableAuthenticator[];
}

export interface SerializableStorageData {
  users: Record<string, SerializableUser>;
  challenges: Record<string, string>;
}

export interface IStorageService {
  loadData(): Promise<StorageData>;
  saveData(data: StorageData): Promise<void>;
  getUserById(userId: string): Promise<User | undefined>;
  saveUser(user: User): Promise<void>;
  deleteUser(userId: string): Promise<boolean>;
  getChallenge(userId: string): Promise<string | undefined>;
  saveChallenge(userId: string, challenge: string): Promise<void>;
  deleteChallenge(userId: string): Promise<boolean>;
  clearAll(): Promise<void>;
}
