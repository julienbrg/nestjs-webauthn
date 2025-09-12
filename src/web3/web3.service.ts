/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access */
import { Injectable } from '@nestjs/common';
import { Wallet, verifyMessage } from 'ethers';
import { JsonStorageService } from '../webauthn/services/json-storage.service';

export interface SignatureResponse {
  message: string;
  ethereumAddress: string;
  signature: string;
  recoveredAddress: string;
}

@Injectable()
export class Web3Service {
  constructor(private storageService: JsonStorageService) {}

  /**
   * Sign a message with the user's private key
   */
  async signMessage(
    ethereumAddress: string,
    message: string,
  ): Promise<SignatureResponse> {
    try {
      // Get user from storage
      const user = await this.storageService.getUserById(ethereumAddress);
      if (!user) {
        throw new Error('User not found');
      }

      // Create wallet instance from stored private key
      const wallet = new Wallet(user.privateKey);

      // Verify the wallet address matches (security check)
      if (wallet.address.toLowerCase() !== ethereumAddress.toLowerCase()) {
        throw new Error('Address mismatch - security error');
      }

      // Sign the message
      const signature = await wallet.signMessage(message);

      // Verify signature by recovering the address
      const recoveredAddress = verifyMessage(message, signature);

      console.log('Message signed successfully:', {
        message,
        ethereumAddress,
        signature,
        recoveredAddress,
        matches:
          recoveredAddress.toLowerCase() === ethereumAddress.toLowerCase(),
      });

      return {
        message,
        ethereumAddress,
        signature,
        recoveredAddress,
      };
    } catch (error) {
      console.error('Failed to sign message:', error);
      throw new Error(
        error instanceof Error ? error.message : 'Failed to sign message',
      );
    }
  }

  /**
   * Verify a message signature
   */
  verifySignature(
    message: string,
    signature: string,
    expectedAddress: string,
  ): { valid: boolean; recoveredAddress: string } {
    try {
      const recoveredAddress = verifyMessage(message, signature);
      const valid =
        recoveredAddress.toLowerCase() === expectedAddress.toLowerCase();

      return {
        valid,
        recoveredAddress,
      };
    } catch (error) {
      console.error('Failed to verify signature:', error);
      return {
        valid: false,
        recoveredAddress: '',
      };
    }
  }
}
