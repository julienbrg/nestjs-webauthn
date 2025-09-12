import {
  Controller,
  Post,
  Body,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Web3Service, SignatureResponse } from './web3.service';

export class SignMessageDto {
  ethereumAddress: string;
  message: string;
}

export class VerifySignatureDto {
  message: string;
  signature: string;
  expectedAddress: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
}

@Controller('web3')
export class Web3Controller {
  constructor(private readonly web3Service: Web3Service) {}

  @Post('sign-message')
  async signMessage(
    @Body() body: SignMessageDto,
  ): Promise<ApiResponse<SignatureResponse>> {
    try {
      const { ethereumAddress, message } = body;

      if (!ethereumAddress || !message) {
        throw new HttpException(
          'ethereumAddress and message are required',
          HttpStatus.BAD_REQUEST,
        );
      }

      const result = await this.web3Service.signMessage(
        ethereumAddress,
        message,
      );

      return {
        success: true,
        message: 'Message signed successfully',
        data: result,
      };
    } catch (error) {
      console.error('Sign message error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error ? error.message : 'Failed to sign message',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('verify-signature')
  verifySignature(
    @Body() body: VerifySignatureDto,
  ): ApiResponse<{ valid: boolean; recoveredAddress: string }> {
    try {
      const { message, signature, expectedAddress } = body;

      if (!message || !signature || !expectedAddress) {
        throw new HttpException(
          'message, signature, and expectedAddress are required',
          HttpStatus.BAD_REQUEST,
        );
      }

      const result = this.web3Service.verifySignature(
        message,
        signature,
        expectedAddress,
      );

      return {
        success: true,
        message: result.valid ? 'Signature is valid' : 'Signature is invalid',
        data: result,
      };
    } catch (error) {
      console.error('Verify signature error:', error);
      throw new HttpException(
        error instanceof Error ? error.message : 'Failed to verify signature',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
