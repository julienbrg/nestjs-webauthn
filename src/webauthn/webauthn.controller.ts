import {
  Controller,
  Post,
  Body,
  HttpException,
  HttpStatus,
  Get,
  Query,
  Headers,
} from '@nestjs/common';
import { WebAuthnService } from './webauthn.service';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/server';
import { ConfigService } from '@nestjs/config';
import { OriginStorageData } from './interfaces/origin.interface';

export class RegisterBeginDto {
  username: string;
  ethereumAddress: string;
}

export class RegisterCompleteDto {
  ethereumAddress: string;
  response: RegistrationResponseJSON;
}

export class AuthenticateBeginDto {
  ethereumAddress: string;
}

export class AuthenticateCompleteDto {
  ethereumAddress: string;
  response: AuthenticationResponseJSON;
}

export class AuthenticateUsernamelessCompleteDto {
  response: AuthenticationResponseJSON;
}

export class AddOriginDto {
  origin: string;
  masterKey: string;
}

export class RemoveOriginDto {
  origin: string;
  masterKey: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
}

export interface UserResponse {
  id: string;
  username: string;
  email: string;
  hasAuthenticators: boolean;
  authenticatorCount: number;
  ethereumAddress: string;
}

@Controller('webauthn')
export class WebAuthnController {
  constructor(
    private readonly webAuthnService: WebAuthnService,
    private readonly configService: ConfigService,
  ) {}

  @Post('register/begin')
  async beginRegistration(
    @Body() body: RegisterBeginDto,
    @Headers('origin') requestOrigin?: string,
  ): Promise<ApiResponse<{ options: any }>> {
    try {
      const { username, ethereumAddress } = body;

      if (!username) {
        throw new HttpException('username is required', HttpStatus.BAD_REQUEST);
      }

      if (!ethereumAddress) {
        throw new HttpException(
          'ethereumAddress is required',
          HttpStatus.BAD_REQUEST,
        );
      }

      // Validate Ethereum address format (basic check)
      if (!/^0x[a-fA-F0-9]{40}$/.test(ethereumAddress)) {
        throw new HttpException(
          'Invalid Ethereum address format',
          HttpStatus.BAD_REQUEST,
        );
      }

      console.log('Registration begin request from origin:', requestOrigin);
      console.log('Username:', username, 'Ethereum Address:', ethereumAddress);

      const result = await this.webAuthnService.generateRegistrationOptions(
        username,
        ethereumAddress,
        requestOrigin,
      );

      return {
        success: true,
        data: {
          options: result.options,
        },
      };
    } catch (error) {
      console.error('Begin registration error:', error);
      throw new HttpException(
        error instanceof Error
          ? error.message
          : 'Failed to generate registration options',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('register/complete')
  async completeRegistration(
    @Body() body: RegisterCompleteDto,
    @Headers('origin') requestOrigin?: string,
  ): Promise<ApiResponse<{ user: UserResponse }>> {
    try {
      const { ethereumAddress, response } = body;

      if (!ethereumAddress || !response) {
        throw new HttpException(
          'ethereumAddress and response are required',
          HttpStatus.BAD_REQUEST,
        );
      }

      console.log('Registration complete request from origin:', requestOrigin);

      const result = await this.webAuthnService.verifyRegistration(
        ethereumAddress,
        response,
        requestOrigin,
      );

      if (result.verified && result.user) {
        const userResponse: UserResponse = {
          id: result.user.id,
          username: result.user.username,
          email: result.user.email,
          hasAuthenticators: (result.user.authenticators?.length || 0) > 0,
          authenticatorCount: result.user.authenticators?.length || 0,
          ethereumAddress: result.user.id,
        };

        return {
          success: true,
          message:
            'Registration successful. User created with client-side encrypted wallet.',
          data: { user: userResponse },
        };
      } else {
        throw new HttpException(
          'Registration verification failed',
          HttpStatus.BAD_REQUEST,
        );
      }
    } catch (error) {
      console.error('Complete registration error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error
          ? error.message
          : 'Registration verification failed',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('authenticate/begin')
  async beginAuthentication(
    @Body() body: AuthenticateBeginDto,
    @Headers('origin') requestOrigin?: string,
  ): Promise<ApiResponse> {
    try {
      const { ethereumAddress } = body;

      if (!ethereumAddress) {
        throw new HttpException(
          'ethereumAddress is required',
          HttpStatus.BAD_REQUEST,
        );
      }

      console.log('Authentication begin request from origin:', requestOrigin);

      // Check if user exists
      if (!(await this.webAuthnService.userExists(ethereumAddress))) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      const options = await this.webAuthnService.generateAuthenticationOptions(
        ethereumAddress,
        requestOrigin,
      );

      return {
        success: true,
        data: { options },
      };
    } catch (error) {
      console.error('Begin authentication error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error
          ? error.message
          : 'Failed to generate authentication options',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('authenticate/complete')
  async completeAuthentication(
    @Body() body: AuthenticateCompleteDto,
    @Headers('origin') requestOrigin?: string,
  ): Promise<ApiResponse<{ user: UserResponse }>> {
    try {
      const { ethereumAddress, response } = body;

      if (!ethereumAddress || !response) {
        throw new HttpException(
          'ethereumAddress and response are required',
          HttpStatus.BAD_REQUEST,
        );
      }

      console.log(
        'Authentication complete request from origin:',
        requestOrigin,
      );

      const result = await this.webAuthnService.verifyAuthentication(
        ethereumAddress,
        response,
        requestOrigin,
      );

      if (result.verified && result.user) {
        const userResponse: UserResponse = {
          id: result.user.id,
          username: result.user.username,
          email: result.user.email,
          hasAuthenticators: (result.user.authenticators?.length || 0) > 0,
          authenticatorCount: result.user.authenticators?.length || 0,
          ethereumAddress: result.user.id,
        };

        return {
          success: true,
          message: 'Authentication successful',
          data: { user: userResponse },
        };
      } else {
        throw new HttpException(
          'Authentication verification failed',
          HttpStatus.UNAUTHORIZED,
        );
      }
    } catch (error) {
      console.error('Complete authentication error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error
          ? error.message
          : 'Authentication verification failed',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('user')
  async getUser(
    @Query('ethereumAddress') ethereumAddress: string,
  ): Promise<ApiResponse<{ user: UserResponse }>> {
    try {
      if (!ethereumAddress) {
        throw new HttpException(
          'ethereumAddress is required',
          HttpStatus.BAD_REQUEST,
        );
      }

      const user = await this.webAuthnService.getUser(ethereumAddress);

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      const userResponse: UserResponse = {
        id: user.id,
        username: user.username,
        email: user.email,
        hasAuthenticators: (user.authenticators?.length || 0) > 0,
        authenticatorCount: user.authenticators?.length || 0,
        ethereumAddress: user.id,
      };

      return {
        success: true,
        data: { user: userResponse },
      };
    } catch (error) {
      console.error('Get user error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error ? error.message : 'Failed to get user',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('health')
  getHealth() {
    const allowedOrigins = this.webAuthnService.getAllowedOrigins();
    return {
      status: 'ok',
      allowedOrigins,
      rpId: process.env.WEBAUTHN_RP_ID,
      primaryOrigin: process.env.WEBAUTHN_ORIGIN,
      ethereumIntegration: true,
      walletGeneration: 'client-side',
    };
  }

  @Get('origins')
  getAllowedOrigins(): ApiResponse<{ origins: string[] }> {
    try {
      const origins = this.webAuthnService.getAllowedOrigins();
      return {
        success: true,
        data: { origins },
      };
    } catch (error) {
      console.error('Get allowed origins error:', error);
      throw new HttpException(
        'Failed to get allowed origins',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // Debug endpoint - remove in production
  @Get('storage/stats')
  async getStorageStats() {
    try {
      const stats = await this.webAuthnService.getStorageStats();
      return {
        success: true,
        data: stats,
      };
    } catch (error) {
      console.error('Get storage stats error:', error);
      throw new HttpException(
        'Failed to get storage stats',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // Debug endpoint - remove in production
  @Post('storage/clear')
  async clearStorage(): Promise<ApiResponse> {
    try {
      await this.webAuthnService.clearAllData();
      return {
        success: true,
        message: 'Storage cleared successfully',
      };
    } catch (error) {
      console.error('Clear storage error:', error);
      throw new HttpException(
        'Failed to clear storage',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('authenticate/usernameless/begin')
  async beginUsernamelessAuthentication(
    @Headers('origin') requestOrigin?: string,
  ): Promise<ApiResponse> {
    try {
      console.log(
        'Usernameless authentication begin request from origin:',
        requestOrigin,
      );

      const options =
        await this.webAuthnService.generateUsernamelessAuthenticationOptions(
          requestOrigin,
        );

      return {
        success: true,
        data: { options },
      };
    } catch (error) {
      console.error('Begin usernameless authentication error:', error);
      throw new HttpException(
        error instanceof Error
          ? error.message
          : 'Failed to generate usernameless authentication options',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('authenticate/usernameless/complete')
  async completeUsernamelessAuthentication(
    @Body() body: AuthenticateUsernamelessCompleteDto,
    @Headers('origin') requestOrigin?: string,
  ): Promise<ApiResponse<{ user: UserResponse }>> {
    try {
      const { response } = body;

      if (!response) {
        throw new HttpException('response is required', HttpStatus.BAD_REQUEST);
      }

      console.log(
        'Usernameless authentication complete request from origin:',
        requestOrigin,
      );

      const result =
        await this.webAuthnService.verifyUsernamelessAuthentication(
          response,
          requestOrigin,
        );

      if (result.verified && result.user) {
        const userResponse: UserResponse = {
          id: result.user.id,
          username: result.user.username,
          email: result.user.email,
          hasAuthenticators: (result.user.authenticators?.length || 0) > 0,
          authenticatorCount: result.user.authenticators?.length || 0,
          ethereumAddress: result.user.id,
        };

        return {
          success: true,
          message: 'Usernameless authentication successful',
          data: { user: userResponse },
        };
      } else {
        throw new HttpException(
          'Usernameless authentication verification failed',
          HttpStatus.UNAUTHORIZED,
        );
      }
    } catch (error) {
      console.error('Complete usernameless authentication error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error
          ? error.message
          : 'Usernameless authentication verification failed',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('admin/origins/add')
  async addOrigin(@Body() body: AddOriginDto): Promise<ApiResponse> {
    try {
      const { origin, masterKey } = body;

      // Validate master key
      const expectedMasterKey = this.configService.get<string>('MASTER_KEY');
      if (!expectedMasterKey) {
        throw new HttpException(
          'Master key not configured',
          HttpStatus.INTERNAL_SERVER_ERROR,
        );
      }

      if (masterKey !== expectedMasterKey) {
        throw new HttpException('Invalid master key', HttpStatus.UNAUTHORIZED);
      }

      if (!origin) {
        throw new HttpException('origin is required', HttpStatus.BAD_REQUEST);
      }

      // Validate origin format
      let hostname: string;
      try {
        const url = new URL(origin);
        hostname = url.hostname;
      } catch {
        throw new HttpException(
          'Invalid origin URL format',
          HttpStatus.BAD_REQUEST,
        );
      }

      await this.webAuthnService.addOrigin(origin);

      return {
        success: true,
        message: `Origin ${origin} added (rpId: ${hostname})`,
      };
    } catch (error) {
      console.error('Add origin error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error ? error.message : 'Failed to add origin',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('admin/origins/remove')
  async removeOrigin(@Body() body: RemoveOriginDto): Promise<ApiResponse> {
    try {
      const { origin, masterKey } = body;

      // Validate master key
      const expectedMasterKey = this.configService.get<string>('MASTER_KEY');
      if (!expectedMasterKey) {
        throw new HttpException(
          'Master key not configured',
          HttpStatus.INTERNAL_SERVER_ERROR,
        );
      }

      if (masterKey !== expectedMasterKey) {
        throw new HttpException('Invalid master key', HttpStatus.UNAUTHORIZED);
      }

      if (!origin) {
        throw new HttpException('origin is required', HttpStatus.BAD_REQUEST);
      }

      const removed = await this.webAuthnService.removeOrigin(origin);

      if (removed) {
        return {
          success: true,
          message: `Origin ${origin} removed successfully`,
        };
      } else {
        throw new HttpException('Origin not found', HttpStatus.NOT_FOUND);
      }
    } catch (error) {
      console.error('Remove origin error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error ? error.message : 'Failed to remove origin',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('admin/origins/list')
  async listOrigins(
    @Query('masterKey') masterKey: string,
  ): Promise<ApiResponse> {
    try {
      // Validate master key
      const expectedMasterKey = this.configService.get<string>('MASTER_KEY');
      if (!expectedMasterKey) {
        throw new HttpException(
          'Master key not configured',
          HttpStatus.INTERNAL_SERVER_ERROR,
        );
      }

      if (masterKey !== expectedMasterKey) {
        throw new HttpException('Invalid master key', HttpStatus.UNAUTHORIZED);
      }

      const origins: OriginStorageData =
        await this.webAuthnService.listOrigins();

      return {
        success: true,
        data: origins,
      };
    } catch (error) {
      console.error('List origins error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error ? error.message : 'Failed to list origins',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
