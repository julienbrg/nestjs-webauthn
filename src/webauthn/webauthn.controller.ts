import {
  Controller,
  Post,
  Body,
  HttpException,
  HttpStatus,
  Get,
  Query,
} from '@nestjs/common';
import { WebAuthnService } from './webauthn.service';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/server';

export class RegisterBeginDto {
  userId: string;
  username: string;
}

export class RegisterCompleteDto {
  userId: string;
  response: RegistrationResponseJSON;
}

export class AuthenticateBeginDto {
  userId: string;
}

export class AuthenticateCompleteDto {
  userId: string;
  response: AuthenticationResponseJSON;
}

export class AuthenticateUsernamelessCompleteDto {
  response: AuthenticationResponseJSON;
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
}

@Controller('webauthn')
export class WebAuthnController {
  constructor(private readonly webAuthnService: WebAuthnService) {}

  @Post('register/begin')
  async beginRegistration(
    @Body() body: RegisterBeginDto,
  ): Promise<ApiResponse> {
    try {
      const { userId, username } = body;

      if (!userId || !username) {
        throw new HttpException(
          'userId and username are required',
          HttpStatus.BAD_REQUEST,
        );
      }

      const options = await this.webAuthnService.generateRegistrationOptions(
        userId,
        username,
      );

      return {
        success: true,
        data: { options },
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
  ): Promise<ApiResponse<{ user: UserResponse }>> {
    try {
      const { userId, response } = body;

      if (!userId || !response) {
        throw new HttpException(
          'userId and response are required',
          HttpStatus.BAD_REQUEST,
        );
      }

      const result = await this.webAuthnService.verifyRegistration(
        userId,
        response,
      );

      if (result.verified && result.user) {
        const userResponse: UserResponse = {
          id: result.user.id,
          username: result.user.username,
          email: result.user.email,
          hasAuthenticators: (result.user.authenticators?.length || 0) > 0,
          authenticatorCount: result.user.authenticators?.length || 0,
        };

        return {
          success: true,
          message: 'Registration successful',
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
  ): Promise<ApiResponse> {
    try {
      const { userId } = body;

      if (!userId) {
        throw new HttpException('userId is required', HttpStatus.BAD_REQUEST);
      }

      // Check if user exists
      if (!(await this.webAuthnService.userExists(userId))) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      const options =
        await this.webAuthnService.generateAuthenticationOptions(userId);

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
  ): Promise<ApiResponse<{ user: UserResponse }>> {
    try {
      const { userId, response } = body;

      if (!userId || !response) {
        throw new HttpException(
          'userId and response are required',
          HttpStatus.BAD_REQUEST,
        );
      }

      const result = await this.webAuthnService.verifyAuthentication(
        userId,
        response,
      );

      if (result.verified && result.user) {
        const userResponse: UserResponse = {
          id: result.user.id,
          username: result.user.username,
          email: result.user.email,
          hasAuthenticators: (result.user.authenticators?.length || 0) > 0,
          authenticatorCount: result.user.authenticators?.length || 0,
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
    @Query('userId') userId: string,
  ): Promise<ApiResponse<{ user: UserResponse }>> {
    try {
      if (!userId) {
        throw new HttpException('userId is required', HttpStatus.BAD_REQUEST);
      }

      const user = await this.webAuthnService.getUser(userId);

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      const userResponse: UserResponse = {
        id: user.id,
        username: user.username,
        email: user.email,
        hasAuthenticators: (user.authenticators?.length || 0) > 0,
        authenticatorCount: user.authenticators?.length || 0,
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
    return {
      status: 'ok',
      origin: process.env.WEBAUTHN_ORIGIN,
      rpId: process.env.WEBAUTHN_RP_ID,
    };
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
  async beginUsernamelessAuthentication(): Promise<ApiResponse> {
    try {
      const options =
        await this.webAuthnService.generateUsernamelessAuthenticationOptions();

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
  ): Promise<ApiResponse<{ user: UserResponse }>> {
    try {
      const { response } = body;

      if (!response) {
        throw new HttpException('response is required', HttpStatus.BAD_REQUEST);
      }

      const result =
        await this.webAuthnService.verifyUsernamelessAuthentication(response);

      if (result.verified && result.user) {
        const userResponse: UserResponse = {
          id: result.user.id,
          username: result.user.username,
          email: result.user.email,
          hasAuthenticators: (result.user.authenticators?.length || 0) > 0,
          authenticatorCount: result.user.authenticators?.length || 0,
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
}
