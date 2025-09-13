import {
  Controller,
  Post,
  Get,
  Delete,
  Param,
  Body,
  UploadedFile,
  UseInterceptors,
  HttpException,
  HttpStatus,
  Res,
  StreamableFile,
  Header,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { Response } from 'express';
import { StoreService, FileInfo, UserStorageStats } from './store.service';

export interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
}

export class UploadFileDto {
  ethereumAddress: string;
  description?: string;
}

@Controller('store')
export class StoreController {
  constructor(private readonly storeService: StoreService) {}

  /**
   * Upload a file to user's directory
   */
  @Post('upload')
  @UseInterceptors(FileInterceptor('file'))
  async uploadFile(
    @UploadedFile() file: Express.Multer.File,
    @Body() body: UploadFileDto,
  ): Promise<ApiResponse<FileInfo>> {
    try {
      if (!file) {
        throw new HttpException('No file provided', HttpStatus.BAD_REQUEST);
      }

      if (!body.ethereumAddress) {
        throw new HttpException(
          'Ethereum address is required',
          HttpStatus.BAD_REQUEST,
        );
      }

      // Validate Ethereum address format (basic check)
      if (!/^0x[a-fA-F0-9]{40}$/.test(body.ethereumAddress)) {
        throw new HttpException(
          'Invalid Ethereum address format',
          HttpStatus.BAD_REQUEST,
        );
      }

      const fileInfo = await this.storeService.addFile(
        body.ethereumAddress,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        file.buffer,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        file.originalname,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        file.mimetype,
      );

      return {
        success: true,
        message: 'File uploaded successfully',
        data: fileInfo,
      };
    } catch (error) {
      console.error('Upload file error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error ? error.message : 'Failed to upload file',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Download a single file
   */
  @Get('download/:ethereumAddress/:filename')
  async downloadFile(
    @Param('ethereumAddress') ethereumAddress: string,
    @Param('filename') filename: string,
    @Res({ passthrough: true }) res: Response,
  ): Promise<StreamableFile> {
    try {
      if (!/^0x[a-fA-F0-9]{40}$/.test(ethereumAddress)) {
        throw new HttpException(
          'Invalid Ethereum address format',
          HttpStatus.BAD_REQUEST,
        );
      }

      const { buffer, fileInfo } = await this.storeService.downloadFile(
        ethereumAddress,
        filename,
      );

      // Set response headers
      res.set({
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${fileInfo.originalName}"`,
        'Content-Length': buffer.length.toString(),
      });

      return new StreamableFile(buffer);
    } catch (error) {
      console.error('Download file error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error ? error.message : 'Failed to download file',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Get user's storage statistics and file list
   */
  @Get('stats/:ethereumAddress')
  async getUserStats(
    @Param('ethereumAddress') ethereumAddress: string,
  ): Promise<ApiResponse<UserStorageStats>> {
    try {
      if (!/^0x[a-fA-F0-9]{40}$/.test(ethereumAddress)) {
        throw new HttpException(
          'Invalid Ethereum address format',
          HttpStatus.BAD_REQUEST,
        );
      }

      const stats =
        await this.storeService.getUserStorageStats(ethereumAddress);

      return {
        success: true,
        data: stats,
      };
    } catch (error) {
      console.error('Get user stats error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error
          ? error.message
          : 'Failed to get user statistics',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Download all files as a ZIP archive (streaming)
   */
  @Get('download-all/:ethereumAddress')
  @Header('Content-Type', 'application/zip')
  async downloadAllFiles(
    @Param('ethereumAddress') ethereumAddress: string,
    @Res({ passthrough: true }) res: Response,
  ): Promise<StreamableFile> {
    try {
      if (!/^0x[a-fA-F0-9]{40}$/.test(ethereumAddress)) {
        throw new HttpException(
          'Invalid Ethereum address format',
          HttpStatus.BAD_REQUEST,
        );
      }

      const { files } =
        await this.storeService.downloadAllFiles(ethereumAddress);

      if (files.length === 0) {
        throw new HttpException(
          'No files found for user',
          HttpStatus.NOT_FOUND,
        );
      }

      // For simplicity, we'll create a simple ZIP-like response
      // In production, you might want to use a proper ZIP library like 'archiver'
      const zipBuffer = this.createSimpleZipBuffer(files);

      res.set({
        'Content-Disposition': `attachment; filename="${ethereumAddress}_files.zip"`,
        'Content-Length': zipBuffer.length.toString(),
      });

      return new StreamableFile(zipBuffer);
    } catch (error) {
      console.error('Download all files error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error ? error.message : 'Failed to download all files',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Get file list without downloading
   */
  @Get('files/:ethereumAddress')
  async getFileList(
    @Param('ethereumAddress') ethereumAddress: string,
  ): Promise<
    ApiResponse<{ files: FileInfo[]; totalSize: number; fileCount: number }>
  > {
    try {
      if (!/^0x[a-fA-F0-9]{40}$/.test(ethereumAddress)) {
        throw new HttpException(
          'Invalid Ethereum address format',
          HttpStatus.BAD_REQUEST,
        );
      }

      const stats =
        await this.storeService.getUserStorageStats(ethereumAddress);

      return {
        success: true,
        data: {
          files: stats.files,
          totalSize: stats.totalSize,
          fileCount: stats.fileCount,
        },
      };
    } catch (error) {
      console.error('Get file list error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error ? error.message : 'Failed to get file list',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Delete a specific file
   */
  @Delete('file/:ethereumAddress/:filename')
  async deleteFile(
    @Param('ethereumAddress') ethereumAddress: string,
    @Param('filename') filename: string,
  ): Promise<ApiResponse> {
    try {
      if (!/^0x[a-fA-F0-9]{40}$/.test(ethereumAddress)) {
        throw new HttpException(
          'Invalid Ethereum address format',
          HttpStatus.BAD_REQUEST,
        );
      }

      await this.storeService.deleteFile(ethereumAddress, filename);

      return {
        success: true,
        message: 'File deleted successfully',
      };
    } catch (error) {
      console.error('Delete file error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error ? error.message : 'Failed to delete file',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Initialize user storage (called during registration)
   */
  @Post('init/:ethereumAddress')
  async initUserStorage(
    @Param('ethereumAddress') ethereumAddress: string,
  ): Promise<ApiResponse> {
    try {
      if (!/^0x[a-fA-F0-9]{40}$/.test(ethereumAddress)) {
        throw new HttpException(
          'Invalid Ethereum address format',
          HttpStatus.BAD_REQUEST,
        );
      }

      await this.storeService.createUserDirectory(ethereumAddress);

      return {
        success: true,
        message: 'User storage initialized successfully',
      };
    } catch (error) {
      console.error('Init user storage error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error
          ? error.message
          : 'Failed to initialize user storage',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Get file info without downloading
   */
  @Get('info/:ethereumAddress/:filename')
  async getFileInfo(
    @Param('ethereumAddress') ethereumAddress: string,
    @Param('filename') filename: string,
  ): Promise<ApiResponse<FileInfo>> {
    try {
      if (!/^0x[a-fA-F0-9]{40}$/.test(ethereumAddress)) {
        throw new HttpException(
          'Invalid Ethereum address format',
          HttpStatus.BAD_REQUEST,
        );
      }

      const { fileInfo } = await this.storeService.downloadFile(
        ethereumAddress,
        filename,
      );

      return {
        success: true,
        data: fileInfo,
      };
    } catch (error) {
      console.error('Get file info error:', error);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error instanceof Error ? error.message : 'Failed to get file info',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Private helper to create a simple bundle buffer
   * In production, use a proper ZIP library like 'archiver'
   */
  private createSimpleZipBuffer(
    files: Array<{ filename: string; buffer: Buffer; fileInfo: FileInfo }>,
  ): Buffer {
    // This is a simplified implementation
    // For production, use a proper ZIP library
    const chunks: Buffer[] = [];

    // Add a simple text manifest
    const manifest = files
      .map(
        (f) =>
          `${f.fileInfo.originalName} (${f.filename}) - ${f.fileInfo.size} bytes - ${f.fileInfo.uploadDate.toISOString()}`,
      )
      .join('\n');

    chunks.push(Buffer.from(`--- FILE MANIFEST ---\n${manifest}\n\n`));

    // Add file separator and content for each file
    for (const file of files) {
      const separator = Buffer.from(
        `\n--- FILE: ${file.fileInfo.originalName} ---\n`,
      );
      chunks.push(separator);
      chunks.push(file.buffer);
      chunks.push(Buffer.from('\n'));
    }

    return Buffer.concat(chunks);
  }
}
