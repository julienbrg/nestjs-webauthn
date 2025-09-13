import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';

export interface FileInfo {
  filename: string;
  originalName: string;
  size: number;
  uploadDate: Date;
  contentType?: string;
}

export interface UserStorageStats {
  ethereumAddress: string;
  fileCount: number;
  totalSize: number;
  files: FileInfo[];
}

@Injectable()
export class StoreService {
  private readonly logger = new Logger(StoreService.name);
  private readonly dataDir: string;
  private readonly maxFileSize: number = 10 * 1024 * 1024; // 10MB default
  private readonly allowedExtensions: string[] = [
    '.txt',
    '.json',
    '.csv',
    '.pdf',
    '.doc',
    '.docx',
    '.jpg',
    '.jpeg',
    '.png',
    '.gif',
    '.mp3',
    '.mp4',
  ];

  constructor(private configService: ConfigService) {
    this.dataDir = this.configService.get('WEBAUTHN_DATA_DIR') || './data';
    this.logger.log(
      `Store service initialized with data directory: ${this.dataDir}`,
    );
  }

  /**
   * Create user directory during registration
   */
  async createUserDirectory(ethereumAddress: string): Promise<void> {
    try {
      const userDir = this.getUserDirectory(ethereumAddress);
      await fs.mkdir(userDir, { recursive: true });

      // Create a metadata file for the user
      const metadata = {
        ethereumAddress,
        createdAt: new Date().toISOString(),
        fileCount: 0,
        totalSize: 0,
      };

      await fs.writeFile(
        path.join(userDir, '.metadata.json'),
        JSON.stringify(metadata, null, 2),
      );

      this.logger.log(`Created directory for user: ${ethereumAddress}`);
    } catch (error) {
      this.logger.error(
        `Failed to create user directory for ${ethereumAddress}:`,
        error,
      );
      throw new HttpException(
        'Failed to create user storage directory',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Add a file to user's directory
   */
  async addFile(
    ethereumAddress: string,
    fileBuffer: Buffer,
    originalName: string,
    contentType?: string,
  ): Promise<FileInfo> {
    try {
      // Validate file size
      if (fileBuffer.length > this.maxFileSize) {
        throw new HttpException(
          `File size exceeds maximum allowed size of ${this.maxFileSize / (1024 * 1024)}MB`,
          HttpStatus.BAD_REQUEST,
        );
      }

      // Validate file extension
      const extension = path.extname(originalName).toLowerCase();
      if (!this.allowedExtensions.includes(extension)) {
        throw new HttpException(
          `File type not allowed. Allowed types: ${this.allowedExtensions.join(', ')}`,
          HttpStatus.BAD_REQUEST,
        );
      }

      const userDir = this.getUserDirectory(ethereumAddress);

      // Ensure user directory exists
      await this.ensureUserDirectory(ethereumAddress);

      // Generate unique filename to prevent conflicts
      const timestamp = Date.now();
      const randomSuffix = crypto.randomBytes(4).toString('hex');
      const safeOriginalName = originalName.replace(/[^a-zA-Z0-9.-]/g, '_');
      const filename = `${timestamp}_${randomSuffix}_${safeOriginalName}`;

      const filePath = path.join(userDir, filename);

      // Write file
      await fs.writeFile(filePath, fileBuffer);

      // Create file info
      const fileInfo: FileInfo = {
        filename,
        originalName,
        size: fileBuffer.length,
        uploadDate: new Date(),
        contentType,
      };

      // Update user metadata
      await this.updateUserMetadata(ethereumAddress);

      this.logger.log(
        `File added for user ${ethereumAddress}: ${originalName} -> ${filename}`,
      );
      return fileInfo;
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      this.logger.error(
        `Failed to add file for user ${ethereumAddress}:`,
        error,
      );
      throw new HttpException(
        'Failed to store file',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Download a single file from user's directory
   */
  async downloadFile(
    ethereumAddress: string,
    filename: string,
  ): Promise<{ buffer: Buffer; fileInfo: FileInfo }> {
    try {
      const userDir = this.getUserDirectory(ethereumAddress);
      const filePath = path.join(userDir, filename);

      // Security check: ensure file is within user directory
      const resolvedPath = path.resolve(filePath);
      const resolvedUserDir = path.resolve(userDir);
      if (!resolvedPath.startsWith(resolvedUserDir)) {
        throw new HttpException(
          'Access denied: Invalid file path',
          HttpStatus.FORBIDDEN,
        );
      }

      // Check if file exists
      try {
        await fs.access(filePath);
      } catch {
        throw new HttpException('File not found', HttpStatus.NOT_FOUND);
      }

      // Get file stats
      const stats = await fs.stat(filePath);

      // Read file
      const buffer = await fs.readFile(filePath);

      // Extract original name from filename (remove timestamp and hash prefix)
      const originalName = filename.replace(/^\d+_[a-f0-9]{8}_/, '');

      const fileInfo: FileInfo = {
        filename,
        originalName,
        size: stats.size,
        uploadDate: stats.mtime,
      };

      this.logger.log(
        `File downloaded by user ${ethereumAddress}: ${filename}`,
      );
      return { buffer, fileInfo };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      this.logger.error(
        `Failed to download file for user ${ethereumAddress}:`,
        error,
      );
      throw new HttpException(
        'Failed to retrieve file',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Download all files from user's directory as individual files info
   */
  async downloadAllFiles(ethereumAddress: string): Promise<{
    files: Array<{ filename: string; buffer: Buffer; fileInfo: FileInfo }>;
    stats: UserStorageStats;
  }> {
    try {
      const userDir = this.getUserDirectory(ethereumAddress);

      // Check if user directory exists
      try {
        await fs.access(userDir);
      } catch {
        throw new HttpException(
          'User directory not found',
          HttpStatus.NOT_FOUND,
        );
      }

      // Read directory contents
      const entries = await fs.readdir(userDir, { withFileTypes: true });
      const fileEntries = entries.filter(
        (entry) => entry.isFile() && !entry.name.startsWith('.'),
      );

      const files: Array<{
        filename: string;
        buffer: Buffer;
        fileInfo: FileInfo;
      }> = [];
      let totalSize = 0;

      // Process each file
      for (const entry of fileEntries) {
        try {
          const filePath = path.join(userDir, entry.name);
          const buffer = await fs.readFile(filePath);
          const stats = await fs.stat(filePath);

          const originalName = entry.name.replace(/^\d+_[a-f0-9]{8}_/, '');

          const fileInfo: FileInfo = {
            filename: entry.name,
            originalName,
            size: stats.size,
            uploadDate: stats.mtime,
          };

          files.push({
            filename: entry.name,
            buffer,
            fileInfo,
          });

          totalSize += stats.size;
        } catch (fileError) {
          this.logger.warn(
            `Failed to read file ${entry.name} for user ${ethereumAddress}:`,
            fileError,
          );
          // Continue with other files
        }
      }

      const userStats: UserStorageStats = {
        ethereumAddress,
        fileCount: files.length,
        totalSize,
        files: files.map((f) => f.fileInfo),
      };

      this.logger.log(
        `Downloaded ${files.length} files for user ${ethereumAddress}`,
      );
      return { files, stats: userStats };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      this.logger.error(
        `Failed to download all files for user ${ethereumAddress}:`,
        error,
      );
      throw new HttpException(
        'Failed to retrieve user files',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Get user's storage statistics
   */
  async getUserStorageStats(
    ethereumAddress: string,
  ): Promise<UserStorageStats> {
    try {
      const userDir = this.getUserDirectory(ethereumAddress);

      try {
        await fs.access(userDir);
      } catch {
        throw new HttpException(
          'User directory not found',
          HttpStatus.NOT_FOUND,
        );
      }

      const entries = await fs.readdir(userDir, { withFileTypes: true });
      const fileEntries = entries.filter(
        (entry) => entry.isFile() && !entry.name.startsWith('.'),
      );

      let totalSize = 0;
      const files: FileInfo[] = [];

      for (const entry of fileEntries) {
        try {
          const filePath = path.join(userDir, entry.name);
          const stats = await fs.stat(filePath);
          const originalName = entry.name.replace(/^\d+_[a-f0-9]{8}_/, '');

          files.push({
            filename: entry.name,
            originalName,
            size: stats.size,
            uploadDate: stats.mtime,
          });

          totalSize += stats.size;
        } catch (fileError) {
          this.logger.warn(`Failed to stat file ${entry.name}:`, fileError);
        }
      }

      return {
        ethereumAddress,
        fileCount: files.length,
        totalSize,
        files,
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      this.logger.error(
        `Failed to get storage stats for user ${ethereumAddress}:`,
        error,
      );
      throw new HttpException(
        'Failed to retrieve storage statistics',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Delete a file from user's directory
   */
  async deleteFile(ethereumAddress: string, filename: string): Promise<void> {
    try {
      const userDir = this.getUserDirectory(ethereumAddress);
      const filePath = path.join(userDir, filename);

      // Security check
      const resolvedPath = path.resolve(filePath);
      const resolvedUserDir = path.resolve(userDir);
      if (!resolvedPath.startsWith(resolvedUserDir)) {
        throw new HttpException(
          'Access denied: Invalid file path',
          HttpStatus.FORBIDDEN,
        );
      }

      await fs.unlink(filePath);
      await this.updateUserMetadata(ethereumAddress);

      this.logger.log(`File deleted for user ${ethereumAddress}: ${filename}`);
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new HttpException('File not found', HttpStatus.NOT_FOUND);
      }
      this.logger.error(
        `Failed to delete file for user ${ethereumAddress}:`,
        error,
      );
      throw new HttpException(
        'Failed to delete file',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Private helper methods
   */
  private getUserDirectory(ethereumAddress: string): string {
    return path.join(this.dataDir, ethereumAddress);
  }

  private async ensureUserDirectory(ethereumAddress: string): Promise<void> {
    const userDir = this.getUserDirectory(ethereumAddress);
    try {
      await fs.access(userDir);
    } catch {
      await this.createUserDirectory(ethereumAddress);
    }
  }

  private async updateUserMetadata(ethereumAddress: string): Promise<void> {
    try {
      const stats = await this.getUserStorageStats(ethereumAddress);
      const metadata = {
        ethereumAddress,
        updatedAt: new Date().toISOString(),
        fileCount: stats.fileCount,
        totalSize: stats.totalSize,
      };

      const userDir = this.getUserDirectory(ethereumAddress);
      await fs.writeFile(
        path.join(userDir, '.metadata.json'),
        JSON.stringify(metadata, null, 2),
      );
    } catch (error) {
      this.logger.warn(
        `Failed to update metadata for user ${ethereumAddress}:`,
        error,
      );
      // Don't throw - metadata update is not critical
    }
  }
}
