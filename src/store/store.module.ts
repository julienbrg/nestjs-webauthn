import { Module } from '@nestjs/common';
import { MulterModule } from '@nestjs/platform-express';
import { StoreService } from './store.service';
import { StoreController } from './store.controller';

@Module({
  imports: [
    MulterModule.register({
      limits: {
        fileSize: 10 * 1024 * 1024, // 10MB
        files: 1, // Only allow 1 file at a time
      },
    }),
  ],
  controllers: [StoreController],
  providers: [StoreService],
  exports: [StoreService],
})
export class StoreModule {}
