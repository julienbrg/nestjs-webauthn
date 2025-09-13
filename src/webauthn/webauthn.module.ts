import { Module } from '@nestjs/common';
import { WebAuthnService } from './webauthn.service';
import { WebAuthnController } from './webauthn.controller';
import { JsonStorageService } from './services/json-storage.service';
import { StoreService } from '../store/store.service';

@Module({
  controllers: [WebAuthnController],
  providers: [WebAuthnService, JsonStorageService, StoreService],
  exports: [WebAuthnService, JsonStorageService],
})
export class WebAuthnModule {}
