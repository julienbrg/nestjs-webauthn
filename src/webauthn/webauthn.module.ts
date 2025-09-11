import { Module } from '@nestjs/common';
import { WebAuthnService } from './webauthn.service';
import { WebAuthnController } from './webauthn.controller';

@Module({
  controllers: [WebAuthnController],
  providers: [WebAuthnService],
  exports: [WebAuthnService],
})
export class WebAuthnModule {}
