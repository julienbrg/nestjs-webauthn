import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { WebAuthnModule } from './webauthn/webauthn.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    WebAuthnModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
