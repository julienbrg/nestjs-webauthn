import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { WebAuthnService } from './webauthn/webauthn.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Get WebAuthn service to access allowed origins
  const webAuthnService = app.get(WebAuthnService);
  const allowedOrigins = webAuthnService.getAllowedOrigins();

  // Enable CORS with dynamic origins support
  app.enableCors({
    origin: (
      origin: string | undefined,
      callback: (err: Error | null, allow?: boolean) => void,
    ) => {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) {
        callback(null, true);
        return;
      }

      if (allowedOrigins.includes(origin)) {
        callback(null, true);
        return;
      } else {
        callback(new Error('Not allowed by CORS'), false);
        return;
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'Origin',
      'X-Requested-With',
      'Accept',
    ],
  });

  await app.listen(process.env.PORT || 3000);
}
bootstrap();
