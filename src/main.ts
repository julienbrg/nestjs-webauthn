import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Define allowed origins
  const allowedOrigins = [
    'http://localhost:3001',
    'https://genji-app.netlify.app',
    'https://d2u.w3hc.org',
  ];

  // Enable CORS with multiple origins support
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

  console.log('=== Server Configuration ===');
  console.log('Port:', process.env.PORT || 3000);
  console.log('Allowed Origins:', allowedOrigins);
  console.log('WebAuthn RP ID:', process.env.WEBAUTHN_RP_ID);
  console.log('WebAuthn Origin:', process.env.WEBAUTHN_ORIGIN);
  console.log('============================');
}
bootstrap();
