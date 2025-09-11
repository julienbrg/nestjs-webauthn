import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable CORS for development
  app.enableCors({
    origin: ['http://localhost:3001', 'https://genji-app.netlify.app'],
    credentials: true,
  });

  await app.listen(3000);
}
bootstrap();
