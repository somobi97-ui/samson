import dotenv from 'dotenv';
import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import { createApiApp } from './server/app.ts';
import { serverConfig } from './server/config/env.ts';
import { logger } from './server/services/logger.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

process.on('unhandledRejection', (reason) => {
  logger.error('process.unhandled_rejection', {}, reason);
});

process.on('uncaughtException', (err) => {
  logger.error('process.uncaught_exception', {}, err);
});

async function startServer() {
  const app = createApiApp();

  const isProd = process.env.NODE_ENV === 'production';
  const distPath = path.resolve(__dirname, 'dist');

  if (!isProd || !fs.existsSync(distPath)) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const PORT = serverConfig.port;
  app.listen(PORT, '0.0.0.0', () => {
    logger.info('server.started', {
      port: PORT,
      mode: isProd ? 'production' : 'development',
      intentModel: serverConfig.ai.intentModel,
    });
  });
}

startServer();
