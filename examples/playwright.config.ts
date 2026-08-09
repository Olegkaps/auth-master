import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e', workers: 1, fullyParallel: false, reporter: 'list', timeout: 30_000,
  use: { trace: 'retain-on-failure' },
  projects: [
    { name: 'minio-storage', use: { baseURL: `http://127.0.0.1:${process.env.MINIO_STORAGE_PORT ?? '8191'}` }, testMatch: /minio-storage\.spec\.ts/ },
    { name: 'deployment-api', use: { baseURL: `http://127.0.0.1:${process.env.DEPLOYMENT_API_PORT ?? '8192'}` }, testMatch: /deployment-api\.spec\.ts/ },
    { name: 'support-desk', use: { baseURL: `http://127.0.0.1:${process.env.SUPPORT_DESK_PORT ?? '8193'}` }, testMatch: /support-desk\.spec\.ts/ },
  ],
});
