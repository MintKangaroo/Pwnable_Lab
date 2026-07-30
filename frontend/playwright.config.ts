import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://127.0.0.1:15173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } },
    },
  ],
  webServer: [
    {
      command: 'uvicorn pwnable_lab.api.app:app --host 127.0.0.1 --port 18000',
      cwd: '../backend',
      env: {
        PLAB_DATABASE_URL: 'sqlite:///./playwright.db',
        PLAB_STORAGE_DIR: './playwright-storage',
        PLAB_AUTO_CREATE_SCHEMA: 'true',
      },
      url: 'http://127.0.0.1:18000/api/v1/health',
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
    {
      command: 'npm run dev -- --host 127.0.0.1 --port 15173',
      cwd: '.',
      env: {
        VITE_API_TARGET: 'http://127.0.0.1:18000',
      },
      url: 'http://127.0.0.1:15173',
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
  ],
});
