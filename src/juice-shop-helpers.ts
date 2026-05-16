import type { Locator, Page } from '@playwright/test';

type LocatorFactory = (page: Page) => Locator;

export function hashRouteUrl(baseUrl: string, hashRoute: string): string {
  const url = new URL(baseUrl);
  const route = hashRoute.startsWith('#') ? hashRoute.slice(1) : hashRoute;
  url.hash = route.startsWith('/') ? route : `/${route}`;
  return url.toString();
}

export async function closeJuiceShopOverlays(page: Page): Promise<void> {
  const candidates: LocatorFactory[] = [
    (targetPage) => targetPage.getByLabel(/close welcome banner/i),
    (targetPage) => targetPage.getByRole('button', { name: /dismiss/i }),
    (targetPage) => targetPage.getByRole('button', { name: /accept/i }),
    (targetPage) => targetPage.getByRole('button', { name: /me want it/i }),
    (targetPage) => targetPage.locator('button[aria-label="Close Welcome Banner"]'),
    (targetPage) => targetPage.locator('button[aria-label="dismiss cookie message"]'),
    (targetPage) => targetPage.locator('.mat-mdc-dialog-actions button').first()
  ];

  for (const candidate of candidates) {
    const locator = candidate(page).first();
    try {
      if (await locator.isVisible({ timeout: 1_000 })) {
        await locator.click({ timeout: 3_000 });
      }
    } catch {
      // Overlay selectors differ between Juice Shop versions. Missing selectors are fine.
    }
  }
}

export async function tryFill(page: Page, candidates: LocatorFactory[], value: string): Promise<boolean> {
  for (const candidate of candidates) {
    const locator = candidate(page).first();
    try {
      if (await locator.isVisible({ timeout: 1_500 })) {
        await locator.fill(value, { timeout: 5_000 });
        return true;
      }
    } catch {
      // Try the next candidate.
    }
  }

  return false;
}

export async function tryClick(page: Page, candidates: LocatorFactory[]): Promise<boolean> {
  for (const candidate of candidates) {
    const locator = candidate(page).first();
    try {
      if (await locator.isVisible({ timeout: 1_500 })) {
        await locator.click({ timeout: 5_000 });
        return true;
      }
    } catch {
      // Try the next candidate.
    }
  }

  return false;
}

export function textPreview(input: string, maxLength = 600): string {
  return sanitizeDetail(input, maxLength).replace(/\s+/g, ' ').trim().slice(0, maxLength);
}

export function sanitizeDetail(input: string, maxLength = 1_200): string {
  return input
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '?')
    .trim()
    .slice(0, maxLength);
}
