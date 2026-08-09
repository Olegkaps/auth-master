import { expect, type Page } from '@playwright/test';

type RGB = readonly [number, number, number];
type RGBA = readonly [number, number, number, number];

function parseComputedRGBA(value: string): RGBA {
  if (!value.startsWith('rgb')) throw new Error(`unsupported computed color: ${value}`);
  const channels = value.match(/[\d.]+/g)?.map(Number);
  if (!channels || channels.length < 3 || channels.slice(0, 3).some((channel) => channel < 0 || channel > 255)) {
    throw new Error(`invalid computed color: ${value}`);
  }
  const alpha = channels[3] ?? 1;
  if (alpha < 0 || alpha > 1) throw new Error(`invalid computed alpha: ${value}`);
  return [channels[0], channels[1], channels[2], alpha];
}

function relativeLuminance([red, green, blue]: RGB): number {
  const linearize = (channel: number): number => {
    const srgb = channel / 255;
    return srgb <= 0.04045 ? srgb / 12.92 : ((srgb + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * linearize(red) + 0.7152 * linearize(green) + 0.0722 * linearize(blue);
}

function contrastRatio(first: RGB, second: RGB): number {
  const lighter = Math.max(relativeLuminance(first), relativeLuminance(second));
  const darker = Math.min(relativeLuminance(first), relativeLuminance(second));
  return (lighter + 0.05) / (darker + 0.05);
}

function composite(foreground: RGBA, background: RGB): RGB {
  return [
    foreground[0] * foreground[3] + background[0] * (1 - foreground[3]),
    foreground[1] * foreground[3] + background[1] * (1 - foreground[3]),
    foreground[2] * foreground[3] + background[2] * (1 - foreground[3]),
  ];
}

function contrastAgainst(foreground: RGBA, background: RGBA): number {
  const opaqueBackground = composite(background, [255, 255, 255]);
  return contrastRatio(composite(foreground, opaqueBackground), opaqueBackground);
}

export async function expectResponsiveExampleLayout(
  page: Page,
  cardTestIds: string[],
  controlTestIds: string[],
): Promise<void> {
  await page.setViewportSize({ width: 1280, height: 900 });
  expect(contrastRatio([0, 0, 0], [255, 255, 255])).toBeCloseTo(21, 5);
  expect(contrastRatio([102, 112, 133], [102, 112, 133])).toBe(1);
  expect(composite([0, 0, 0, 0.5], [255, 255, 255])).toEqual([127.5, 127.5, 127.5]);
  expect(contrastAgainst([0, 0, 0, 0], [255, 255, 255, 1])).toBe(1);
  expect(contrastAgainst([0, 0, 0, 1], [255, 255, 255, 1])).toBeCloseTo(21, 5);
  const accessibility = await page.evaluate((controlTestID) => {
    const input = document.querySelector(`[data-testid="${controlTestID}"]`);
    const secondary = document.querySelector('button.secondary');
    if (!(input instanceof HTMLElement) || !(secondary instanceof HTMLButtonElement)) {
      throw new Error('accessibility contrast controls are missing');
    }
    const inputStyle = getComputedStyle(input);
    const secondaryStyle = getComputedStyle(secondary);
    return {
      lang: document.documentElement.lang,
      inputBackground: inputStyle.backgroundColor,
      inputBorder: inputStyle.borderTopColor,
      placeholder: getComputedStyle(input, '::placeholder').color,
      secondaryBackground: secondaryStyle.backgroundColor,
      secondaryBorder: secondaryStyle.borderTopColor,
    };
  }, controlTestIds[0]);
  expect(accessibility.lang).toBe('en');
  expect(contrastAgainst(parseComputedRGBA(accessibility.inputBorder), parseComputedRGBA(accessibility.inputBackground))).toBeGreaterThanOrEqual(3);
  expect(contrastAgainst(parseComputedRGBA(accessibility.placeholder), parseComputedRGBA(accessibility.inputBackground))).toBeGreaterThanOrEqual(4.5);
  expect(contrastAgainst(parseComputedRGBA(accessibility.secondaryBorder), parseComputedRGBA(accessibility.secondaryBackground))).toBeGreaterThanOrEqual(3);

  const secondary = page.locator('button.secondary').first();
  await secondary.hover();
  const hoverState = await secondary.evaluate((button) => {
    const style = getComputedStyle(button);
    const card = button.closest('[data-ui="card"]');
    if (!(card instanceof HTMLElement)) throw new Error('secondary button card is missing');
    return {
      background: style.backgroundColor,
      border: style.borderTopColor,
      surroundingBackground: getComputedStyle(card).backgroundColor,
    };
  });
  expect(contrastAgainst(parseComputedRGBA(hoverState.border), parseComputedRGBA(hoverState.background))).toBeGreaterThanOrEqual(3);
  expect(contrastAgainst(parseComputedRGBA(hoverState.border), parseComputedRGBA(hoverState.surroundingBackground))).toBeGreaterThanOrEqual(3);

  await page.locator('body').click({ position: { x: 2, y: 2 } });
  await page.keyboard.press('Tab');
  const focusControl = page.getByTestId(controlTestIds[0]);
  await expect(focusControl).toBeFocused();
  const focusState = await focusControl.evaluate((control) => {
    const style = getComputedStyle(control);
    const card = control.closest('[data-ui="card"]');
    if (!(card instanceof HTMLElement)) throw new Error('focused control card is missing');
    return {
      focusVisible: control.matches(':focus-visible'),
      outlineColor: style.outlineColor,
      outlineStyle: style.outlineStyle,
      outlineWidth: Number.parseFloat(style.outlineWidth),
      surroundingBackground: getComputedStyle(card).backgroundColor,
    };
  });
  expect(focusState.focusVisible).toBe(true);
  expect(focusState.outlineStyle).toBe('solid');
  expect(focusState.outlineWidth).toBeGreaterThanOrEqual(3);
  expect(contrastAgainst(parseComputedRGBA(focusState.outlineColor), parseComputedRGBA(focusState.surroundingBackground))).toBeGreaterThanOrEqual(3);

  const desktopMain = await page.locator('[data-ui="page-shell"]').boundingBox();
  expect(desktopMain).not.toBeNull();
  expect(desktopMain!.width).toBeGreaterThan(600);
  expect(desktopMain!.width).toBeLessThanOrEqual(1100);
  for (const testID of [...cardTestIds, ...controlTestIds]) {
    await expect(page.getByTestId(testID)).toBeVisible();
  }

  await page.setViewportSize({ width: 390, height: 844 });
  const mobileMain = await page.locator('[data-ui="page-shell"]').boundingBox();
  expect(mobileMain).not.toBeNull();
  expect(mobileMain!.width).toBeGreaterThan(330);
  expect(mobileMain!.width).toBeLessThanOrEqual(390);
  const mobileControl = await page.getByTestId(controlTestIds[0]).boundingBox();
  expect(mobileControl).not.toBeNull();
  expect(mobileControl!.width).toBeGreaterThan(250);
  const pageWidth = await page.evaluate(() => ({
    client: document.documentElement.clientWidth,
    scroll: document.documentElement.scrollWidth,
  }));
  expect(pageWidth.scroll).toBeLessThanOrEqual(pageWidth.client + 1);

  await page.setViewportSize({ width: 1280, height: 900 });
}
