import { describe, expect, it } from 'vitest';
import {
	describePolicy,
	idleWarnable,
	idleWarning,
	idleLabel,
	idleLimitError,
	idleLimitFromSeconds,
	idleSeconds,
} from '@/shared/credentials/lib/idleLimit';

const DAY = 86_400;

describe('idleSeconds / idleLimitError', () => {
	it('reads presets and custom amounts in hours or days', () => {
		expect(idleSeconds({ kind: 'preset', preset: '14d' })).toBe(14 * DAY);
		expect(idleSeconds({ kind: 'custom', amount: '36', unit: 'hours' })).toBe(36 * 3_600);
		expect(idleSeconds({ kind: 'custom', amount: '3', unit: 'days' })).toBe(3 * DAY);
		expect(idleSeconds(null)).toBeNull();
	});

	it('refuses under a day, over 999 days and anything not a whole number', () => {
		expect(idleSeconds({ kind: 'custom', amount: '23', unit: 'hours' })).toBeNull();
		expect(idleLimitError({ kind: 'custom', amount: '23', unit: 'hours' })).toBe(
			'Choose between 1 day and 999 days.',
		);
		expect(idleLimitError({ kind: 'custom', amount: '1000', unit: 'days' })).not.toBeNull();
		expect(idleLimitError({ kind: 'custom', amount: '1.5', unit: 'days' })).toBe(
			'Enter a whole number.',
		);
		expect(idleLimitError({ kind: 'custom', amount: '', unit: 'days' })).toBe(
			'Enter how long it may go unused.',
		);
		expect(idleLimitError(null)).toBeNull();
	});
});

describe('idleLimitFromSeconds / idleLabel', () => {
	it('round-trips a limit the API returns', () => {
		expect(idleLimitFromSeconds(30 * DAY)).toEqual({ kind: 'preset', preset: '30d' });
		expect(idleLimitFromSeconds(3 * DAY)).toEqual({
			kind: 'custom',
			amount: '3',
			unit: 'days',
		});
		expect(idleLimitFromSeconds(36 * 3_600)).toEqual({
			kind: 'custom',
			amount: '36',
			unit: 'hours',
		});
		expect(idleLimitFromSeconds(null)).toBeNull();
		expect(idleLabel(DAY)).toBe('1 day');
		expect(idleLabel(14 * DAY)).toBe('14 days');
		expect(idleLabel(36 * 3_600)).toBe('36 hours');
	});
});

describe('idleWarning / idleWarnable', () => {
	it('sends a ticked warning only on a limit of 4 days or more', () => {
		expect(idleWarnable(4 * DAY)).toBe(true);
		expect(idleWarnable(4 * DAY - 1)).toBe(false);
		expect(idleWarnable(null)).toBe(false);
		expect(idleWarning({ kind: 'preset', preset: '7d', warn: true })).toBe(true);
		expect(idleWarning({ kind: 'preset', preset: '7d' })).toBe(false);
		expect(idleWarning({ kind: 'custom', amount: '3', unit: 'days', warn: true })).toBe(false);
		expect(idleWarning(null)).toBe(false);
	});

	it('seeds the warning from the binding', () => {
		expect(idleLimitFromSeconds(14 * DAY, true)).toEqual({
			kind: 'preset',
			preset: '14d',
			warn: true,
		});
	});
});

describe('describePolicy', () => {
	const end = new Date('2026-12-15T12:00:00Z');

	it('says how the end date and the idle limit combine', () => {
		expect(describePolicy(end, 14 * DAY)).toMatch(
			/^Access ends around .+, or sooner if unused for 14 days\.$/,
		);
		expect(describePolicy(end, null)).toMatch(/^Access ends around .+\.$/);
		expect(describePolicy('never', 14 * DAY)).toBe(
			'Access ends if unused for 14 days. An agent that keeps using it keeps access.',
		);
		expect(describePolicy('never', null)).toBeNull();
	});
});
