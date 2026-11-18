import { describe, expect, it } from 'vitest';
import {
	BINDING_DURATION_UNITS,
	DEFAULT_BINDING_DURATION,
	bindingDurationError,
	expiresAtFromDuration,
	parseDurationAmount,
} from '@/shared/credentials/lib/bindingDuration';

const NOW = new Date('2026-01-31T12:00:00.000Z');

/** The expiry as an ISO string — fails the test unless it is an actual date. */
function iso(result: Date | 'never' | null): string {
	expect(result).toBeInstanceOf(Date);
	return (result as Date).toISOString();
}

describe('parseDurationAmount', () => {
	it('accepts whole numbers from 1 to 999', () => {
		expect(parseDurationAmount('1')).toBe(1);
		expect(parseDurationAmount(' 45 ')).toBe(45);
		expect(parseDurationAmount('999')).toBe(999);
	});

	it('refuses anything else', () => {
		for (const bad of ['', '0', '1000', '-5', '1.5', '1e3', 'ten']) {
			expect(parseDurationAmount(bad)).toBeNull();
		}
	});
});

describe('bindingDurationError', () => {
	it('is silent for the default', () => {
		expect(DEFAULT_BINDING_DURATION).toEqual({ amount: '10', unit: 'minutes' });
		expect(bindingDurationError(DEFAULT_BINDING_DURATION)).toBeNull();
	});

	it('asks for an amount when the field is empty, and a valid one otherwise', () => {
		expect(bindingDurationError({ amount: '', unit: 'hours' })).toBe(
			'Enter how long access lasts.',
		);
		expect(bindingDurationError({ amount: '0', unit: 'hours' })).toBe(
			'Enter a whole number from 1 to 999.',
		);
	});
});

describe('BINDING_DURATION_UNITS', () => {
	it('offers only fixed-length units, plus Never expires — no months', () => {
		expect(BINDING_DURATION_UNITS.map((u) => u.value)).toEqual([
			'seconds',
			'minutes',
			'hours',
			'days',
			'never',
		]);
	});
});

describe('expiresAtFromDuration', () => {
	it.each([
		['30', 'seconds', '2026-01-31T12:00:30.000Z'],
		['10', 'minutes', '2026-01-31T12:10:00.000Z'],
		['2', 'hours', '2026-01-31T14:00:00.000Z'],
		['3', 'days', '2026-02-03T12:00:00.000Z'],
	] as const)('%s %s from now', (amount, unit, expected) => {
		expect(iso(expiresAtFromDuration({ amount, unit }, NOW))).toBe(expected);
	});

	it('the longest duration is 999 days, a fixed length', () => {
		expect(iso(expiresAtFromDuration({ amount: '999', unit: 'days' }, NOW))).toBe(
			'2028-10-26T12:00:00.000Z',
		);
	});

	it('is null for an invalid amount', () => {
		expect(expiresAtFromDuration({ amount: '', unit: 'minutes' }, NOW)).toBeNull();
	});

	it("is 'never' for Never expires, whatever the amount field holds", () => {
		expect(expiresAtFromDuration({ amount: '10', unit: 'never' }, NOW)).toBe('never');
		expect(expiresAtFromDuration({ amount: '', unit: 'never' }, NOW)).toBe('never');
		expect(bindingDurationError({ amount: '', unit: 'never' })).toBeNull();
	});
});
