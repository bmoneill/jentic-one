import { describe, expect, it } from 'vitest';
import {
	bindingExpiresSoon,
	bindingExpiryLabel,
	bindingExpiryShortLabel,
	bindingIsExpired,
	choosesNoExpiry,
	durationChosen,
} from '@/shared/credentials/lib/bindingExpiry';
import { INITIAL_CUSTOM_DURATION } from '@/shared/credentials/lib/bindingDuration';

const NOW = Date.parse('2026-01-31T12:00:00.000Z');
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** An end date `ms` from NOW (negative: in the past). */
function endsIn(ms: number): { expiresAt: string } {
	return { expiresAt: new Date(NOW + ms).toISOString() };
}

describe('bindingIsExpired', () => {
	it('is false with no end date, and before it', () => {
		expect(bindingIsExpired({ expiresAt: null }, NOW)).toBe(false);
		expect(bindingIsExpired({}, NOW)).toBe(false);
		expect(bindingIsExpired(endsIn(1), NOW)).toBe(false);
	});

	it('is true at and after the end date, as the broker refuses it', () => {
		expect(bindingIsExpired(endsIn(0), NOW)).toBe(true);
		expect(bindingIsExpired(endsIn(-DAY), NOW)).toBe(true);
	});

	it("trusts the server's verdict even when the local clock disagrees", () => {
		expect(bindingIsExpired({ ...endsIn(HOUR), expired: true }, NOW)).toBe(true);
	});
});

describe('bindingExpiryLabel', () => {
	it('claims nothing for a binding that never expires', () => {
		expect(bindingExpiryLabel({ expiresAt: null }, NOW)).toBeNull();
		expect(bindingExpiryLabel({}, NOW)).toBeNull();
	});

	it('says how long is left, rounded to the nearest unit', () => {
		expect(bindingExpiryLabel(endsIn(3 * DAY), NOW)).toBe('Expires in 3 days');
		// Just saved for 7 days: it reads 7, not 6.
		expect(bindingExpiryLabel(endsIn(7 * DAY - 1_000), NOW)).toBe('Expires in 7 days');
		expect(bindingExpiryLabel(endsIn(2 * DAY + 11 * HOUR), NOW)).toBe('Expires in 2 days');
		expect(bindingExpiryLabel(endsIn(DAY), NOW)).toBe('Expires in 1 day');
		expect(bindingExpiryLabel(endsIn(5 * HOUR + 20 * MINUTE), NOW)).toBe('Expires in 5 hours');
		expect(bindingExpiryLabel(endsIn(MINUTE), NOW)).toBe('Expires in 1 minute');
		expect(bindingExpiryLabel(endsIn(20_000), NOW)).toBe('Expires in less than a minute');
	});

	it('reads a rounding that reaches the next unit in that unit', () => {
		expect(bindingExpiryLabel(endsIn(59 * MINUTE + 50_000), NOW)).toBe('Expires in 1 hour');
		expect(bindingExpiryLabel(endsIn(23 * HOUR + 40 * MINUTE), NOW)).toBe('Expires in 1 day');
	});

	it('says how long ago an expired binding ended', () => {
		expect(bindingExpiryLabel(endsIn(-2 * DAY), NOW)).toBe('Expired 2 days ago');
		expect(bindingExpiryLabel(endsIn(-HOUR), NOW)).toBe('Expired 1 hour ago');
		expect(bindingExpiryLabel(endsIn(0), NOW)).toBe('Expired just now');
	});

	it('says Expired for a verdict with no date to go on', () => {
		expect(bindingExpiryLabel({ expiresAt: null, expired: true }, NOW)).toBe('Expired');
	});
});

describe('bindingExpiryShortLabel', () => {
	it('is the compact form', () => {
		expect(bindingExpiryShortLabel(endsIn(3 * DAY), NOW)).toBe('Ends in 3d');
		expect(bindingExpiryShortLabel(endsIn(5 * HOUR), NOW)).toBe('Ends in 5h');
		expect(bindingExpiryShortLabel(endsIn(12 * MINUTE), NOW)).toBe('Ends in 12m');
		expect(bindingExpiryShortLabel(endsIn(1_000), NOW)).toBe('Ends in <1m');
		expect(bindingExpiryShortLabel(endsIn(-2 * DAY), NOW)).toBe('Ended 2d ago');
		expect(bindingExpiryShortLabel({ expiresAt: null }, NOW)).toBeNull();
	});
});

describe('bindingExpiresSoon', () => {
	it('is true within a week of the end, and not once it has passed', () => {
		expect(bindingExpiresSoon(endsIn(7 * DAY), NOW)).toBe(true);
		expect(bindingExpiresSoon(endsIn(HOUR), NOW)).toBe(true);
		expect(bindingExpiresSoon(endsIn(7 * DAY + 1), NOW)).toBe(false);
		expect(bindingExpiresSoon(endsIn(-HOUR), NOW)).toBe(false);
		expect(bindingExpiresSoon({ expiresAt: null }, NOW)).toBe(false);
	});
});

describe('durationChosen / choosesNoExpiry', () => {
	const noExpiry = { kind: 'custom' as const, amount: '1', unit: 'never' as const };
	const preset = { kind: 'preset' as const, preset: '7d' as const };
	const bad = { kind: 'custom' as const, amount: '', unit: 'days' as const };

	it('a duration is chosen once it is a preset, a valid amount or No expiry', () => {
		expect(durationChosen(null)).toBe(false);
		expect(durationChosen(bad)).toBe(false);
		expect(durationChosen(preset)).toBe(true);
		expect(durationChosen(INITIAL_CUSTOM_DURATION)).toBe(true);
		expect(durationChosen(noExpiry)).toBe(true);
	});

	it('only No expiry means no end date — nothing chosen is not a choice', () => {
		expect(choosesNoExpiry(noExpiry)).toBe(true);
		expect(choosesNoExpiry(null)).toBe(false);
		expect(choosesNoExpiry(preset)).toBe(false);
		expect(choosesNoExpiry(bad)).toBe(false);
	});
});
