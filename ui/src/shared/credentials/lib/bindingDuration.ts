/**
 * How long a new credential binding lasts — the grant's `expires_at`, chosen
 * as an amount and a unit ("10 minutes") rather than a timestamp.
 *
 * The amount is kept as the field's text so a half-typed value ("", "1") stays
 * editable; it is parsed only when the expiry is worked out. The expiry is
 * computed at the moment of the bind, never ahead of it, so "10 minutes" runs
 * from when the operator confirms, not from when the step opened.
 *
 * `never` is the one unit with no amount: the binding is made without an
 * `expires_at` and lasts until it is suspended or removed.
 *
 * Every unit is a fixed length of time. There are deliberately no months (or
 * years): "1 month" depends on the start date and the calendar, which makes the
 * resulting expiry ambiguous; operators wanting about a month enter 30 days.
 */

export type BindingDurationUnit = 'seconds' | 'minutes' | 'hours' | 'days' | 'never';

export interface BindingDuration {
	/** The number field's text. */
	amount: string;
	unit: BindingDurationUnit;
}

/** A low default: a new binding lapses quickly unless the operator says otherwise. */
export const DEFAULT_BINDING_DURATION: BindingDuration = { amount: '10', unit: 'minutes' };

export const BINDING_DURATION_UNITS: readonly { value: BindingDurationUnit; label: string }[] = [
	{ value: 'seconds', label: 'Seconds' },
	{ value: 'minutes', label: 'Minutes' },
	{ value: 'hours', label: 'Hours' },
	{ value: 'days', label: 'Days' },
	{ value: 'never', label: 'Never expires' },
];

/** Upper bound on the amount, whatever the unit (999 days is about 2.7 years). */
export const MAX_BINDING_DURATION_AMOUNT = 999;

const UNIT_MS: Record<Exclude<BindingDurationUnit, 'never'>, number> = {
	seconds: 1_000,
	minutes: 60_000,
	hours: 3_600_000,
	days: 86_400_000,
};

/** The amount as a whole number in range, or `null` when it is not one. */
export function parseDurationAmount(amount: string): number | null {
	const trimmed = amount.trim();
	if (!/^\d+$/.test(trimmed)) return null;
	const n = Number(trimmed);
	return n >= 1 && n <= MAX_BINDING_DURATION_AMOUNT ? n : null;
}

/** What is wrong with the amount, for the field's error — `null` when it is fine
 * (always, for `never`, which takes no amount). */
export function bindingDurationError(duration: BindingDuration): string | null {
	if (duration.unit === 'never') return null;
	if (duration.amount.trim() === '') return 'Enter how long access lasts.';
	if (parseDurationAmount(duration.amount) === null) {
		return `Enter a whole number from 1 to ${MAX_BINDING_DURATION_AMOUNT}.`;
	}
	return null;
}

/**
 * When a binding made at `now` with this duration expires: a `Date`, `'never'`
 * for a binding with no expiry, or `null` for an invalid amount. Kept apart so
 * a bad amount can never be mistaken for "no expiry".
 */
export function expiresAtFromDuration(
	duration: BindingDuration,
	now: Date = new Date(),
): Date | 'never' | null {
	if (duration.unit === 'never') return 'never';
	const amount = parseDurationAmount(duration.amount);
	if (amount === null) return null;
	return new Date(now.getTime() + amount * UNIT_MS[duration.unit]);
}
