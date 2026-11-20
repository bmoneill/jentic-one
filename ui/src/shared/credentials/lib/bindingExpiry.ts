/**
 * How a binding's end date reads wherever the binding is shown: "Expires in
 * 3 days", "Expired 2 days ago", or nothing for a binding that never expires.
 *
 * The server reports `expired` as of its read; a binding whose `expires_at`
 * passes while the page is open is expired too, so both count. Time left is
 * rounded to the nearest whole unit, so access just set for 7 days reads
 * "Expires in 7 days", not 6; time since an end is rounded down, like every
 * other "ago" in the console. Where the exact moment matters, it is shown too.
 */
import type { BindingDuration } from '@/shared/credentials/lib/bindingDuration';
import { expiresAtFromDuration } from '@/shared/credentials/lib/bindingDuration';

const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

/**
 * Within this long of its end, a binding's end date reads as a caution: the
 * same 48 hours the owner is warned before an idle limit (D13). A window as
 * long as a common duration (a week, say) would mark every binding of that
 * length as ending soon from the moment it was made.
 */
export const EXPIRES_SOON_MS = 2 * DAY_MS;

/** What a binding carries about its end date, as the API reports it. */
export interface BindingExpiryFields {
	/** RFC 3339; null when it never expires, undefined when not reported. */
	expiresAt?: string | null;
	/** The server's verdict as of its read. */
	expired?: boolean;
}

function endMs(expiresAt: string | null | undefined): number | null {
	if (!expiresAt) return null;
	const ms = Date.parse(expiresAt);
	return Number.isNaN(ms) ? null : ms;
}

function plural(n: number, unit: string): string {
	return `${n} ${unit}${n === 1 ? '' : 's'}`;
}

type SpanUnit = 'day' | 'hour' | 'minute';

/**
 * A span as a count of its largest unit, or null under one minute. Rounded to
 * the nearest (`round`) or down: a rounding that reaches the next unit up (60
 * minutes, 24 hours) is read in that unit.
 */
function spanParts(ms: number, round: boolean): { n: number; unit: SpanUnit } | null {
	const to = (unitMs: number): number => (round ? Math.round : Math.floor)(ms / unitMs);
	const minutes = to(MINUTE_MS);
	if (minutes < 1) return null;
	if (minutes < 60) return { n: minutes, unit: 'minute' };
	const hours = to(HOUR_MS);
	if (hours < 24) return { n: hours, unit: 'hour' };
	return { n: to(DAY_MS), unit: 'day' };
}

/** "3 days", "5 hours", "12 minutes", or null under a minute. */
function span(ms: number, round: boolean): string | null {
	const parts = spanParts(ms, round);
	return parts ? plural(parts.n, parts.unit) : null;
}

/** "3d", "5h", "12m", or "<1m". */
function shortSpan(ms: number, round: boolean): string {
	const parts = spanParts(ms, round);
	return parts ? `${parts.n}${parts.unit[0]}` : '<1m';
}

/** Under the duration control where a binding is created, while nothing is chosen. */
export const NO_DURATION_HINT =
	'Choose when this access ends. To give access with no end date, pick Custom… and then No expiry.';

/** Whether the binding no longer authorizes calls because its end date passed. */
export function bindingIsExpired(
	{ expiresAt, expired }: BindingExpiryFields,
	now: number = Date.now(),
): boolean {
	if (expired) return true;
	const end = endMs(expiresAt);
	return end !== null && end <= now;
}

/** Whether the binding ends within {@link EXPIRES_SOON_MS} and hasn't yet. */
export function bindingExpiresSoon(
	binding: BindingExpiryFields,
	now: number = Date.now(),
): boolean {
	const end = endMs(binding.expiresAt);
	return end !== null && !bindingIsExpired(binding, now) && end - now <= EXPIRES_SOON_MS;
}

/**
 * "Expires in 3 days" / "Expires in less than a minute" / "Expired 2 days ago"
 * / "Expired just now", or null when the binding never expires (or the server
 * didn't say), so nothing is claimed.
 */
export function bindingExpiryLabel(
	binding: BindingExpiryFields,
	now: number = Date.now(),
): string | null {
	const end = endMs(binding.expiresAt);
	if (end === null) return binding.expired ? 'Expired' : null;
	if (bindingIsExpired(binding, now)) {
		const ago = span(now - end, false);
		return ago ? `Expired ${ago} ago` : 'Expired just now';
	}
	const left = span(end - now, true);
	return left ? `Expires in ${left}` : 'Expires in less than a minute';
}

/**
 * The compact form for tight spots: "Ends in 3d" / "Ended 2d ago", or null as
 * {@link bindingExpiryLabel}. Paired with the full phrase in the element's
 * accessible name or tooltip.
 */
export function bindingExpiryShortLabel(
	binding: BindingExpiryFields,
	now: number = Date.now(),
): string | null {
	const end = endMs(binding.expiresAt);
	if (end === null) return binding.expired ? 'Ended' : null;
	if (bindingIsExpired(binding, now)) return `Ended ${shortSpan(now - end, false)} ago`;
	return `Ends in ${shortSpan(end - now, true)}`;
}

/**
 * Whether a complete duration is chosen — a preset, a valid custom amount, or
 * "No expiry". Creating or renewing a binding waits for one: there is no
 * default, so an end date (or deliberately none) is always the operator's call.
 */
export function durationChosen(duration: BindingDuration | null): boolean {
	return expiresAtFromDuration(duration) !== null;
}

/**
 * Whether the choice is "No expiry": saving it creates a binding with no end
 * date, or clears an existing one's. Either asks for confirmation first.
 */
export function choosesNoExpiry(duration: BindingDuration | null): boolean {
	return expiresAtFromDuration(duration) === 'never';
}
