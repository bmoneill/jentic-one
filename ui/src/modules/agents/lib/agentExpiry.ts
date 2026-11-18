/**
 * Copy for an agent's expiry, shared by the expiry card and the approve
 * banner so both say the same thing under the duration control.
 */
import { formatDurationEnd } from '@/shared/credentials/components';

/** The line under the duration control: when the agent would stop working if saved now. */
export function describeAgentExpiry(end: Date | 'never'): string {
	return end === 'never'
		? 'The agent never stops working on its own.'
		: `If saved now, the agent stops working around ${formatDurationEnd(end)}: it gets no new tokens and the ones it holds stop working.`;
}
