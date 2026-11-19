/**
 * ApprovalExpiryField — the optional "stops working after" choice offered
 * wherever a pending agent is approved. Nothing chosen (or "No expiry") means
 * the agent is approved without an expiry; a duration runs from the moment
 * Approve is pressed. `compact` fits it into a row of buttons.
 */
import { BindingDurationField } from '@/shared/credentials/components';
import type { BindingDuration } from '@/shared/credentials/lib/bindingDuration';
import { describeAgentExpiry } from '@/modules/agents/lib/agentExpiry';

export function ApprovalExpiryField({
	value,
	onChange,
	disabled = false,
	compact = false,
	testIdPrefix = 'approve-expiry',
}: {
	value: BindingDuration | null;
	onChange: (value: BindingDuration | null) => void;
	disabled?: boolean;
	compact?: boolean;
	testIdPrefix?: string;
}) {
	return (
		<BindingDurationField
			value={value}
			onChange={onChange}
			disabled={disabled}
			compact={compact}
			clearable
			placeholder="No expiry"
			label={
				compact ? 'Agent stops working after (optional)' : 'Stops working after (optional)'
			}
			describe={describeAgentExpiry}
			testIdPrefix={testIdPrefix}
		/>
	);
}
