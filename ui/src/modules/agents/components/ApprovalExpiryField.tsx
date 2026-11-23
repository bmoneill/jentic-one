/**
 * ApprovalExpiryField — the optional "stops working after" choice offered
 * wherever a pending agent is approved. Nothing chosen (or "No expiry") means
 * the agent is approved without an expiry; a duration runs from the moment
 * Approve is pressed. `compact` fits it into a row of buttons.
 *
 * Under the org's agent expiry limits, nothing chosen means its default (the
 * server applies it), and choices above its maximum are disabled.
 */
import { BindingDurationField } from '@/shared/credentials/components';
import { useGrantPolicyLimits } from '@/shared/credentials/api';
import { agentExpiryPlaceholder } from '@/shared/credentials/lib/grantLimits';
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
	const limits = useGrantPolicyLimits();
	return (
		<BindingDurationField
			value={value}
			onChange={onChange}
			disabled={disabled}
			compact={compact}
			clearable
			placeholder={agentExpiryPlaceholder(limits)}
			maxSeconds={limits.agent.maxSeconds}
			label={
				compact ? 'Agent stops working after (optional)' : 'Stops working after (optional)'
			}
			describe={describeAgentExpiry}
			testIdPrefix={testIdPrefix}
		/>
	);
}
