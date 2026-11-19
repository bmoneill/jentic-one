/**
 * RenewBindingControl — renew one agent's binding to a credential: choose a
 * new duration (the shared duration control, nothing preselected) and save it
 * through `PATCH /agents/{id}/credentials/{cid}`. The end date runs from the
 * moment of saving. "No expiry" (in Custom…) clears the end date, behind the
 * "No expiry" warning. Renewing restores an expired binding; it never resumes a
 * suspended one.
 *
 * Shown only to a viewer who may renew: `agents:write` and the credential's
 * owner, or an `org:admin` (the same checks as resuming a binding). The host
 * decides; the server refuses anyone else with a 404.
 */
import { useRef, useState, type KeyboardEvent } from 'react';
import { RefreshCw } from 'lucide-react';
import { Button, ErrorAlert, UserText, toast } from '@/shared/ui';
import { isolateText } from '@/shared/lib/utils';
import { useRenewCredentialBinding } from '@/shared/credentials/api/vendors-hooks';
import { expiresAtIso, type BindingDuration } from '@/shared/credentials/lib/bindingDuration';
import { choosesNoExpiry, durationChosen } from '@/shared/credentials/lib/bindingExpiry';
import {
	BindingDurationField,
	formatDurationEnd,
} from '@/shared/credentials/components/BindingDurationField';
import {
	NoExpiryConfirmDialog,
	useNoExpiryConfirm,
} from '@/shared/credentials/components/NoExpiryConfirmDialog';

export interface RenewBindingControlProps {
	agentId: string;
	agentName: string;
	credentialId: string;
	/** The binding's current end date; null when it never expires. */
	expiresAt: string | null | undefined;
	expired: boolean;
	/** Fit into a list row: no visible label. */
	compact?: boolean;
	/** After a renewal lands. */
	onRenewed?: () => void;
	/** Prefix for test ids (`<prefix>-duration-*`, `<prefix>-save`). */
	testIdPrefix?: string;
}

function describeRenewal(end: Date | 'never'): string {
	return end === 'never'
		? 'No expiry: access lasts until someone removes it.'
		: `If saved now, access ends around ${formatDurationEnd(end)}.`;
}

export function RenewBindingControl({
	agentId,
	agentName,
	credentialId,
	expiresAt,
	expired,
	compact = false,
	onRenewed,
	testIdPrefix = 'renew-binding',
}: RenewBindingControlProps) {
	const renew = useRenewCredentialBinding();
	const confirm = useNoExpiryConfirm();
	const fieldRef = useRef<HTMLSelectElement>(null);
	const [duration, setDuration] = useState<BindingDuration | null>(null);

	const clearing = choosesNoExpiry(duration);
	// Clearing an end date the binding doesn't have changes nothing.
	const nothingToClear = clearing && !expiresAt;
	const blocked = renew.isPending || !durationChosen(duration) || nothingToClear;

	const save = (): void => {
		// Worked out now, as the operator confirms: the duration runs from here.
		const at = expiresAtIso(duration);
		if (at === undefined) return;
		renew.mutate(
			{ agentId, credentialId, expiresAt: at },
			{
				onSuccess: () => {
					toast({
						title: at === null ? 'Expiry removed' : 'Access renewed',
						description:
							at === null
								? `${isolateText(agentName)} keeps this access until someone removes it.`
								: `${isolateText(agentName)} has access until ${formatDurationEnd(new Date(at))}.`,
						variant: 'success',
					});
					setDuration(null);
					onRenewed?.();
				},
			},
		);
	};

	const label = expired ? 'Renew for' : expiresAt ? 'Change expiry to' : 'Set an expiry';
	const action = clearing
		? 'Remove expiry'
		: expired
			? 'Renew'
			: expiresAt
				? 'Change expiry'
				: 'Set expiry';

	const submit = (): void => confirm.request(clearing, save);
	// Enter in the amount renews — and never submits a form the host wraps
	// around this control (the edit-credential sheet is one).
	const onKeyDown = (event: KeyboardEvent<HTMLDivElement>): void => {
		if (event.key !== 'Enter' || !(event.target instanceof HTMLInputElement)) return;
		event.preventDefault();
		if (!blocked) submit();
	};

	return (
		<div className="space-y-2" data-testid={testIdPrefix} onKeyDown={onKeyDown}>
			<BindingDurationField
				value={duration}
				onChange={setDuration}
				disabled={renew.isPending}
				label={label}
				compact={compact}
				describe={describeRenewal}
				selectRef={fieldRef}
				testIdPrefix={testIdPrefix}
			/>
			<Button
				size="sm"
				variant={expired ? 'primary' : 'secondary'}
				disabled={blocked}
				loading={renew.isPending}
				onClick={submit}
				data-testid={`${testIdPrefix}-save`}
				aria-label={`${action} for ${isolateText(agentName)}`}
			>
				<RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
				{action}
			</Button>
			{renew.error && <ErrorAlert message={renew.error} />}
			<NoExpiryConfirmDialog
				{...confirm.dialogProps}
				kind="renew"
				subject={<UserText>{agentName}</UserText>}
				fieldRef={fieldRef}
			/>
		</div>
	);
}
