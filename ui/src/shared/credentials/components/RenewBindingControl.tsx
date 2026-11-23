/**
 * RenewBindingControl — renew one agent's binding to a credential: choose a
 * new duration (the shared duration control, nothing preselected) and save it
 * through `PATCH /agents/{id}/credentials/{cid}`. The end date runs from the
 * moment of saving. "No expiry" (in Custom…) clears the end date, behind the
 * "No expiry" warning (unless an idle limit still ends it). The idle row
 * below it starts on the binding's current idle limit and is sent when it
 * changes. A binding with an idle limit also offers "Still needed": a renewal
 * that changes nothing but restarts its idle clock. Renewing restores an
 * expired binding; it never resumes a suspended one.
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
import {
	expiresAtFromDuration,
	expiresAtIso,
	type BindingDuration,
} from '@/shared/credentials/lib/bindingDuration';
import {
	idleLimitError,
	idleLimitFromSeconds,
	idleSeconds,
	idleWarning,
	type IdleLimit,
} from '@/shared/credentials/lib/idleLimit';
import { IdleLimitField } from '@/shared/credentials/components/IdleLimitField';
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
	/** The binding's current idle limit in seconds; null without one. */
	maxIdlePeriod?: number | null;
	/** Whether its owner is warned before that idle limit is reached. */
	idleWarning?: boolean;
	/** Which limit ended it (`end_date`, `idle`), when it has ended. */
	expiredReason?: string | null;
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
	maxIdlePeriod = null,
	idleWarning: warnedBefore = false,
	expiredReason = null,
	compact = false,
	onRenewed,
	testIdPrefix = 'renew-binding',
}: RenewBindingControlProps) {
	const renew = useRenewCredentialBinding();
	const confirm = useNoExpiryConfirm();
	const fieldRef = useRef<HTMLSelectElement>(null);
	const [duration, setDuration] = useState<BindingDuration | null>(null);
	const [idle, setIdle] = useState<IdleLimit | null>(() =>
		idleLimitFromSeconds(maxIdlePeriod, warnedBefore),
	);

	const idleNow = idleSeconds(idle);
	const warnNow = idleWarning(idle);
	const limitChanged = idleNow !== (maxIdlePeriod ?? null);
	const warnChanged = warnNow !== warnedBefore;
	// The idle row (the limit or its warning) differs from the binding's.
	const idleChanged = limitChanged || warnChanged;
	const idleInvalid = idleLimitError(idle) !== null;
	const clearing = choosesNoExpiry(duration);
	// Clearing an end date the binding doesn't have changes nothing.
	const nothingToClear = clearing && !expiresAt && !idleChanged;
	const blocked =
		renew.isPending ||
		idleInvalid ||
		(!durationChosen(duration) && !idleChanged) ||
		nothingToClear;
	// With no end date and no idle limit left, the access never ends: warn first.
	const leavesOpenEnded = clearing && idleNow === null;

	const done = (title: string, description: string): void => {
		toast({ title, description, variant: 'success' });
		setDuration(null);
		onRenewed?.();
	};

	const save = (): void => {
		// Worked out now, as the operator confirms: the duration runs from here.
		const at = durationChosen(duration) ? expiresAtIso(duration) : undefined;
		renew.mutate(
			{
				agentId,
				credentialId,
				...(at !== undefined ? { expiresAt: at } : {}),
				...(limitChanged ? { maxIdlePeriod: idleNow } : {}),
				...(warnChanged ? { idleWarning: warnNow } : {}),
			},
			{
				onSuccess: () => {
					if (at === null) {
						done(
							'Expiry removed',
							idleNow === null
								? `${isolateText(agentName)} keeps this access until someone removes it.`
								: `${isolateText(agentName)} keeps this access while it uses it.`,
						);
					} else if (at) {
						done(
							'Access renewed',
							`${isolateText(agentName)} has access until ${formatDurationEnd(new Date(at))}.`,
						);
					} else {
						done(
							'Idle limit saved',
							`${isolateText(agentName)}'s access was re-certified.`,
						);
					}
				},
			},
		);
	};

	// Re-certify without changing anything: restarts the idle clock.
	const stillNeeded = (): void => {
		renew.mutate(
			{ agentId, credentialId },
			{
				onSuccess: () =>
					done(
						'Access re-certified',
						`${isolateText(agentName)}'s idle limit starts again from now.`,
					),
			},
		);
	};
	const endDatePassed = expiredReason === 'end_date' || (expired && expiredReason == null);
	const offerStillNeeded = maxIdlePeriod != null && !endDatePassed;

	const label = expired ? 'Renew for' : expiresAt ? 'Change expiry to' : 'Set an expiry';
	const action =
		!durationChosen(duration) && idleChanged
			? 'Save idle limit'
			: clearing
				? 'Remove expiry'
				: expired
					? 'Renew'
					: expiresAt
						? 'Change expiry'
						: 'Set expiry';

	const submit = (): void => confirm.request(leavesOpenEnded, save);
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
			<IdleLimitField
				value={idle}
				onChange={setIdle}
				end={
					durationChosen(duration)
						? expiresAtFromDuration(duration)
						: expiresAt
							? new Date(expiresAt)
							: 'never'
				}
				disabled={renew.isPending}
				testIdPrefix={testIdPrefix}
			/>
			<div className="flex flex-wrap items-center gap-2">
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
				{offerStillNeeded && (
					<Button
						size="sm"
						variant="ghost"
						disabled={renew.isPending}
						onClick={stillNeeded}
						data-testid={`${testIdPrefix}-still-needed`}
						aria-label={`Still needed: restart the idle limit for ${isolateText(agentName)}`}
					>
						Still needed
					</Button>
				)}
			</div>
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
