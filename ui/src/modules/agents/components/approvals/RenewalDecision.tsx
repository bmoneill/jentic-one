/**
 * RenewalDecision — the decision on a held call whose agent's access ended
 * (`kind: grant_renewal`). A reviewer who may renew the binding directly
 * chooses its fresh policy with the same controls as granting access (an end
 * date, nothing preselected; an idle limit; single use; the warning before
 * it ends and what happens after it, starting on the binding's own), then either
 * re-grants access and runs the call, re-grants it without running a stale call, or
 * denies. Re-granting replaces the binding's old policy; its rules stay.
 *
 * Anyone else who may review sees only Deny, with who can re-grant access.
 * Where the deployment can't tell who may renew from here (`renewElsewhere`),
 * everyone sees the choices, and the renewal itself says if they may not.
 */
import { useRef, useState } from 'react';
import {
	AccessEndFields,
	BindingDurationField,
	IdleLimitField,
	NoExpiryConfirmDialog,
	SingleUseField,
	useNoExpiryConfirm,
} from '@/shared/credentials/components';
import { useGrantPolicyLimits } from '@/shared/credentials/api';
import { usePreselectGrantDefaults } from '@/shared/credentials/lib/grantDefaults';
import {
	expiresAtFromDuration,
	expiresAtIso,
	type BindingDuration,
} from '@/shared/credentials/lib/bindingDuration';
import {
	choosesNoExpiry,
	durationChosen,
	NO_DURATION_HINT,
} from '@/shared/credentials/lib/bindingExpiry';
import { idleLimitError, idleSeconds, type IdleLimit } from '@/shared/credentials/lib/idleLimit';
import {
	afterExpiryFrom,
	expiryWarnable,
	expiryWarning,
	type AfterExpiry,
} from '@/shared/credentials/lib/accessEnd';
import { Button, Label, Textarea, UserText } from '@/shared/ui';

/** The fresh policy a renewal sends, as `:decide` takes it. */
export interface RenewalPolicyBody {
	expires_at: string | null;
	max_idle_period: number | null;
	idle_warning: boolean;
	max_quota: number | null;
	after_expiry: AfterExpiry;
}

export interface RenewalDecisionProps {
	agentName: string;
	/** Whether the viewer may re-grant access (the server's `renewal.can_renew`). */
	canRenew: boolean;
	/**
	 * The renewal goes through the binding's own renew endpoint before the
	 * approval (`renewal.renew_on_decide` is false), so who may renew is only
	 * known once it is tried.
	 */
	renewElsewhere?: boolean;
	/** What a call through the binding gets once it ends now (`hold` or `refuse`). */
	afterExpiry?: string | null;
	pending: boolean;
	onDeny: (reason: string) => void;
	onRenew: (policy: RenewalPolicyBody, run: boolean, reason: string) => void;
}

export function RenewalDecision({
	agentName,
	canRenew: viewerMayRenew,
	renewElsewhere = false,
	afterExpiry: afterExpiryNow = null,
	pending,
	onDeny,
	onRenew,
}: RenewalDecisionProps) {
	const canRenew = viewerMayRenew || renewElsewhere;
	const [reason, setReason] = useState('');
	const [duration, setDuration] = useState<BindingDuration | null>(null);
	const [idle, setIdle] = useState<IdleLimit | null>(null);
	const [uses, setUses] = useState<number | null>(null);
	const [warn, setWarn] = useState(false);
	const [after, setAfter] = useState<AfterExpiry>(() => afterExpiryFrom(afterExpiryNow));
	// The org's defaults preselect the re-granted access (D14); its maximums bound it.
	const limits = useGrantPolicyLimits();
	usePreselectGrantDefaults(limits, (d) => {
		setDuration((cur) => cur ?? d.duration);
		setIdle((cur) => cur ?? d.idle);
		setUses((cur) => cur ?? d.uses);
	});
	const durationRef = useRef<HTMLSelectElement>(null);
	const noExpiry = useNoExpiryConfirm();

	const incomplete =
		!durationChosen(duration, limits.expires.maxSeconds) ||
		idleLimitError(idle, limits.idle.maxSeconds) !== null;
	const renew = (run: boolean): void =>
		noExpiry.request(
			// An idle limit or a use count still ends the access; only none warns.
			choosesNoExpiry(duration) && idleSeconds(idle) === null && uses === null,
			() =>
				onRenew(
					{
						// Worked out now, as the reviewer decides: the duration runs from here.
						expires_at: expiresAtIso(duration) ?? null,
						max_idle_period: idleSeconds(idle),
						idle_warning: expiryWarning(
							warn,
							expiresAtFromDuration(duration),
							idleSeconds(idle),
						),
						max_quota: uses,
						after_expiry: after,
					},
					run,
					reason,
				),
		);

	return (
		<div className="flex flex-col gap-4" data-testid="renewal-decision">
			{canRenew ? (
				<div className="space-y-3">
					{renewElsewhere && (
						<p
							className="text-muted-foreground text-sm"
							data-testid="renewal-elsewhere"
						>
							Re-granting access renews the agent&apos;s access first. Only someone
							who owns both the agent and the credential, or an org admin, can.
						</p>
					)}
					<BindingDurationField
						maxSeconds={limits.expires.maxSeconds}
						value={duration}
						onChange={setDuration}
						disabled={pending}
						label="Re-grant access for"
						emptyHint={NO_DURATION_HINT}
						selectRef={durationRef}
						testIdPrefix="renewal"
					/>
					<IdleLimitField
						maxSeconds={limits.idle.maxSeconds}
						value={idle}
						onChange={setIdle}
						end={expiresAtFromDuration(duration)}
						disabled={pending}
						testIdPrefix="renewal"
					/>
					<SingleUseField
						value={uses}
						onChange={setUses}
						end={expiresAtFromDuration(duration)}
						idleSeconds={idleSeconds(idle)}
						disabled={pending}
						testIdPrefix="renewal"
					/>
					<AccessEndFields
						warn={warn}
						onWarnChange={setWarn}
						warnable={expiryWarnable(
							expiresAtFromDuration(duration),
							idleSeconds(idle),
						)}
						afterExpiry={after}
						onAfterExpiryChange={setAfter}
						disabled={pending}
						testIdPrefix="renewal"
					/>
				</div>
			) : (
				<p className="text-muted-foreground text-sm" data-testid="renewal-cannot-renew">
					Only someone who owns both the agent and the credential, or an org admin, can
					re-grant access. You can deny the call.
				</p>
			)}
			<div>
				<Label htmlFor="renewal-reason">Reason (optional)</Label>
				<Textarea
					id="renewal-reason"
					placeholder="Recorded with your decision…"
					value={reason}
					onChange={(e) => setReason(e.target.value)}
					rows={2}
					maxLength={500}
					className="mt-1"
				/>
			</div>
			<div className="flex flex-wrap gap-3">
				<Button
					type="button"
					variant="danger"
					onClick={() => onDeny(reason)}
					disabled={pending}
					data-testid="renewal-deny"
				>
					Deny
				</Button>
				{canRenew && (
					<>
						<Button
							type="button"
							variant="secondary"
							onClick={() => renew(false)}
							disabled={pending || incomplete}
							data-testid="renewal-grant"
						>
							Re-grant access
						</Button>
						<Button
							type="button"
							variant="primary"
							onClick={() => renew(true)}
							disabled={pending || incomplete}
							data-testid="renewal-grant-and-run"
						>
							Re-grant access and run this call
						</Button>
					</>
				)}
			</div>
			<NoExpiryConfirmDialog
				{...noExpiry.dialogProps}
				kind="renew"
				subject={<UserText>{agentName}</UserText>}
				fieldRef={durationRef}
			/>
		</div>
	);
}
