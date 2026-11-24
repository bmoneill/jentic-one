/**
 * AccessEndFields — the bottom rows of every grant's policy controls, below
 * the limits: "Warn me before this access ends" (off to start) and "After
 * access ends" (hold the first denied request, or let the agent ask).
 *
 * The warning box is usable once the access has a deadline worth warning
 * about (an end date at least 4 days away, or an idle limit of 4 days or
 * more); otherwise it is disabled and says why. Controlled.
 */
import { useId } from 'react';
import { Checkbox, Select } from '@/shared/ui';
import { AFTER_EXPIRY_OPTIONS, type AfterExpiry } from '@/shared/credentials/lib/accessEnd';

export interface AccessEndFieldsProps {
	/** Whether the warning box is ticked. */
	warn: boolean;
	onWarnChange: (warn: boolean) => void;
	/** Whether the access, if saved now, has a deadline to warn about. */
	warnable: boolean;
	afterExpiry: AfterExpiry;
	onAfterExpiryChange: (value: AfterExpiry) => void;
	disabled?: boolean;
	/** Prefix for test ids (`<prefix>-idle-warning`, `<prefix>-after-expiry`). */
	testIdPrefix?: string;
}

export function AccessEndFields({
	warn,
	onWarnChange,
	warnable,
	afterExpiry,
	onAfterExpiryChange,
	disabled = false,
	testIdPrefix = 'binding',
}: AccessEndFieldsProps) {
	const selectId = useId();
	const hintId = useId();
	const option = AFTER_EXPIRY_OPTIONS.find((o) => o.value === afterExpiry);
	return (
		<div className="space-y-2" data-testid={`${testIdPrefix}-access-end`}>
			<div className="space-y-0.5">
				<div data-testid={`${testIdPrefix}-idle-warning`}>
					<Checkbox
						size="sm"
						checked={warnable && warn}
						disabled={disabled || !warnable}
						onChange={(on): void => onWarnChange(on)}
					>
						<span className="text-foreground text-sm">
							Warn me before this access ends
						</span>
					</Checkbox>
				</div>
				<p
					className="text-muted-foreground pl-6 text-xs"
					data-testid={`${testIdPrefix}-idle-warning-hint`}
				>
					{warnable
						? 'Up to 48 hours before the end date or idle limit, in "Waiting for you" and the event stream.'
						: 'Warnings need an end date at least 4 days away or an idle limit of 4 days or more.'}
				</p>
			</div>
			<div className="space-y-1">
				<label htmlFor={selectId} className="text-foreground block text-sm">
					After access ends
				</label>
				<div className="w-60 max-w-full">
					<Select
						id={selectId}
						aria-describedby={hintId}
						value={afterExpiry}
						disabled={disabled}
						className="py-1.5"
						data-testid={`${testIdPrefix}-after-expiry`}
						onChange={(e): void => onAfterExpiryChange(e.target.value as AfterExpiry)}
					>
						{AFTER_EXPIRY_OPTIONS.map((o) => (
							<option key={o.value} value={o.value}>
								{o.label}
							</option>
						))}
					</Select>
				</div>
				<p
					id={hintId}
					className="text-muted-foreground text-xs"
					data-testid={`${testIdPrefix}-after-expiry-hint`}
				>
					{option?.hint}
				</p>
			</div>
		</div>
	);
}
