/**
 * BindingDurationField — how long access lasts (credential grant expiry, D8):
 * a dropdown of preset durations (1 hour to 90 days) plus "Custom…", which
 * opens a whole-number-and-unit picker that also holds "No expiry". Controlled;
 * the caller keeps the {@link BindingDuration} (or `null` while nothing is
 * chosen — there is no default) and works out the actual `expires_at` when it
 * saves ({@link expiresAtFromDuration}), so the time runs from the save, not
 * from when this field rendered.
 *
 * Under the control it says roughly when access would end if saved now (in
 * the caller's words, via `describe`), or what is wrong with a custom amount.
 */
import { useId } from 'react';
import { Input, Select } from '@/shared/ui';
import {
	BINDING_DURATION_PRESETS,
	CUSTOM_DURATION_UNITS,
	INITIAL_CUSTOM_DURATION,
	MAX_BINDING_DURATION_AMOUNT,
	bindingDurationError,
	expiresAtFromDuration,
	type BindingDuration,
	type BindingDurationPreset,
	type CustomDurationUnit,
} from '@/shared/credentials/lib/bindingDuration';

export interface BindingDurationFieldProps {
	/** The choice; `null` while nothing is chosen. */
	value: BindingDuration | null;
	onChange: (value: BindingDuration) => void;
	disabled?: boolean;
	/** The control's visible label. */
	label?: string;
	/** The line under the control for a valid choice: when access would end if saved now. */
	describe?: (end: Date | 'never') => string;
	/** Prefix for the field's test ids (`<prefix>-duration-*`). */
	testIdPrefix?: string;
}

const EXPIRY_FORMAT = new Intl.DateTimeFormat(undefined, {
	dateStyle: 'medium',
	timeStyle: 'short',
});

/** Formats an end date the way this field does, for callers' `describe`. */
export function formatDurationEnd(end: Date): string {
	return EXPIRY_FORMAT.format(end);
}

function defaultDescribe(end: Date | 'never'): string {
	return end === 'never'
		? 'No expiry: access lasts until someone removes it.'
		: `If saved now, access ends around ${formatDurationEnd(end)}.`;
}

const CUSTOM = 'custom';
const NONE = '';

export function BindingDurationField({
	value,
	onChange,
	disabled = false,
	label = 'Expires after',
	describe = defaultDescribe,
	testIdPrefix = 'binding',
}: BindingDurationFieldProps) {
	const labelId = useId();
	const hintId = useId();
	const error = bindingDurationError(value);
	const end = error ? null : expiresAtFromDuration(value);
	const custom = value?.kind === 'custom' ? value : null;
	const selected = value === null ? NONE : value.kind === 'preset' ? value.preset : CUSTOM;

	const onSelect = (next: string): void => {
		if (next === CUSTOM) {
			if (!custom) onChange(INITIAL_CUSTOM_DURATION);
			return;
		}
		if (next !== NONE) onChange({ kind: 'preset', preset: next as BindingDurationPreset });
	};

	return (
		<div
			role="group"
			aria-labelledby={labelId}
			className="space-y-1.5"
			data-testid={`${testIdPrefix}-duration`}
		>
			<p id={labelId} className="text-foreground text-sm font-medium">
				{label}
			</p>
			<div className="flex flex-wrap items-start gap-2">
				<div className="w-40 shrink-0">
					<Select
						aria-label="Duration"
						aria-describedby={hintId}
						value={selected}
						disabled={disabled}
						className="py-1.5"
						data-testid={`${testIdPrefix}-duration-preset`}
						onChange={(e): void => onSelect(e.target.value)}
					>
						{value === null && (
							<option value={NONE} disabled>
								Choose…
							</option>
						)}
						{BINDING_DURATION_PRESETS.map((p) => (
							<option key={p.value} value={p.value}>
								{p.label}
							</option>
						))}
						<option value={CUSTOM}>Custom…</option>
					</Select>
				</div>
				{custom && (
					<>
						{custom.unit !== 'never' && (
							<div className="w-24 shrink-0">
								<Input
									type="number"
									inputMode="numeric"
									min={1}
									max={MAX_BINDING_DURATION_AMOUNT}
									step={1}
									size="sm"
									aria-label="Amount"
									aria-invalid={error ? true : undefined}
									aria-describedby={hintId}
									value={custom.amount}
									disabled={disabled}
									data-testid={`${testIdPrefix}-duration-amount`}
									onChange={(e): void =>
										onChange({ ...custom, amount: e.target.value })
									}
								/>
							</div>
						)}
						<div className="w-36 shrink-0">
							<Select
								aria-label="Unit"
								aria-describedby={hintId}
								value={custom.unit}
								disabled={disabled}
								className="py-1.5"
								data-testid={`${testIdPrefix}-duration-unit`}
								onChange={(e): void =>
									onChange({
										...custom,
										unit: e.target.value as CustomDurationUnit,
									})
								}
							>
								{CUSTOM_DURATION_UNITS.map((u) => (
									<option key={u.value} value={u.value}>
										{u.label}
									</option>
								))}
							</Select>
						</div>
					</>
				)}
			</div>
			{error ? (
				<p
					id={hintId}
					role="alert"
					className="text-danger text-xs"
					data-testid={`${testIdPrefix}-duration-error`}
				>
					{error}
				</p>
			) : (
				<p
					id={hintId}
					className="text-muted-foreground text-xs"
					data-testid={`${testIdPrefix}-duration-hint`}
				>
					{end ? describe(end) : null}
				</p>
			)}
		</div>
	);
}
