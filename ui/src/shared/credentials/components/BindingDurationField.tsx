/**
 * BindingDurationField — how long a new credential binding lasts: a whole
 * number and a unit (seconds · minutes · hours · days), or Never expires. Controlled;
 * the caller keeps the {@link BindingDuration} and works out the actual
 * `expires_at` when it binds ({@link expiresAtFromDuration}), so the time runs
 * from the bind, not from when this field rendered.
 *
 * Under the row it says roughly when access would end if the binding were made
 * now, or what is wrong with the amount. "Never expires" hides the number: the
 * binding is made without an expiry.
 */
import { useId } from 'react';
import { Input, Select } from '@/shared/ui';
import {
	BINDING_DURATION_UNITS,
	MAX_BINDING_DURATION_AMOUNT,
	bindingDurationError,
	expiresAtFromDuration,
	type BindingDuration,
	type BindingDurationUnit,
} from '@/shared/credentials/lib/bindingDuration';

export interface BindingDurationFieldProps {
	value: BindingDuration;
	onChange: (value: BindingDuration) => void;
	disabled?: boolean;
	/** Prefix for the field's test ids (`<prefix>-duration-*`). */
	testIdPrefix?: string;
}

const EXPIRY_FORMAT = new Intl.DateTimeFormat(undefined, {
	dateStyle: 'medium',
	timeStyle: 'short',
});

export function BindingDurationField({
	value,
	onChange,
	disabled = false,
	testIdPrefix = 'binding',
}: BindingDurationFieldProps) {
	const headingId = useId();
	const hintId = useId();
	const error = bindingDurationError(value);
	const expiresAt = error ? null : expiresAtFromDuration(value);
	const never = value.unit === 'never';

	return (
		<div
			role="group"
			aria-labelledby={headingId}
			className="space-y-1.5"
			data-testid={`${testIdPrefix}-duration`}
		>
			<p id={headingId} className="text-foreground text-sm font-medium">
				Access expires after
			</p>
			<div className="flex items-start gap-2">
				{!never && (
					<div className="w-24 shrink-0">
						<Input
							type="number"
							inputMode="numeric"
							min={1}
							max={MAX_BINDING_DURATION_AMOUNT}
							step={1}
							size="sm"
							aria-label="Duration"
							aria-invalid={error ? true : undefined}
							aria-describedby={hintId}
							value={value.amount}
							disabled={disabled}
							data-testid={`${testIdPrefix}-duration-amount`}
							onChange={(e): void => onChange({ ...value, amount: e.target.value })}
						/>
					</div>
				)}
				<div className="w-36 shrink-0">
					<Select
						aria-label="Unit"
						aria-describedby={hintId}
						value={value.unit}
						disabled={disabled}
						className="py-1.5"
						data-testid={`${testIdPrefix}-duration-unit`}
						onChange={(e): void =>
							onChange({ ...value, unit: e.target.value as BindingDurationUnit })
						}
					>
						{BINDING_DURATION_UNITS.map((u) => (
							<option key={u.value} value={u.value}>
								{u.label}
							</option>
						))}
					</Select>
				</div>
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
					{expiresAt === 'never'
						? 'Access does not expire. It lasts until the binding is suspended or removed.'
						: expiresAt
							? `If added now, access ends around ${EXPIRY_FORMAT.format(expiresAt)}. After that, calls are refused until the binding is renewed.`
							: null}
				</p>
			)}
		</div>
	);
}
