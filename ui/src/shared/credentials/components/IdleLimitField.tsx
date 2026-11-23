/**
 * IdleLimitField — the optional second row of the duration control: "Also end
 * if unused for", off by default. Ticking it turns on an idle limit (14 days
 * to start), chosen from idle-sized presets or "Custom…" in hours or days,
 * between 1 day and 999 days. Controlled: `null` is off.
 *
 * Under it, one line says how the end date and the idle limit combine if
 * saved now (`end` is the end date the sibling control would set), so the
 * operator sees which limit applies first.
 *
 * With the row on, "Warn me before it ends" (off to start) asks for a warning
 * up to 48 hours before the limit is reached. It is the value's `warn` flag,
 * so turning the row off drops it too. A limit under 4 days can't be warned
 * about, so the box is disabled there and the value sent is false.
 */
import { useId } from 'react';
import { Checkbox, Input, Select } from '@/shared/ui';
import {
	DEFAULT_IDLE_LIMIT,
	IDLE_PRESETS,
	IDLE_UNITS,
	describePolicy,
	idleLimitError,
	idleSeconds,
	idleWarnable,
	type IdleLimit,
	type IdlePreset,
	type IdleUnit,
} from '@/shared/credentials/lib/idleLimit';

export interface IdleLimitFieldProps {
	/** The idle limit; `null` while the row is off. */
	value: IdleLimit | null;
	onChange: (value: IdleLimit | null) => void;
	/** When the end date chosen beside it would end access if saved now. */
	end: Date | 'never' | null;
	disabled?: boolean;
	/** Prefix for test ids (`<prefix>-idle-*`). */
	testIdPrefix?: string;
	/**
	 * The org's maximum idle limit, in seconds; null when it sets none. Under
	 * one, longer presets are disabled and the row can't be turned off.
	 */
	maxSeconds?: number | null;
}

const CUSTOM = 'custom';

export function IdleLimitField({
	value,
	onChange,
	end,
	disabled = false,
	testIdPrefix = 'binding',
	maxSeconds = null,
}: IdleLimitFieldProps) {
	const hintId = useId();
	const error = idleLimitError(value, maxSeconds);
	// An org maximum makes an idle limit required: once on, it stays on.
	const required = maxSeconds !== null && value !== null;
	const custom = value?.kind === 'custom' ? value : null;
	const summary = error ? null : describePolicy(end, idleSeconds(value));
	const warnable = idleWarnable(idleSeconds(value));

	return (
		<div className="space-y-1.5" data-testid={`${testIdPrefix}-idle`}>
			<div data-testid={`${testIdPrefix}-idle-toggle`}>
				<Checkbox
					size="sm"
					checked={value !== null}
					disabled={disabled || required}
					onChange={(): void => onChange(value === null ? DEFAULT_IDLE_LIMIT : null)}
				>
					<span className="text-foreground text-sm">Also end if unused for</span>
				</Checkbox>
			</div>
			{value !== null && (
				<div className="flex flex-wrap items-start gap-2 pl-6">
					<div className="w-40 shrink-0">
						<Select
							aria-label="Idle limit"
							aria-describedby={hintId}
							value={value.kind === 'preset' ? value.preset : CUSTOM}
							disabled={disabled}
							className="py-1.5"
							data-testid={`${testIdPrefix}-idle-preset`}
							onChange={(e): void => {
								const next = e.target.value;
								if (next === CUSTOM) {
									if (!custom)
										onChange({
											kind: 'custom',
											amount: '14',
											unit: 'days',
											warn: value.warn,
										});
									return;
								}
								onChange({
									kind: 'preset',
									preset: next as IdlePreset,
									warn: value.warn,
								});
							}}
						>
							{IDLE_PRESETS.map((p) => (
								<option
									key={p.value}
									value={p.value}
									disabled={maxSeconds !== null && p.seconds > maxSeconds}
								>
									{p.label}
								</option>
							))}
							<option value={CUSTOM}>Custom…</option>
						</Select>
					</div>
					{custom && (
						<>
							<div className="w-24 shrink-0">
								<Input
									type="number"
									inputMode="numeric"
									min={1}
									step={1}
									size="sm"
									aria-label="Idle amount"
									aria-invalid={error ? true : undefined}
									aria-describedby={hintId}
									value={custom.amount}
									disabled={disabled}
									data-testid={`${testIdPrefix}-idle-amount`}
									onChange={(e): void =>
										onChange({ ...custom, amount: e.target.value })
									}
								/>
							</div>
							<div className="w-28 shrink-0">
								<Select
									aria-label="Idle unit"
									aria-describedby={hintId}
									value={custom.unit}
									disabled={disabled}
									className="py-1.5"
									data-testid={`${testIdPrefix}-idle-unit`}
									onChange={(e): void =>
										onChange({ ...custom, unit: e.target.value as IdleUnit })
									}
								>
									{IDLE_UNITS.map((u) => (
										<option key={u.value} value={u.value}>
											{u.label}
										</option>
									))}
								</Select>
							</div>
						</>
					)}
				</div>
			)}
			{value !== null &&
				(error ? (
					<p
						id={hintId}
						role="alert"
						className="text-danger pl-6 text-xs"
						data-testid={`${testIdPrefix}-idle-error`}
					>
						{error}
					</p>
				) : (
					<p
						id={hintId}
						className="text-muted-foreground pl-6 text-xs"
						data-testid={`${testIdPrefix}-idle-summary`}
					>
						{summary}
					</p>
				))}
			{value !== null && (
				<div className="space-y-0.5 pl-6">
					<div data-testid={`${testIdPrefix}-idle-warning`}>
						<Checkbox
							size="sm"
							checked={warnable && value.warn === true}
							disabled={disabled || !warnable}
							onChange={(on): void => onChange({ ...value, warn: on })}
						>
							<span className="text-foreground text-sm">Warn me before it ends</span>
						</Checkbox>
					</div>
					<p
						className="text-muted-foreground pl-6 text-xs"
						data-testid={`${testIdPrefix}-idle-warning-hint`}
					>
						{warnable
							? 'Up to 48 hours ahead, in "Waiting for you" and the event stream.'
							: 'Too short to warn: warnings need an idle limit of 4 days or more.'}
					</p>
				</div>
			)}
		</div>
	);
}
