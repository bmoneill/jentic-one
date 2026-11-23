/**
 * SingleUseField — "End after one use", next to the end date and the idle
 * limit wherever a binding's policy is set. Off by default. The console only
 * offers one use; a binding given a larger count through the API keeps it,
 * and the box then reads "End after 5 uses" (unticking it removes the count).
 *
 * Ticked, one line says how it combines with the other limits if saved now
 * (`end` and `idleSeconds` are what the sibling controls would set): any
 * limit reached ends the access.
 */
import { Checkbox } from '@/shared/ui';
import { describeSingleUse } from '@/shared/credentials/lib/idleLimit';

export interface SingleUseFieldProps {
	/** The use count: `null` off, 1 for single use (a larger count only from the API). */
	value: number | null;
	onChange: (value: number | null) => void;
	/** When the end date chosen beside it would end access if saved now. */
	end: Date | 'never' | null;
	/** The idle limit chosen beside it, in seconds; null without one. */
	idleSeconds: number | null;
	disabled?: boolean;
	/** Prefix for test ids (`<prefix>-single-use`, `<prefix>-single-use-summary`). */
	testIdPrefix?: string;
}

export function SingleUseField({
	value,
	onChange,
	end,
	idleSeconds,
	disabled = false,
	testIdPrefix = 'binding',
}: SingleUseFieldProps) {
	const label = value !== null && value > 1 ? `End after ${value} uses` : 'End after one use';
	return (
		<div className="space-y-1.5">
			<div data-testid={`${testIdPrefix}-single-use`}>
				<Checkbox
					size="sm"
					checked={value !== null}
					disabled={disabled}
					onChange={(on): void => onChange(on ? 1 : null)}
				>
					<span className="text-foreground text-sm">{label}</span>
				</Checkbox>
			</div>
			{value !== null && (
				<p
					className="text-muted-foreground pl-6 text-xs"
					data-testid={`${testIdPrefix}-single-use-summary`}
				>
					{describeSingleUse(value, end, idleSeconds)}
				</p>
			)}
		</div>
	);
}
