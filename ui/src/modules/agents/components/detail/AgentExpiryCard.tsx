/**
 * AgentExpiryCard — when an agent stops working. An agent past its expiry gets
 * no new token and the tokens it holds stop working; it keeps its grants and
 * can be restored by setting a later time or clearing the expiry. Uses the
 * shared duration field: the expiry runs from the moment the operator saves.
 */
import { useState } from 'react';
import { Button, Card } from '@/shared/ui';
import { BindingDurationField } from '@/shared/credentials/components';
import {
	DEFAULT_BINDING_DURATION,
	bindingDurationError,
	expiresAtFromDuration,
	type BindingDuration,
} from '@/shared/credentials/lib/bindingDuration';
import { useUpdateAgent, type AgentEntity } from '@/modules/agents/api';

const WHEN = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

export function AgentExpiryCard({ agent, canManage }: { agent: AgentEntity; canManage: boolean }) {
	const update = useUpdateAgent();
	const [duration, setDuration] = useState<BindingDuration>(DEFAULT_BINDING_DURATION);

	const status = agent.expiresAt
		? agent.expired
			? `Expired ${WHEN.format(new Date(agent.expiresAt))}. This agent can no longer get tokens.`
			: `Stops working ${WHEN.format(new Date(agent.expiresAt))}.`
		: 'Never expires.';
	const error = bindingDurationError(duration);

	const save = async () => {
		const at = expiresAtFromDuration(duration);
		if (at === null) return;
		await update.mutateAsync({
			id: agent.id,
			patch: { expiresAt: at === 'never' ? null : at.toISOString() },
		});
	};

	return (
		<Card className="space-y-3 p-4" data-testid="agent-expiry-card">
			<div>
				<h3 className="text-foreground text-sm font-semibold">Expiry</h3>
				<p
					className={
						agent.expired ? 'text-destructive text-sm' : 'text-muted-foreground text-sm'
					}
					data-testid="agent-expiry-status"
				>
					{status}
				</p>
			</div>
			{canManage && (
				<>
					<BindingDurationField
						value={duration}
						onChange={setDuration}
						disabled={update.isPending}
						testIdPrefix="agent-expiry"
					/>
					<Button
						size="sm"
						onClick={() => void save()}
						disabled={update.isPending || error !== null}
						data-testid="agent-expiry-save"
					>
						{duration.unit === 'never' ? 'Clear expiry' : 'Set expiry'}
					</Button>
				</>
			)}
		</Card>
	);
}
