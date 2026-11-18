/**
 * AgentExpiryCard — when an agent stops working. An agent past its expiry gets
 * no new token and the tokens it holds stop working; it keeps its grants and
 * can be restored by setting a later time or clearing the expiry. Uses the
 * shared duration field: nothing is chosen until the operator picks, and the
 * expiry runs from the moment they save.
 */
import { useState } from 'react';
import { Button, Card } from '@/shared/ui';
import { BindingDurationField } from '@/shared/credentials/components';
import {
	expiresAtFromDuration,
	type BindingDuration,
} from '@/shared/credentials/lib/bindingDuration';
import { useUpdateAgent, type AgentEntity } from '@/modules/agents/api';
import { describeAgentExpiry } from '@/modules/agents/lib/agentExpiry';

const WHEN = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

export function AgentExpiryCard({ agent, canManage }: { agent: AgentEntity; canManage: boolean }) {
	const update = useUpdateAgent();
	const [duration, setDuration] = useState<BindingDuration | null>(null);

	const status = agent.expiresAt
		? agent.expired
			? `Expired ${WHEN.format(new Date(agent.expiresAt))}. This agent can no longer get tokens.`
			: `Stops working ${WHEN.format(new Date(agent.expiresAt))}.`
		: 'Never expires.';
	const clearing = duration?.kind === 'custom' && duration.unit === 'never';

	const save = async () => {
		const at = expiresAtFromDuration(duration);
		if (at === null) return;
		try {
			await update.mutateAsync({
				id: agent.id,
				patch: { expiresAt: at === 'never' ? null : at.toISOString() },
			});
			setDuration(null);
		} catch {
			// useUpdateAgent already reports the failure.
		}
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
						label="Stops working after"
						describe={describeAgentExpiry}
						testIdPrefix="agent-expiry"
					/>
					<Button
						size="sm"
						onClick={() => void save()}
						disabled={update.isPending || expiresAtFromDuration(duration) === null}
						data-testid="agent-expiry-save"
					>
						{clearing ? 'Clear expiry' : 'Set expiry'}
					</Button>
				</>
			)}
		</Card>
	);
}
