/**
 * The inline verb an attention item can be cleared with — approve a waiting
 * agent. Shared (not per-module) because two surfaces offer it: the top-bar
 * Notifications menu (shell) and the Home inbox.
 *
 * It invalidates every surface that counts the item, so the badge, the inbox
 * and the Activity rail drop the row together.
 */
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { AgentsService, sharedQueryKeys, type AgentResponse } from '@/shared/api';

/** An agent id, or the id with when the approved agent stops working (ISO 8601). */
export type ApproveAgentVariables = string | { agentId: string; expiresAt?: string };

export function useApproveAgent() {
	const queryClient = useQueryClient();
	return useMutation<AgentResponse, Error, ApproveAgentVariables>({
		mutationFn: (variables) =>
			typeof variables === 'string'
				? AgentsService.approveAgent({ agentId: variables })
				: AgentsService.approveAgent({
						agentId: variables.agentId,
						requestBody: variables.expiresAt
							? { expires_at: variables.expiresAt }
							: undefined,
					}),
		onSuccess: () => {
			void queryClient.invalidateQueries({ queryKey: sharedQueryKeys.agentsRoot });
			void queryClient.invalidateQueries({ queryKey: sharedQueryKeys.attentionRoot });
		},
	});
}
