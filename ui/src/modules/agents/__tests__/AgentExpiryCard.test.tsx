import { describe, it, expect } from 'vitest';
import { http, HttpResponse } from 'msw';
import { worker } from '@/mocks/browser';
import { renderWithProviders, screen, waitFor, userEvent } from '@/__tests__/test-utils';
import type { AgentEntity } from '@/modules/agents/api';
import { AgentExpiryCard } from '@/modules/agents/components/detail/AgentExpiryCard';

function agent(over: Partial<AgentEntity> = {}): AgentEntity {
	return {
		id: 'agnt_exp_1',
		name: 'expiring-agent',
		description: null,
		status: 'active',
		ownerId: null,
		parentAgentId: null,
		denialReason: null,
		createdAt: '2026-10-01T10:00:00Z',
		approvedAt: null,
		expiresAt: null,
		expired: false,
		attribution: { registeredBy: null, approvedBy: null, deniedBy: null },
		hasApiKey: false,
		...over,
	};
}

describe('AgentExpiryCard', () => {
	it('says an agent without an expiry never expires', () => {
		renderWithProviders(<AgentExpiryCard agent={agent()} canManage />);
		expect(screen.getByTestId('agent-expiry-status')).toHaveTextContent('Never expires.');
	});

	it('flags an expired agent', () => {
		renderWithProviders(
			<AgentExpiryCard
				agent={agent({ expiresAt: '2026-10-02T10:00:00Z', expired: true })}
				canManage
			/>,
		);
		expect(screen.getByTestId('agent-expiry-status')).toHaveTextContent(/Expired/);
	});

	it('hides the controls without permission to manage agents', () => {
		renderWithProviders(<AgentExpiryCard agent={agent()} canManage={false} />);
		expect(screen.queryByTestId('agent-expiry-save')).toBeNull();
	});

	it('PATCHes a future expires_at when saved', async () => {
		let body: { expires_at?: string | null } | null = null;
		worker.use(
			http.patch('*/agents/agnt_exp_1', async ({ request }) => {
				body = (await request.json()) as { expires_at?: string | null };
				return HttpResponse.json({
					id: 'agnt_exp_1',
					name: 'expiring-agent',
					registered_by: 'self',
					status: 'active',
					created_at: '2026-10-01T10:00:00Z',
					expires_at: body.expires_at ?? null,
				});
			}),
		);
		renderWithProviders(<AgentExpiryCard agent={agent()} canManage />);
		await userEvent.click(screen.getByTestId('agent-expiry-save'));
		await waitFor(() => expect(body).not.toBeNull());
		expect(new Date(body!.expires_at as string).getTime()).toBeGreaterThan(Date.now());
	});
});
