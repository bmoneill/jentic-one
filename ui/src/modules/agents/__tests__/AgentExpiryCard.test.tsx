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

	function capturePatch(): { body: { expires_at?: string | null } | null } {
		const seen: { body: { expires_at?: string | null } | null } = { body: null };
		worker.use(
			http.patch('*/agents/agnt_exp_1', async ({ request }) => {
				seen.body = (await request.json()) as { expires_at?: string | null };
				return HttpResponse.json({
					id: 'agnt_exp_1',
					name: 'expiring-agent',
					registered_by: 'self',
					status: 'active',
					created_at: '2026-10-01T10:00:00Z',
					expires_at: seen.body.expires_at ?? null,
				});
			}),
		);
		return seen;
	}

	it('has no default: nothing is chosen and Save is disabled until the operator picks', () => {
		renderWithProviders(<AgentExpiryCard agent={agent()} canManage />);
		expect(screen.getByTestId('agent-expiry-duration-preset')).toHaveValue('');
		expect(screen.getByTestId('agent-expiry-save')).toBeDisabled();
	});

	it('PATCHes an expires_at a preset away when saved', async () => {
		const seen = capturePatch();
		renderWithProviders(<AgentExpiryCard agent={agent()} canManage />);
		await userEvent.selectOptions(screen.getByTestId('agent-expiry-duration-preset'), '1d');
		expect(screen.getByTestId('agent-expiry-duration-hint')).toHaveTextContent(
			/the agent stops working around/,
		);
		await userEvent.click(screen.getByTestId('agent-expiry-save'));
		await waitFor(() => expect(seen.body).not.toBeNull());
		const hours =
			(new Date(seen.body!.expires_at as string).getTime() - Date.now()) / 3_600_000;
		expect(hours).toBeGreaterThan(23.9);
		expect(hours).toBeLessThanOrEqual(24);
	});

	it('keeps No expiry behind Custom…, and clearing PATCHes null', async () => {
		const seen = capturePatch();
		renderWithProviders(
			<AgentExpiryCard agent={agent({ expiresAt: '2099-01-01T00:00:00Z' })} canManage />,
		);
		const preset = screen.getByTestId('agent-expiry-duration-preset');
		expect(
			Array.from((preset as HTMLSelectElement).options).map((o) => o.textContent),
		).not.toContain('No expiry');
		await userEvent.selectOptions(preset, 'custom');
		await userEvent.selectOptions(screen.getByTestId('agent-expiry-duration-unit'), 'never');
		expect(screen.getByTestId('agent-expiry-save')).toHaveTextContent('Clear expiry');
		await userEvent.click(screen.getByTestId('agent-expiry-save'));
		await waitFor(() => expect(seen.body).not.toBeNull());
		expect(seen.body!.expires_at).toBeNull();
	});
});
