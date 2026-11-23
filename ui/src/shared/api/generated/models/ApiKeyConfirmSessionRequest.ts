/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PermissionRuleSchema } from './PermissionRuleSchema';
/**
 * Confirm a ``manual_api_key`` session with the API key to store.
 */
export type ApiKeyConfirmSessionRequest = {
    /**
     * Agent to bind when the session has none; ignored if the session already has one.
     */
    agent_id?: (string | null);
    /**
     * Review digest echoed from the review data; a mismatch is 409 review_stale.
     */
    digest: string;
    /**
     * Agent ID from the review the approver saw; a mismatch is 409 review_stale.
     */
    expected_agent_id?: (string | null);
    /**
     * When the new binding stops authorizing calls (RFC 3339, in the future), as the approver chose it; worked out when the approver confirms. Null binds with no expiry (refused under an org maximum). A body that sets none of `expires_at`, `max_idle_period` and `max_quota` gets the org's default policy. Ignored when the agent is already bound to the credential: that binding keeps its own end date.
     */
    expires_at?: (string | null);
    /**
     * Warn the agent's owner before the new binding's idle limit is reached (a daily `credential_grant.idle_expiring` event, for idle limits of 4 days or more).
     */
    idle_warning?: boolean;
    /**
     * API key to store; write-only.
     */
    key: string;
    /**
     * Confirm variant; always `api_key`.
     */
    kind: string;
    /**
     * The new binding's idle limit, in seconds (1 to 999 days), as the approver chose it: the binding ends once it goes this long without a call. Null or absent sets none. Ignored when the agent is already bound to the credential.
     */
    max_idle_period?: (number | null);
    /**
     * How many calls the new binding allows before it ends (1 is single use). Null or absent sets no count. Ignored when the agent is already bound to the credential.
     */
    max_quota?: (number | null);
    /**
     * Permission rules to bind for the agent (at most 100).
     */
    permission_rules: Array<PermissionRuleSchema>;
    /**
     * The revision the approver reviewed (`revision.id`); required. Missing is 422 revision_required, a newer one 409 revision_changed.
     */
    revision_id?: (string | null);
};

