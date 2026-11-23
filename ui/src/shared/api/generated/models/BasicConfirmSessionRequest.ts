/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PermissionRuleSchema } from './PermissionRuleSchema';
/**
 * Confirm a ``manual_basic`` session with the username and password to store.
 */
export type BasicConfirmSessionRequest = {
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
     * When the new binding stops authorizing calls (RFC 3339, in the future), as the approver chose it; worked out when the approver confirms. Null or absent binds with no expiry. Ignored when the agent is already bound to the credential: that binding keeps its own end date.
     */
    expires_at?: (string | null);
    /**
     * Confirm variant; always `basic`.
     */
    kind: string;
    /**
     * The new binding's idle limit, in seconds (1 to 999 days), as the approver chose it: the binding ends once it goes this long without a call. Null or absent sets none. Ignored when the agent is already bound to the credential.
     */
    max_idle_period?: (number | null);
    /**
     * Password to store; write-only.
     */
    password: string;
    /**
     * Permission rules to bind for the agent (at most 100).
     */
    permission_rules: Array<PermissionRuleSchema>;
    /**
     * The revision the approver reviewed (`revision.id`); required. Missing is 422 revision_required, a newer one 409 revision_changed.
     */
    revision_id?: (string | null);
    /**
     * Username to store.
     */
    username: string;
};

