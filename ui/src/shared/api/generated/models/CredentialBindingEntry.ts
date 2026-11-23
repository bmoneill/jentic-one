/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { GrantEndReason } from './GrantEndReason';
import type { ServedApiRef } from './ServedApiRef';
/**
 * Direct agent↔credential binding summary for the /me response (theme 5 phase 1).
 */
export type CredentialBindingEntry = {
    /**
     * When the credential was bound (RFC 3339).
     */
    bound_at: string;
    /**
     * ID of the bound credential.
     */
    credential_id: string;
    /**
     * Whether `expires_at` has passed; the agent cannot execute through an expired binding until its operator renews it.
     */
    expired?: boolean;
    /**
     * Which limit ended the binding while `expired` is true: `end_date` (`expires_at` passed) or `idle` (unused for its idle limit). Null while the binding holds.
     */
    expired_reason?: (GrantEndReason | null);
    /**
     * When the binding stops authorizing calls (RFC 3339); null if it never expires.
     */
    expires_at?: (string | null);
    /**
     * When the idle limit ends the binding if it is not used before then (RFC 3339); null without an idle limit. Each call moves it later.
     */
    idle_expires_at?: (string | null);
    /**
     * When this agent last made a call through the binding; null if never.
     */
    last_used_at?: (string | null);
    /**
     * Idle limit in seconds: the binding ends once it goes this long without a call; null when it has none.
     */
    max_idle_period?: (number | null);
    /**
     * Name of the bound credential; null if it no longer exists or cannot be resolved.
     */
    name?: (string | null);
    /**
     * ID of the shared permission rule set attached; null when inline rules apply.
     */
    rule_set_id?: (string | null);
    /**
     * The APIs the bound credential serves; empty if unresolvable.
     */
    serves?: Array<ServedApiRef>;
    /**
     * Lifecycle state of the bound credential (`pending`, `connected` or `failed`); null if the credential cannot be resolved.
     */
    state?: (string | null);
    /**
     * Whether the binding is suspended; the agent cannot execute through it until resumed.
     */
    suspended?: boolean;
    /**
     * Why the binding is suspended: null for a manual suspension, `api_deleted` when the API the credential serves was deleted.
     */
    suspended_reason?: (string | null);
};

