/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Fresh access for an ended binding.
 *
 * Every field left out sets no such limit, except the end date: left out, the
 * binding runs again for as long as it was granted for, capped at the org's
 * maximum (``null`` sets no end date).
 */
export type GrantRenewalRequest = {
    /**
     * New end date (RFC 3339, in the future); null for no end date. Left out, the binding runs again for as long as it was granted for, capped at the org's maximum.
     */
    expires_at?: (string | null);
    /**
     * Warn the agent's owner before the idle limit is reached.
     */
    idle_warning?: boolean;
    /**
     * New idle limit in seconds (1 day to 999 days); null for none.
     */
    max_idle_period?: (number | null);
    /**
     * New use count (1 is single use); null for unlimited calls.
     */
    max_quota?: (number | null);
};

