/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for renewing a credential binding: re-certify it, and change its limits.
 *
 * Every renewal restarts the binding's idle clock. Each limit sent is set, and
 * null clears it; a limit left out stays as it is, so an absent field is never
 * read as clearing. An empty body only re-certifies ("still needed").
 */
export type CredentialBindingPatchRequest = {
    /**
     * When the binding stops authorizing calls (RFC 3339, in the future). After this moment the broker refuses the agent's calls through it with 403 `credential_binding_expired`, whatever its token. The binding keeps its permission rules; an owner renews it by setting a later time or null. Send null to clear the end date; leave it out to keep it.
     */
    expires_at?: (string | null);
    /**
     * Warn the agent's owner before the idle limit is reached: once a day a job raises a `credential_grant.idle_expiring` event when the binding will go idle within 48 hours (for idle limits of 4 days or more), once per idle period. Off unless set. Leave it out to keep it as it is.
     */
    idle_warning?: (boolean | null);
    /**
     * Idle limit, in whole seconds (at least 1 day, at most 999 days): the binding ends once it has gone this long without a call, and the broker then refuses calls through it with 403 `credential_binding_expired`. Each call restarts the clock (counted at most about hourly), and so does every renewal; a binding that is never used ends one idle period after it was granted. Send null to remove the idle limit; leave it out to keep it.
     */
    max_idle_period?: (number | null);
    /**
     * How many calls the binding allows before it ends (1 is single use); each authorized call takes one, whatever the upstream answers, and renewing restores the count. Send null to remove the count; leave it out to keep it (every renewal restores the uses left).
     */
    max_quota?: (number | null);
};

