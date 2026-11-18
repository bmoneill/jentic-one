/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for renewing a credential binding: set, move or clear its expiry.
 *
 * `expires_at` is required but nullable: a body without it is a 422, never read
 * as clearing the expiry.
 */
export type CredentialBindingPatchRequest = {
    /**
     * When the binding stops authorizing calls (RFC 3339, in the future). After this moment the broker refuses the agent's calls through it with 403 `credential_binding_expired`, whatever its token. The binding keeps its permission rules; an owner renews it by setting a later time or null. Required: send null to clear the expiry; a body without it is a 422.
     */
    expires_at: (string | null);
};

