/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for directly binding a credential to an agent.
 */
export type CredentialBindRequest = {
    /**
     * ID of the credential to bind to the agent.
     */
    credential_id: string;
    /**
     * When the binding stops authorizing calls (RFC 3339, in the future). After this moment the broker refuses the agent's calls through it with 403 `credential_binding_expired`, whatever its token. The binding keeps its permission rules; an owner renews it by setting a later time or null. Omit for a binding that never expires.
     */
    expires_at?: (string | null);
};

