/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for creating an agent manually.
 */
export type AgentCreateRequest = {
    /**
     * Optional free-text description of the agent.
     */
    description?: (string | null);
    /**
     * When the agent stops working (RFC 3339, in the future). After this moment it is refused new tokens and the tokens it already holds stop working. The agent is not deleted and keeps its grants; set a later time or null to restore it. Omit for an agent that never expires.
     */
    expires_at?: (string | null);
    /**
     * Human-readable name of the agent.
     */
    name: string;
    /**
     * Permissions to grant the agent; each must be grantable by the caller. Omit to grant the default agent permission set.
     */
    permissions?: (Array<string> | null);
};

