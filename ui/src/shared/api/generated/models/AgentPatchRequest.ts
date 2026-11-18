/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for partially updating an agent.
 */
export type AgentPatchRequest = {
    /**
     * New description for the agent.
     */
    description?: (string | null);
    /**
     * When the agent stops working (RFC 3339, in the future). After this moment it is refused new tokens and the tokens it already holds stop working. The agent is not deleted and keeps its grants; set a later time or null to restore it. Send null to clear the expiry.
     */
    expires_at?: (string | null);
    /**
     * New name for the agent.
     */
    name?: (string | null);
    /**
     * ID of the user to transfer ownership to; `org:admin` only.
     */
    owner_id?: (string | null);
};

