/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Optional request body for approving an agent.
 */
export type AgentApproveRequest = {
    /**
     * When the agent stops working (RFC 3339, in the future). After this moment it is refused new tokens and the tokens it already holds stop working. The agent is not deleted and keeps its grants; set a later time or null to restore it. Omit to leave the agent's expiry as it is.
     */
    expires_at?: (string | null);
};

