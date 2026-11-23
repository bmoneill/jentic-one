/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Why a call is held.
 *
 * ``execution``: a ``require-approval`` rule matched; approving runs it.
 * ``grant_renewal``: the agent's binding to the credential has ended (its end
 * date, idle limit or uses); approving gives the binding fresh access first,
 * and may then run the call.
 */
export enum HeldExecutionKind {
    EXECUTION = 'execution',
    GRANT_RENEWAL = 'grant_renewal',
}
