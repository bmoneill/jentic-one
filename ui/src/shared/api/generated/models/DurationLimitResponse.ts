/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A default and a maximum for one duration, in seconds; null when unset.
 */
export type DurationLimitResponse = {
    /**
     * Applied when a creation sets no policy; null for none.
     */
    default_seconds?: (number | null);
    /**
     * The longest allowed; when set, every grant (or agent) must have one.
     */
    max_seconds?: (number | null);
};

