export interface AdapterConfig {
    region: string;
    tableName: string;
    hashKey?: string;
    rangeKey?: string;
    endpoint?: string;  // For LocalStack: 'http://localhost:4566'
    credentials?: {     // Optional: Only needed for LocalStack or non-IAM environments
        accessKeyId: string;
        secretAccessKey: string;
    };
    index?: {
        name: string;
        hashKey: string;
        hashValue: string;
    };
}

/**
 * Implements a policy adapter for Casbin with DynamoDB support.
 *
 * @class
 */
export class CasbinDynamoDBAdapter {
    /**
     * Create adapter with AWS SDK v3 configuration or legacy v2 client
     * @param {AdapterConfig | object} config Configuration object or legacy client
     * @param {string} [tableName] Legacy table name parameter
     */
    static newAdapter(config: AdapterConfig): Promise<CasbinDynamoDBAdapter>;
    static newAdapter(client: object, tableName: string): Promise<CasbinDynamoDBAdapter>;
    /**
     *
     * @param {object} client DynamoDB Document Client
     * @param {object} opts Options
     */
    constructor(client: object, opts?: object);
    client: any;
    tableName: any;
    hashKey: any;
    rangeKey: any;
    params: {
        TableName: any;
    };
    index: any;
    policyLine(policy: any): any;
    /**
     *
     * @param {object} policy
     * @param {Model} model
     */
    loadPolicyLine(policy: object, model: Model): void;
    /**
     *
     * @param {Model} model Model instance from enforcer
     * @returns {Promise<void>}
     */
    loadPolicy(model: Model): Promise<void>;
    /**
     *
     * @param {string} pType
     * @param {Array<string>} rule
     * @returns {object}
     */
    savePolicyLine(pType: string, rule: Array<string>): object;
    /**
     *
     * @param {Model} model Model instance from enforcer
     * @returns {Promise<boolean>}
     */
    savePolicy(model: Model): Promise<boolean>;
    /**
     *
     * @param {string} sec
     * @param {string} pType
     * @param {Array<string>} rule
     * @returns {Promise<void>}
     */
    addPolicy(sec: string, pType: string, rule: Array<string>): Promise<void>;
    /**
     *
     * @param {string} sec
     * @param {string} pType
     * @param {Array<string>} rule
     * @returns {Promise<void>}
     */
    removePolicy(sec: string, pType: string, rule: Array<string>): Promise<void>;
    /**
     *
     * @param {string} sec
     * @param {string} pType
     * @param {number} fieldIndex
     * @param  {...string} fieldValues
     * @returns {Promise<void>}
     */
    removeFilteredPolicy(sec: string, pType: string, fieldIndex: number, ...fieldValues: string[]): Promise<void>;
    /**
     *
     * @param {string} sec
     * @param {string} pType
     * @param {Array<Array<string>>} rules
     * @returns {Promise<void>}
     */
    addPolicies(sec: string, pType: string, rules: Array<Array<string>>): Promise<void>;
    /**
     *
     * @param {string} sec
     * @param {string} pType
     * @param {Array<Array<string>>} rules
     * @returns {Promise<void>}
     */
    removePolicies(sec: string, pType: string, rules: Array<Array<string>>): Promise<void>;
}
/**
 * Based on DefaultFilteredAdapter
 */
export class CasbinDynamoDBFilteredAdapter extends CasbinDynamoDBAdapter {
    filtered: boolean;
    /**
     *
     * @param {Model} model Model instance from enforcer
     * @param {Filter} filter Filter
     * @returns {Promise<void>}
     */
    loadFilteredPolicy(model: Model, filter: Filter): Promise<void>;
    /**
     *
     * @returns {void}
     */
    isFiltered(): void;
}
import { Model } from "casbin/lib/cjs/model/model";
import { Filter } from "casbin/lib/cjs/persist/defaultFilteredAdapter";
