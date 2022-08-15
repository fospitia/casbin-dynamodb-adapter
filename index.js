'use strict';

const { Helper, Model, DefaultFilteredAdapter } = require('casbin');
const { createHash } = require('crypto')

/**
 * 
 * @param {*} client 
 * @param {*} params 
 */
const find = async (client, params) => {
  const data = (params.KeyConditionExpression) ? await client.query(params).promise() : await client.scan(params).promise();
  if (data.LastEvaluatedKey) {
    params.ExclusiveStartKey = data.LastEvaluatedKey;
    data.Items = data.Items.concat(await find(client, params));
  }
  return data.Items;
};

/**
 * 
 * @param {*} client 
 * @param {*} params 
 */
const batchWrite = async (client, params) => {
  const data = await client.batchWrite(params).promise();
  if (Object.keys(data.UnprocessedItems).length) {
    params.RequestItems = data.UnprocessedItems;
    await batchWrite(client, params);
  }
  return data;
};

/**
 * Implements a policy adapter for Casbin with DynamoDB support.
 *
 * @class
 */
class CasbinDynamoDBAdapter {

  /**
   * 
   * @param {object} client DynamoDB Document Client
   * @param {object} opts Options
   */
  constructor(client, opts = {}) {
    this.client = client;
    this.tableName = opts.tableName;
    this.hashKey = opts.hashKey;
    this.params = { TableName: opts.tableName };
    this.index = opts.index;
    if (opts.index && opts.index.name && opts.index.hashKey && opts.index.hashValue) {
      this.params.IndexName = opts.index.name;
      this.params.KeyConditionExpression = `#${opts.index.hashKey} = :${opts.index.hashKey}`;
      this.params.ExpressionAttributeNames = {};
      this.params.ExpressionAttributeNames[`#${opts.index.hashKey}`] = opts.index.hashKey;
      this.params.ExpressionAttributeValues = {};
      this.params.ExpressionAttributeValues[`:${opts.index.hashKey}`] = opts.index.hashValue;
    }
  }

  /**
   * 
   * @param {object} client DynamoDB Document Client
   * @param {string} tableName DynamoDB Table Name
   */
  static async newAdapter(client, tableName) {
    return new CasbinDynamoDBAdapter(client, tableName);
  }

  policyLine(policy) {
    let line = policy.pType;

    if (policy.v0) {
      line += ', ' + policy.v0;
    }
    if (policy.v1) {
      line += ', ' + policy.v1;
    }
    if (policy.v2) {
      line += ', ' + policy.v2;
    }
    if (policy.v3) {
      line += ', ' + policy.v3;
    }
    if (policy.v4) {
      line += ', ' + policy.v4;
    }
    if (policy.v5) {
      line += ', ' + policy.v5;
    }

    return line;
  }

  /**
   * 
   * @param {object} policy 
   * @param {Model} model 
   */
  loadPolicyLine(policy, model) {
    const line = policyLine(policy);

    Helper.loadPolicyLine(line, model);
  }

  /**
   * 
   * @param {Model} model Model instance from enforcer
   * @returns {Promise<void>}
   */
  async loadPolicy(model) {
    const items = await find(this.client, this.params);
    for (const item of items) {
      this.loadPolicyLine(item, model);
    }
  }

  /**
   * 
   * @param {string} pType 
   * @param {Array<string>} rule
   * @returns {object}
   */
  savePolicyLine(pType, rule) {
    const [v0, v1, v2, v3, v4, v5] = rule;
    const policy = { pType, v0, v1, v2, v3, v4, v5 };
    if (this.index && this.index.hashKey && this.index.hashValue) {
      policy[this.index.hashKey] = this.index.hashValue;
    }
    policy[this.hashKey] = createHash('md5').update(JSON.stringify(policy)).digest("hex");
    return policy;
  }

  /**
   * 
   * @param {Model} model Model instance from enforcer
   * @returns {Promise<boolean>}
   */
  async savePolicy(model) {
    const policyRuleAST = model.model.get('p');
    const groupingPolicyAST = model.model.get('g');

    for (const [pType, ast] of policyRuleAST) {
      for (const rule of ast.policy) {
        const casbinPolicy = this.savePolicyLine(pType, rule);
        await this.client.put({ TableName: this.tableName, Item: casbinPolicy }).promise();
      }
    }

    for (const [pType, ast] of groupingPolicyAST) {
      for (const rule of ast.policy) {
        const casbinPolicy = this.savePolicyLine(pType, rule);
        await this.client.put({ TableName: this.tableName, Item: casbinPolicy }).promise();
      }
    }

    return true;
  }

  /**
   * 
   * @param {string} sec 
   * @param {string} pType 
   * @param {Array<string>} rule 
   * @returns {Promise<void>}
   */
  async addPolicy(sec, pType, rule) {
    const policy = this.savePolicyLine(pType, rule);
    await this.client.put({ TableName: this.tableName, Item: policy }).promise();
  }

  /**
   * 
   * @param {string} sec
   * @param {string} pType
   * @param {Array<string>} rule
   * @returns {Promise<void>}
   */
  async removePolicy(sec, pType, rule) {
    const policy = this.savePolicyLine(pType, rule);
    const params = { TableName: this.tableName, Key: {} };
    params.Key[this.hashKey] = policy[this.hashKey];
    await this.client.delete(params).promise();
  }

  /**
   * 
   * @param {string} sec 
   * @param {string} pType 
   * @param {number} fieldIndex 
   * @param  {...string} fieldValues 
   * @returns {Promise<void>}
   */
  async removeFilteredPolicy(sec, pType, fieldIndex, ...fieldValues) {
    const params = Object.assign({}, this.params);
    params.FilterExpression = '#pType = :pType';
    params.ExpressionAttributeNames = { '#pType': 'pType' };
    params.ExpressionAttributeValues = { ':pType': pType };

    if (fieldIndex <= 0 && fieldIndex + fieldValues.length > 0 && !!fieldValues[0 - fieldIndex]) {
      params.FilterExpression += ' AND #v0 = :v0';
      params.ExpressionAttributeNames['#v0'] = 'v0';
      params.ExpressionAttributeValues[':v0'] = fieldValues[0 - fieldIndex];
    }
    if (fieldIndex <= 1 && fieldIndex + fieldValues.length > 1 && !!fieldValues[1 - fieldIndex]) {
      params.FilterExpression += ' AND #v1 = :v1';
      params.ExpressionAttributeNames['#v1'] = 'v1';
      params.ExpressionAttributeValues[':v1'] = fieldValues[1 - fieldIndex];
    }
    if (fieldIndex <= 2 && fieldIndex + fieldValues.length > 2 && !!fieldValues[2 - fieldIndex]) {
      params.FilterExpression += ' AND #v2 = :v2';
      params.ExpressionAttributeNames['#v2'] = 'v2';
      params.ExpressionAttributeValues[':v2'] = fieldValues[2 - fieldIndex];
    }
    if (fieldIndex <= 3 && fieldIndex + fieldValues.length > 3 && !!fieldValues[3 - fieldIndex]) {
      params.FilterExpression += ' AND #v3 = :v3';
      params.ExpressionAttributeNames['#v3'] = 'v3';
      params.ExpressionAttributeValues[':v3'] = fieldValues[3 - fieldIndex];
    }
    if (fieldIndex <= 4 && fieldIndex + fieldValues.length > 4 && !!fieldValues[4 - fieldIndex]) {
      params.FilterExpression += ' AND #v4 = :v4';
      params.ExpressionAttributeNames['#v4'] = 'v4';
      params.ExpressionAttributeValues[':v4'] = fieldValues[4 - fieldIndex];
    }
    if (fieldIndex <= 5 && fieldIndex + fieldValues.length > 5 && !!fieldValues[5 - fieldIndex]) {
      params.FilterExpression += ' AND #v5 = :v5';
      params.ExpressionAttributeNames['#v5'] = 'v5';
      params.ExpressionAttributeValues[':v5'] = fieldValues[5 - fieldIndex];
    }

    const items = await find(this.client, params);

    const requestItems = [];
    for (const item of items) {
      const Key = {};
      Key[this.hashKey] = item[this.hashKey];
      requestItems.push({ DeleteRequest: { Key } });
    }

    const len = requestItems.length / 25;
    for (let x = 0, i = 0; x < len; i += 25, x++) {
      const params = { RequestItems: {} };
      params.RequestItems[this.tableName] = requestItems.slice(i, i + 25);
      await batchWrite(this.client, params);
    }
  }

  /**
   * 
   * @param {string} sec 
   * @param {string} pType 
   * @param {Array<Array<string>>} rules
   * @returns {Promise<void>}
   */
  async addPolicies(sec, pType, rules) {
    const requestItems = [];
    for (const rule of rules) {
      const policy = this.savePolicyLine(pType, rule);
      requestItems.push({ PutRequest: { Item: policy } });
    }

    const len = requestItems.length / 25;
    for (let x = 0, i = 0; x < len; i += 25, x++) {
      const params = { RequestItems: {} };
      params.RequestItems[this.tableName] = requestItems.slice(i, i + 25);
      await batchWrite(this.client, params);
    }
  }

  /**
   * 
   * @param {string} sec 
   * @param {string} pType 
   * @param {Array<Array<string>>} rules
   * @returns {Promise<void>}
   */
  async removePolicies(sec, pType, rules) {
    const requestItems = [];
    for (const rule of rules) {
      const policy = this.savePolicyLine(pType, rule);
      const Key = {};
      Key[this.hashKey] = policy[this.hashKey];
      requestItems.push({ DeleteRequest: { Key } });
    }

    const len = requestItems.length / 25;
    for (let x = 0, i = 0; x < len; i += 25, x++) {
      const params = { RequestItems: {} };
      params.RequestItems[this.tableName] = requestItems.slice(i, i + 25);
      await batchWrite(this.client, params);
    }
  }
}

/**
 * Based on DefaultFilteredAdapter
 */
class CasbinDynamoDBFilteredAdapter extends CasbinDynamoDBAdapter {

  constructor(client, opts = {}) {
    super(client, opts);
    this.filtered = false;
  }

  async loadPolicy(model) {
    this.filtered = false;
    await super.loadPolicy(model);
  }

  async loadFilteredPolicy(model, filter) {
    if (!filter) {
      await this.loadPolicy(model);
      return;
    }

    const items = await find(this.client, this.params);
    for (const item of items) {
      const line = this.policyLine(item);

      if (!line || DefaultFilteredAdapter.filterLine(line, filter)) {
        continue;
      }

      Helper.loadPolicyLine(line, model);
    }

    this.filtered = true;
  }

  isFiltered() {
    return this.filtered;
  }

  async savePolicy(model) {
    if (this.filtered) {
      throw new Error('cannot save a filtered policy');
    }
    await super.savePolicy(model);
    return true;
  }
}

module.exports.CasbinDynamoDBAdapter = CasbinDynamoDBAdapter;
module.exports.CasbinDynamoDBFilteredAdapter = CasbinDynamoDBFilteredAdapter;
