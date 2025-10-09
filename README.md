# casbin-dynamodb-adapter

DynamoDB adapter for Casbin https://github.com/casbin/node-casbin

Based on [casbin-couchbase-adapter](https://github.com/MarkMYoung/casbin-couchbase-adapter).

## Installation

npm install casbin-dynamodb-adapter

## Changes in version 0.5.x

- **AWS SDK v3 Support**: Full compatibility with AWS SDK v3
- **Backward Compatibility**: Still supports AWS SDK v2
- **Enhanced Configuration**: Built-in client creation from config
- **LocalStack Support**: Easy endpoint configuration for local development

## Changes in version 0.4.x

- Change in CasbinDynamoDBAdapter class import
- New CasbinDynamoDBFilteredAdapter class based on DefaultFilteredAdapter class

## AWS SDK v3 Example (Recommended)

```js
const Casbin = require('casbin');
const { CasbinDynamoDBAdapter } = require('casbin-dynamodb-adapter');

(async () => {
  try {
    // Create adapter with configuration
    const adapter = await CasbinDynamoDBAdapter.newAdapter({
      region: 'us-east-1',
      tableName: 'casbin-rules'
      // Uses default: hashKey: 'id' (MD5 hash primary key)
      // AWS SDK uses IAM roles automatically (ECS, EC2, Lambda)
      // Credentials only needed for LocalStack:
      // endpoint: 'http://localhost:4566',
      // credentials: { accessKeyId: 'test', secretAccessKey: 'test' }
    });

    const enforcer = await Casbin.newEnforcer('model.conf', adapter);

    // Load policies from the database
    await enforcer.loadPolicy();

    // Add a policy
    await enforcer.addPolicy('alice', 'data1', 'read');

    // Check permissions
    const isMatched = enforcer.enforce('alice', 'data1', 'read');
    console.log(isMatched);

    await enforcer.removePolicy('alice', 'data1', 'read');

    // Save policies back to the database
    await enforcer.savePolicy();
  } catch (e) {
    console.error(e);
  }
})();
```

## AWS SDK v2 Example (Legacy)

```js
const Casbin = require('casbin');
const { CasbinDynamoDBAdapter } = require('casbin-dynamodb-adapter');
const AWS = require('aws-sdk');

const client = new AWS.DynamoDB.DocumentClient();

(async () => {
  try {
    const opts = {
      tableName: 'casbin-rules',
      hashKey: 'id'
    };
    const enforcer = await Casbin.newEnforcer('model.conf', new CasbinDynamoDBAdapter(client, opts));

    // Load policies from the database
    await enforcer.loadPolicy();

    // Add a policy
    await enforcer.addPolicy('alice', 'data1', 'read');

    // Check permissions
    const isMatched = enforcer.enforce('alice', 'data1', 'read');
    console.log(isMatched);

    await enforcer.removePolicy('alice', 'data1', 'read');

    // Save policies back to the database
    await enforcer.savePolicy();
  } catch (e) {
    console.error(e);
  }
})();
```