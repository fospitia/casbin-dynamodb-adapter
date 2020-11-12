# casbin-dynamodb-adapter

DynamoDB adapter for Casbin https://github.com/casbin/node-casbin

Based on [casbin-couchbase-adapter](https://github.com/MarkMYoung/casbin-couchbase-adapter).

## Installation

npm install casbin-dynamodb-adapter

## Simple Example

```js
const Casbin = require( 'casbin' );
const CasbinDynamoDBAdapter = require( 'casbin-dynamodb-adapter' );
const AWS = require('aws-sdk');

const client = new AWS.DynamoDB.DocumentClient();

(async () => {
	try{
        const opts = {
            tableName:  'Test_Casbin',
            hashKey: 'id'
        };
        const enforcer = await Casbin.newEnforcer('model.conf', new CasbinDynamoDBAdapter(client, opts));

		// Load policies from the database.
		await enforcer.loadPolicy();

		// Add a policy.
		await enforcer.addPolicy('alice', 'data1', 'read');

		// Check permissions.
		let isMatched = enforcer.enforce( 'alice', 'data1', 'read' );
		console.log( isMatched );

		await enforcer.removePolicy('alice', 'data1', 'read');

		// Save policies back to the database.
		await enforcer.savePolicy();

		process.exit();
	}
    catch( e ) {
        console.error( e );
    }
})();
```