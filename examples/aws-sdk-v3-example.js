const Casbin = require('casbin');
const { CasbinDynamoDBAdapter } = require('../index');

// AWS SDK v3 Example
async function exampleV3() {
  try {
    const adapter = await CasbinDynamoDBAdapter.newAdapter({
      region: 'us-east-1',
      tableName: 'casbin-rules'
      // Uses default: hashKey: 'id' (MD5 hash primary key)
    });

    const enforcer = await Casbin.newEnforcer('model.conf', adapter);
    await enforcer.loadPolicy();
    await enforcer.addPolicy('alice', 'data1', 'read');
    
    const isMatched = enforcer.enforce('alice', 'data1', 'read');
    console.log('Permission check:', isMatched);

    await enforcer.removePolicy('alice', 'data1', 'read');
    await enforcer.savePolicy();
    
    console.log('AWS SDK v3 example completed');
  } catch (error) {
    console.error('Error:', error);
  }
}

module.exports = { exampleV3 };