# DynamoDB Table Schema

The adapter works with the following DynamoDB table schema:

## Required Table Structure

```hcl
resource "aws_dynamodb_table" "casbin_rules" {
  name         = "casbin-rules"
  billing_mode = "PAY_PER_REQUEST"

  hash_key = "id"

  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled  = true
    sse_type = "AES256"
  }

  point_in_time_recovery {
    enabled = true
  }

  deletion_protection_enabled = true

  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Name        = "casbin_rules"
    Environment = "production"
  }
}
```

## Table Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | String (S) | MD5 hash - Primary Key |
| `pType` | String (S) | Policy type (p, g, etc.) |
| `v0` | String (S) | First policy value |
| `v1` | String (S) | Second policy value (optional) |
| `v2` | String (S) | Third policy value (optional) |
| `v3` | String (S) | Fourth policy value (optional) |
| `v4` | String (S) | Fifth policy value (optional) |
| `v5` | String (S) | Sixth policy value (optional) |

## Key Design

- **Primary Key (id)**: MD5 hash of the entire policy object ensures uniqueness
- **Policy Fields**: Standard Casbin format with `pType` (capital T)

## Example Data

```json
{
  "id": "6b06c5ab394cbfafe05c8f9ca0ee5973",
  "pType": "p",
  "v0": "admin",
  "v1": "order_service", 
  "v2": "read"
}
```

## Adapter Configuration

**Production (ECS/EC2/Lambda with IAM roles):**
```javascript
const adapter = await CasbinDynamoDBAdapter.newAdapter({
  region: 'us-east-1',
  tableName: 'casbin_rules'
  // No credentials needed - uses IAM roles automatically
});
```

**LocalStack Development:**
```javascript
const adapter = await CasbinDynamoDBAdapter.newAdapter({
  region: 'us-east-1',
  tableName: 'casbin_rules',
  endpoint: 'http://localhost:4566',
  credentials: {  // Required for LocalStack
    accessKeyId: 'test',
    secretAccessKey: 'test'
  }
});
```

**Legacy (AWS SDK v2):**
```javascript
const adapter = new CasbinDynamoDBAdapter(dynamoClient, {
  tableName: 'casbin_rules',
  hashKey: 'id'
});
```

This matches the exact original Casbin DynamoDB adapter structure.