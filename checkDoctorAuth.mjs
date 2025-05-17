// index.mjs

/**
 * Lambda Authorizer ESM – zero‑dependency
 * header: Authorization: "Bearer <JWT>"
 */
export const handler = async (event) => {
  const authHeader = event.authorizationToken;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return generatePolicy('anonymous', 'Deny', event.methodArn);
  }

  const jwt = authHeader.slice(7);
  let payload;
  try {
    const base64Payload = jwt.split('.')[1];
    const jsonPayload = Buffer.from(base64Payload, 'base64').toString('utf8');
    payload = JSON.parse(jsonPayload);
  } catch (err) {
    console.error('Invalid JWT format', err);
    return generatePolicy('anonymous', 'Deny', event.methodArn);
  }

  const groups = Array.isArray(payload['cognito:groups'])
    ? payload['cognito:groups']
    : [];

  const effect = groups.includes('Doctor') ? 'Allow' : 'Deny';
  const principalId = payload.sub || 'user';
  return generatePolicy(principalId, effect, event.methodArn);
};

function generatePolicy(principalId, effect, resource) {
  return {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [{
        Action: 'execute-api:Invoke',
        Effect: effect,
        Resource: resource
      }]
    }
  };
}
