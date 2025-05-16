import jwt
import json
import boto3
import os
from jwt import PyJWKClient

COGNITO_USERPOOL_ID = 'us-east-1_dPfef9vVU'
COGNITO_REGION      = 'us-east-1'
COGNITO_GROUP       = 'Doctor'
KEYS_URL = (
    f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/"
    f"{COGNITO_USERPOOL_ID}/.well-known/jwks.json"
)

# Crea il client JWKS una volta sola (fuori dall'handler)
jwk_client = PyJWKClient(KEYS_URL)

def lambda_handler(event, context):
    token_header = event.get('authorizationToken', '')
    if not token_header.startswith("Bearer "):
        return generate_policy('unauthorized', 'Deny', event.get('methodArn','*'))
    token = token_header.split()[1]

    # Ottieni la chiave pubblica dal JWK endpoint
    signing_key = jwk_client.get_signing_key_from_jwt(token)

    # Decodifica e verifica
    decoded = jwt.decode(
        token,
        signing_key.key,
        algorithms=['RS256'],
        audience=None,        # opzionale: l’audience attesa
        issuer=f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USERPOOL_ID}"
    )

    groups = decoded.get('cognito:groups', [])
    if COGNITO_GROUP in groups:
        return generate_policy(decoded['sub'], 'Allow', event['methodArn'], {
            'username': decoded.get('username','unknown'),
            'groups': ','.join(groups)
        })
    else:
        return generate_policy('unauthorized', 'Deny', event['methodArn'])
