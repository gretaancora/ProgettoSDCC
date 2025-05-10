import jwt
import json
import urllib.request
import json
import boto3
import os

COGNITO_USERPOOL_ID = 'us-east-1_dPfef9vVU'
COGNITO_REGION = 'us-east-1'
COGNITO_GROUP = 'Doctor'

# URL per scaricare le chiavi pubbliche JWKS
KEYS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USERPOOL_ID}/.well-known/jwks.json"

# Carica le chiavi una sola volta
jwks = json.loads(urllib.request.urlopen(KEYS_URL).read())
public_keys = {
    key['kid']: jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
    for key in jwks['keys']
}


def lambda_handler(event, context):
    try:
        print("Inizio verifica del token")

        # Verifica che il token esista e sia ben formato
        token_header = event.get('authorizationToken')
        print(f"Authorization header: {token_header}")
        if not token_header or not token_header.startswith("Bearer "):
            raise Exception("Missing or malformed token")

        token = token_header.split()[1]  # estrae il token JWT
        print(f"Token ricevuto: {token[:10]}...")  # Mostra solo i primi 10 caratteri del token per privacy

        # Ottieni l'header JWT e la chiave pubblica corretta
        headers = jwt.get_unverified_header(token)
        print(f"Intestazione JWT: {headers}")
        
        key = public_keys.get(headers['kid'])
        if not key:
            raise Exception("Public key not found")

        # Decodifica il token JWT
        print("Decodifica del token in corso...")
        decoded_token = jwt.decode(token, key=key, algorithms=['RS256'])
        print(f"Token decodificato: {decoded_token}")

        # Controlla se l'utente è nel gruppo "Doctor"
        groups = decoded_token.get('cognito:groups', [])
        print(f"Gruppi dell'utente: {groups}")

        if COGNITO_GROUP in groups:
            print(f"L'utente è nel gruppo {COGNITO_GROUP}. Accesso consentito.")
            return generate_policy(decoded_token['sub'], 'Allow', event['methodArn'], {
                'username': decoded_token.get('username', 'unknown'),
                'groups': ','.join(groups)
            })
        else:
            print(f"L'utente non è nel gruppo {COGNITO_GROUP}. Accesso negato.")
            # Non è nel gruppo richiesto → accesso negato
            return generate_policy('unauthorized', 'Deny', event['methodArn'])

    except Exception as e:
        print(f"Errore di autorizzazione: {str(e)}")
        return generate_policy('unauthorized', 'Deny', event.get('methodArn', '*'))


def generate_policy(principal_id, effect, resource, context=None):
    print(f"Generazione policy per l'ID {principal_id} con effetto {effect}")
    policy = {
        'principalId': principal_id,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': resource
            }]
        }
    }
    if context:
        policy['context'] = context
    return policy
