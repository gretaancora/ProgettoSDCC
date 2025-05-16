import json
import boto3
import os

dynamodb = boto3.client('dynamodb')
TABLE_NAME = os.environ.get('TABLE_NAME', 'ClinicalRecords')

def lambda_handler(event, context):
    try:
        # 1) Parse diretto del body JSON
        body_str = event.get('body') or ''
        payload = json.loads(body_str)

        # 2) Se vuoi supportare batch: normalizza in lista
        records = [payload] if isinstance(payload, dict) else payload
        if not isinstance(records, list):
            raise ValueError("Payload deve essere un oggetto o un array di oggetti")

        # 3) Validazione minima e insert su DynamoDB
        for i, rec in enumerate(records, start=1):
            for f in ('patientID','timestamp','doctorID','anomalyDescription'):
                if f not in rec:
                    return {
                        "statusCode": 400,
                        "headers": {"Content-Type":"application/json"},
                        "body": json.dumps({
                            "error": f"Manca il campo '{f}' nel record #{i}"
                        })
                    }

            dynamodb.put_item(
                TableName=TABLE_NAME,
                Item={
                    'patientID':          {'S': rec['patientID']},
                    'timestamp':          {'S': rec['timestamp']},
                    'doctorID':           {'S': rec['doctorID']},
                    'anomalyDescription': {'S': rec['anomalyDescription']}
                }
            )

        # 4) Risposta proxy‐style
        return {
            "statusCode": 200,
            "headers": {"Content-Type":"application/json"},
            "body": json.dumps({"message":"Dati inseriti correttamente"})
        }

    except ValueError as ve:
        # payload malformato
        return {
            "statusCode": 400,
            "headers": {"Content-Type":"application/json"},
            "body": json.dumps({"error": str(ve)})
        }
    except Exception as e:
        # errori a runtime
        return {
            "statusCode": 500,
            "headers": {"Content-Type":"application/json"},
            "body": json.dumps({"error": f"Errore interno: {e}"})
        }

