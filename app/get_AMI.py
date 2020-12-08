import time
import jwt

def get_AMI():
    service_account_id = environ.get('YANDEX_ACC_ID')
    key_id = environ.get('YANDEX_KEY_ID')# ID ресурса Key, который принадлежит сервисному аккаунту.

    private_key = environ.get('PRIVATE_KEY')

    now = int(time.time())
    payload = {
            'aud': 'https://iam.api.cloud.yandex.net/iam/v1/tokens',
            'iss': service_account_id,
            'iat': now,
            'exp': now + 600}

    # Формирование JWT.
    encoded_token = jwt.encode(
        payload,
        private_key,
        algorithm='PS256',
        headers={'kid': key_id})
    return encoded_token