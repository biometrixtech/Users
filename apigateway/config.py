import os
from dotenv import load_dotenv


load_dotenv('.env', verbose=True)

POSTGRES_DB_URI = os.getenv('POSTGRES_DB_URI')

SECRET_KEY_BASE = os.getenv('SECRET_KEY_BASE', 'ADNFI#NV)@#$CANSLF#')

BCRYPT_LOG_ROUNDS = 12
