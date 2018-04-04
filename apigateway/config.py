import os
from dotenv import load_dotenv


load_dotenv('../.env', verbose=True)

POSTGRES_DB_URI = os.getenv('POSTGRES_DB_URI')


BCRYPT_LOG_ROUNDS = 12