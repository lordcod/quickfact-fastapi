from os import getenv
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = getenv('REDIS_URL')
SECRET_KEY = getenv('SECRET_KEY')
