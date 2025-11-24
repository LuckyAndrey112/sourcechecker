from classes import CryptoPassMP
import os

c=(CryptoPassMP(os.getenv('SECRET_KEY_MP')))
c.encrypt_secret()