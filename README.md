Password manager encrypts/decrypts passwords and stores them on postgresql database.
Option for multiple users(masters), each user decrypts their own keys

Technologies used:
Argon2Id for user authenticaion.
AES_GCM for encryption/decryption.
Pycopg and sqlAlchemy for communication with database

