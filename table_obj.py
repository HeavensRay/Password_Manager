from sqlalchemy import Column, Integer,String, LargeBinary
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    username = Column(String(30), primary_key=True)
    password = Column(LargeBinary())
    keydata = Column(LargeBinary())


class Master(Base):
    __tablename__ = "masters"

    username = Column(String(30), primary_key=True)
    verify_hash = Column(String(100))
    kdf_salt = Column(LargeBinary())
