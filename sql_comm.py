import psycopg
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from table_obj import User, Master
import binascii

user = 'postgres'
password = 'securePass'
host = '127.0.0.1'
port = 8080
database = 'postgres'

def get_connection():
    return create_engine(
        url="postgresql+psycopg://{0}:{1}@{2}:{3}/{4}".format(
            user, password, host, port, database
        )
    )


try:
    engine = get_connection()
    engine.connect()
    session = Session(bind=engine)
except Exception as e:
    print("Connection to database failed \n", e)


def add_user(username, password, keydata):
    global session
    tester = User(username=username,password=password, keydata=keydata)
    session.add(tester)

    try:
        session.commit()
    except Exception as e:
        print("User was not sent to database, perhaps username is not unique" )

def get_user_data(username):
    global session
    usr = session.get(User, username)
    dek = usr.keydata
    password = usr.password
    
    return dek, password

def alter_password(username, password_new, keydata_new):
    global session
    usr = session.get(User, username)
    
    if usr != None:
        usr.keydata = keydata_new
        usr.password  = password_new
        session.commit()
    else:
        print("User not found")

def drop_user(username):
    global session
    usr = session.get(User, username)
    if usr != None:
        session.delete(usr)
        session.commit()
    else:
        print("User not found")

def get_master_info(master_name):
    global session
    master = session.get(Master, master_name)
    return master.kdf_salt, master.verify_hash



def new_master(master_name, hashs, kdf_salt):
    global session
    tester = Master(username=master_name, verify_hash = hashs, kdf_salt=kdf_salt)

    print(hashs)
    session.add(tester)

    try:
        session.commit()
    except Exception as e:
        print("Database rejected master. Keep in mind master name must be unique" )

def exit_db():
    global session
    session.close()

