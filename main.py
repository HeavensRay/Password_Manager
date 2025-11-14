from userpass_handle import argon_KDF, public_key, verify_master
from sql_comm import add_user, get_user_data, alter_password, drop_user, exit_db, get_master_info, new_master
from Crypto.Random import get_random_bytes
from encrypt_decrypt import encrypt_DEK, decrypt_DEK

def command_explained():
    print("Command types \n -c create new user \n -p show userpassword \n -a alter/change password \n -d delete user \n -m create new master \n -e exit")

mp_user = input("Who are you???? ")
mp_ask = input("Please enter master password ")
master_password = mp_ask.encode("utf-8") #to bytes |masterPass

try:
    kdf_salt, db_hash = get_master_info(mp_user)
    verify_master(master_password, db_hash)
except Exception as e:
    print("Master login failed. Relaunch program")
    exit()
    
KEK_Key = argon_KDF(password=master_password,salt=kdf_salt) 

print(f"Welcome, elevated user: {mp_user}")

command_explained()
command = input().strip().lower()

def main():

    global command

    while command != "-e":
    
        match(command):
            case "-c": create_user()
            case "-p": get_password()
            case "-a": change_password()
            case "-d": delete_user()
            case "-m":create_master()
        command_explained()
        command = command = input().strip().lower()

    exit_db()
    print("DB connection terminated, Goodbye")


def create_user():
    username = input("Enter a username ")
    password = input("Enter a password ")
    global KEK_Key

    DEK_plaintext = get_random_bytes(32)
    usr_plaintext= password.encode("utf-8")

    try:
        pass_enc, pass_tag, pass_nunce = encrypt_DEK(KEK_Key=DEK_plaintext, DEK_plaintext=usr_plaintext)
    except Exception as e:
        print("Key decryption failed, maybe you're not the master who encrypteed it")
        return
    pass_data = pass_nunce+ pass_tag+ pass_enc

    DEK_encr, tag, nunce = encrypt_DEK(KEK_Key=KEK_Key, DEK_plaintext=DEK_plaintext)
    dek_data= nunce+ tag+ DEK_encr

    add_user(username, pass_data, dek_data)

    print(f"Username {username} successfully created! ")

def get_password():

    username = input("Username whose password you wish to see: ")
    concat_dek, concat_vault=get_user_data(username=username)

    global KEK_Key

    pass_nunce = concat_vault[:12]
    pass_tag = concat_vault[12:28]
    encrypted_passw = concat_vault[28:]

    nunce_dek = concat_dek[:12]
    tag_dek = concat_dek[12:28]
    encrypted_DEK = concat_dek[28:]
    
    try:
        decrypted_DEK = decrypt_DEK(KEK_Key=KEK_Key, ciphertext=encrypted_DEK, tag=tag_dek, nonce=nunce_dek)
    except Exception as e:
        print("Key decryption failed, maybe you're not the master who encrypteed it")
        return

    pass_dec = decrypt_DEK(KEK_Key=decrypted_DEK, ciphertext=encrypted_passw, tag=pass_tag, nonce=pass_nunce)
    
    print(f"pasword: {pass_dec.decode("utf-8")}")

def change_password():
    username = input("Enter username you wish to alter ")
    new_pass = input("Enter new password ")

    mp_ask = input("Please re-enter MASTER password ")
    master_password = mp_ask.encode("utf-8") #to bytes |masterPass

    kdf_salt, db_hash = get_master_info(mp_user)

    try:
        verify_master(master_password, db_hash)
    except Exception as e:
        print("Master password was most likely incorrect. Please try again")
        return

    KEK_Key_Assure = argon_KDF(password=master_password,salt=kdf_salt) # regen KEK so we know mp is correct

    # dek passed 
    DEK_plaintext = get_random_bytes(32)
    usr_plaintext= new_pass.encode("utf-8")

    pass_enc, pass_tag, pass_nunce = encrypt_DEK(KEK_Key=DEK_plaintext, DEK_plaintext=usr_plaintext)

    pass_data = pass_nunce+ pass_tag+ pass_enc

    DEK_encr, tag, nunce = encrypt_DEK(KEK_Key=KEK_Key, DEK_plaintext=DEK_plaintext)
    dek_data= nunce+ tag+ DEK_encr

    alter_password(username, pass_data, dek_data)

    print(f"Password for username {username} successfully changed! ")

def delete_user():

    username = input("Enter username you wish to delete ")

    mp_ask = input("Please re-enter MASTER password ")
    master_password = mp_ask.encode("utf-8") #to bytes |masterPass

    kdf_salt, db_hash = get_master_info(mp_user)

    try:
        verify_master(master_password, db_hash)
        
    except Exception as e:
        print("Master password was most likely incorrect. Please try again")
        return

    drop_user(username)

def create_master():
    
    mp_user = input("What will new masters name be? ")
    mp_ask = input(f"Please enter {mp_user}'s password ")

    master_password = mp_ask.encode("utf-8") #to bytes |masterPass
    salt_KDF = get_random_bytes(16) #salt for encrypt/decryp
    db_hash = public_key(master_password)

    ask_again = input(f"Please enter {mp_user}'s password again ")
    ask_bytes = ask_again.encode("utf-8")
    try:
        verify_master(password=ask_bytes, db_hash=db_hash)
    except Exception as e:
        print("Passwords don't match. Terminated. Returning to menu")    
        return
    
    new_master(mp_user, db_hash, salt_KDF)
    print(f"Master {mp_user} successfully added!")


if __name__ == "__main__":
    main()

# usr keydata = new keydata not working

# do a hash encode and store it in secret w the salt lowlevel argon 