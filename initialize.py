import json

def is_it_ready():
    '''opens ready.txt file and checks if the app has ever been run or not'''
    ready = open("ready.txt", "rt").read() #read
    match(ready):
        case "False": return False
        case "True": return True
        case _: return False

def set_ready():
    '''Writes True to ready file, recording that first ever master has been created'''
    with open("ready.txt", "w") as file:
        file.write("True") #overwrite false

def connection_parameters():
    '''Read json config file'''
    with open("config.json", "r") as file:
        config = json.load(file)
        return config