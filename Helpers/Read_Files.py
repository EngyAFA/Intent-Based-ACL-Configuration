#################### Helping function : read the files inside a given folder ####################
#################################################################################################

import os
# ############ read all configs files in folder path ############
def read_all_files_in_folder(folder_path):
    all_file_contents = {}  # Dictionary to hold contents of all configs files
    try:
        # List all files in the given folder
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            # Check if it is a file ?
            if os.path.isfile(file_path):
                with open(file_path, 'r') as file:
                    all_file_contents[filename] = file.read()  # Read file content
    except Exception as e:
        print(f"An error occurred: {e}")
    
    return all_file_contents

# ############ read all JSON files in folder path ############
def read_all_json_files_in_folder(folder_path):
    all_json_contents = {}  # Dictionary to hold contents of all JSON files
    try:
        # List all files in the given folder
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            # Check if it is a file and if it has a .json extension ?
            if os.path.isfile(file_path) and filename.lower().endswith('.json'):
                with open(file_path, 'r') as file:
                    all_json_contents[filename] = file.read()  # Read file content
    except Exception as e:
        print(f"An error occurred: {e}")
    
    return all_json_contents
# ############ read all JSON files in folder path for evaluation ############

def read_all_json_files_in_folder_Eval(folder_path):
    all_json_contents = {}
    try:
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)

            # only topology json files (skip intents)
            if (os.path.isfile(file_path)
                and filename.lower().endswith(".json")
                and "topology" in filename.lower()
                and "intent" not in filename.lower()):
                
                with open(file_path, "r", encoding="utf-8") as file:
                    all_json_contents[filename] = file.read()

    except Exception as e:
        print(f"An error occurred: {e}")

    return all_json_contents
    
# ############ read all vpc files in folder path (PC configs files) ############
def read_all_vpc_files_in_folder(folder_path):
    all_vpc_contents = {}  # Dictionary to hold contents of all vpc files
    try:
        # List all files in the given folder
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            # Check if it is a file and if it has a .json extension
            if os.path.isfile(file_path) and filename.lower().endswith('.vpc'):
                with open(file_path, 'r') as file:
                    all_vpc_contents[filename] = file.read()  # Read file content
    except Exception as e:
        print(f"An error occurred: {e}")
    
    return all_vpc_contents

# ############ read a given file ############
def read_topology_file(file_path):
    try:
        with open(file_path, 'r') as file:
            contents = file.readlines()
        return contents
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        return None