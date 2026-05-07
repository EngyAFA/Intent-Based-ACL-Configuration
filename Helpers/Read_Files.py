import os

# ############ read all configs files in folder path ############
def read_all_files_in_folder(folder_path: str) -> dict:
    all_file_contents = {}

    try:
        # List all files in the given folder
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)

            # Check if it is a file ?
            if os.path.isfile(file_path):
                with open(file_path, "r") as file:
                    all_file_contents[filename] = file.read()

    except Exception as error:
        print(f"An error occurred: {error}")

    return all_file_contents


# ############ read all JSON files in folder path ############
def read_all_json_files_in_folder(folder_path: str) -> dict:
    all_json_contents = {}

    try:
        # List all files in the given folder
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)

            # Check if it is a file and if it has a .json extension ?
            if (
                os.path.isfile(file_path)
                and filename.lower().endswith(".json")
            ):
                with open(file_path, "r") as file:
                    all_json_contents[filename] = file.read()

    except Exception as error:
        print(f"An error occurred: {error}")

    return all_json_contents


# ############ read all JSON files in folder path for evaluation ############
def read_all_json_files_in_folder_Eval(folder_path: str) -> dict:
    all_json_contents = {}

    try:
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)

            # only topology json files (skip intents)
            if (
                os.path.isfile(file_path)
                and filename.lower().endswith(".json")
                and "topology" in filename.lower()
                and "intent" not in filename.lower()
            ):
                with open(file_path, "r", encoding="utf-8") as file:
                    all_json_contents[filename] = file.read()

    except Exception as error:
        print(f"An error occurred: {error}")

    return all_json_contents


# ############ read all vpc files in folder path (PC configs files) ############
def read_all_vpc_files_in_folder(folder_path: str) -> dict:
    all_vpc_contents = {}

    try:
        # List all files in the given folder
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)

            # Check if it is a file and if it has a .json extension
            if (
                os.path.isfile(file_path)
                and filename.lower().endswith(".vpc")
            ):
                with open(file_path, "r") as file:
                    all_vpc_contents[filename] = file.read()

    except Exception as error:
        print(f"An error occurred: {error}")

    return all_vpc_contents


# ############ read a given file ############
def read_topology_file(file_path: str):
    try:
        with open(file_path, "r") as file:
            contents = file.readlines()

        return contents

    except Exception as error:
        print(f"An error occurred while reading the file: {error}")

        return None