# src/siem/ingestion/file_reader.py

def read_log_file(file_path: str):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            # .readlines() returns a list of strings, which Python can loop through
            return file.readlines()
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return []  # Return an empty list so the engine doesn't crash
