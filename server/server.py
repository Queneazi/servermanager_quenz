import socket
import threading
import sqlite3
import hashlib
import os
import Encryptor
import shutil

user_dirs = {}
lock = threading.Lock()


def handle_client(client_socket):
    global user_id
    with (client_socket):
        print(f"Has been connected: {client_socket.getpeername()}")
        while True:
            data = client_socket.recv(1024).decode("utf-8")
            data = encrypt.decrypt_AES_CBC('papa', data)
            if not data:
                break
            flag, new_data = data[0], data[1:]
            print(f"Flag: {flag}")
            match flag:
                case '@':
                    client_socket.send(encrypt.encrypt_AES_CBC('papa', f'{user_id}Successful logged').encode("utf-8") if login(new_data)
                                       else encrypt.encrypt_AES_CBC('papa', 'Login already exists').encode("utf-8"))
                case '#':
                    client_socket.send(encrypt.encrypt_AES_CBC('papa', f'{user_id}Successful registered').encode("utf-8") if register(new_data)
                                       else encrypt.encrypt_AES_CBC('papa', 'Login already exists').encode("utf-8"))
                case _:
                    try:
                        operation, name = new_data.split()
                    except ValueError:
                        name = None
                        operation = new_data
                    client_socket.sendall(encrypt.encrypt_AES_CBC('papa', handle_request(flag, operation, name)).encode('utf-8'))
            print(f"Received: {new_data}")
        print(f"Has been disconnected: {client_socket.getpeername()}")


def handle_request(flag, operation, name):
    # Parse the request
    with lock:
        if flag not in user_dirs:
            user_dirs[flag] = {
                'current': os.path.join(os.getcwd(), flag),
                'root': os.path.join(os.getcwd(), flag)
            }

        user_dir = user_dirs[flag]['current']
        root_dir = user_dirs[flag]['root']

    response = ""
    try:
        if not operation:
            # If no operation is specified, display the contents of the user's root directory
            response = "\n".join(os.listdir(root_dir))

        elif operation == "list":
            # Check the presence of a folder in the current and root directories of the user
            target_dir_current = os.path.join(user_dir, name)
            target_dir_root = os.path.join(root_dir, name)

            # checks if the directory exists and if it is a directory
            if os.path.exists(target_dir_current) and os.path.isdir(target_dir_current):
                response = "\n".join(os.listdir(target_dir_current))
                with lock:
                    # pins the current directory
                    user_dirs[flag]['current'] = target_dir_current
            # check if this is the root directory
            elif os.path.exists(target_dir_root) and os.path.isdir(target_dir_root):
                response = "\n".join(os.listdir(target_dir_root))
                with lock:
                    user_dirs[flag]['current'] = target_dir_root
            else:
                response = "Directory does not exist"

        # deletes a file or directory
        elif operation == "delete":
            target_path = os.path.join(user_dir, name)
            print(target_path)
            # checks for either a directory or a file
            if os.path.exists(target_path):
                if os.path.isfile(target_path):
                    os.remove(target_path)
                    response = "File deleted"
                elif os.path.isdir(target_path):
                    shutil.rmtree(target_path)
                    response = "Directory deleted"
            else:
                response = "File or directory does not exist"

        # runs files on the server
        elif operation == "run":
            target_path = os.path.join(user_dir, name)
            print(target_path)
            # checks if exists and if it is a file
            if os.path.exists(target_path) and os.path.isfile(target_path):
                os.system(f'{target_path}')
                response = "File executed"
            else:
                response = "File does not exist or is not executable"

        else:
            response = "Invalid operation"

    except Exception as e:
        response = f"Error: {str(e)}"

    return response


# function for splitting data
def validate_data(data):
    try:
        return data.split()  # Split into list, handle potential IndexError internally
    except IndexError:
        return None


def register(data):
    login_1, password = validate_data(data)
    password = hashlib.sha256(password.encode("utf-8")).hexdigest() # saves the password as a hash
    global user_id
    # Validate login and password before attempting insertion (optional)
    if not login_1 or not password:
        # Handle invalid data (e.g., send error message to client)
        print("Invalid registration data. Login and password required.")
        return
    try:
        # searches the database for the last user by his ID
        cursor.execute('SELECT id FROM Users ORDER BY id DESC LIMIT 1')
        result = cursor.fetchone()
        if result:
            user_id = result[0] + 1
        else:
            user_id = 0
        # adds a new user to the database with his new ID
        cursor.execute('INSERT INTO Users(id, login, password) VALUES (?, ?, ?)', (user_id, login_1, password))
        conn_db.commit()
        print("User successfully added.")
        # creates a folder with its number
        os.mkdir(f'{user_id}')
        # returns the new user ID to send it to the client
        return [user_id, 'True']
    # eliminates errors so that the server does not crash due to an error
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed: Users.login" in str(e):
            return ['', 'False']
        else:
            print(f"Database error: {e}")  # Handle other potential errors


def login(data):
    login_1, password = validate_data(data)
    password = hashlib.sha256(password.encode("utf-8")).hexdigest() # saves the password as a hash
    global user_id
    # Validate login and password before querying the database (optional)
    if not login_1 or not password:
        # Handle invalid data (e.g., send error message to client)
        return False
    cursor.execute('SELECT * FROM Users WHERE login = ? AND password = ?', (login_1, password))
    result = cursor.fetchone()  # Fetch only the first matching row
    if not result:
        return False
    else:
        user_id = result[0]
        return True


def main(ip='localhost', port=9090):
    global conn_db, cursor
    # creates and connects the database to the server
    conn_db = sqlite3.connect('database.db', check_same_thread=False)
    cursor = conn_db.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY,
    login TEXT NOT NULL,
    password TEXT NOT NULL
    )
    ''')
    # starts the server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(10)
    print(f"Server was started on: {ip}:{port}")

    while True:
        # creates a new thread on the server and connects the user
        client_socket, addr = server.accept()
        print(f"Connection was established: {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()


if __name__ == "__main__":
    user_id = 0
    encrypt = Encryptor
    main()
