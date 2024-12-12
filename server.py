# import

import socket
import select
import pandas as pd
import json
import os
import uuid  # to get the client id when it connects

import chatlib
import tables_handaling as tb
from cyphers import cypher_functions as cf, server_secret_value as ssv, asymetric_encrypt as ae
import port_and_ip_data as paid

global logged_users
global ready_to_write
global client_sockets
global messages_to_send
global hobbies_dictionary
global friendships_requests_dictionary
global friendships_dictionary
global id_dictionary
global info_dictionary

info_dictionary_key = "groups and requests"

HOBBIES_FILE_PATH = os.path.join(os.getcwd(), 'hobbies_dictionary_place.json')
FRIENDSHIPS_REQUESTS_FILE_PATH = os.path.join(os.getcwd(), 'friendships_requests_dictionary_place.json')
FRIENDSHIPS_FILE_PATH = os.path.join(os.getcwd(), 'friendships_dictionary_place.json')
ID_FILE_PATH = os.path.join(os.getcwd(), 'id_dictionary_place.json')
INFO_FILE_PATH = os.path.join(os.getcwd(), 'info_dictionary_place.json')

data_base_connection = tb.create_connection('data_base.db')
cursor = data_base_connection.cursor()

trigger_word = "disconnect"
opposite_trigger = "don't disconnect"

invalid_password_msg = "\nThe password should at least be from length 6 and contain a digit\n"
invalid_username_msg = "\nThe username should at least be from length 6 and contain a digit\n"

invalid_message_part1 = "\nThe username and the password must contain a digit and a lowercase letter"
invalid_message_part2 = "and the length needs to be between 6 and 15\n"
invalid_message = invalid_message_part1 + invalid_message_part2

users_table = "users"
tasks_table = "tasks"
diaries_sharing_requests_table = "diaries_sharing_requests"
diaries_sharing_table = "diaries_sharing_groups"
tasks_sharing_requests_table = "tasks_sharing_requests"
tasks_sharing_table = "tasks_sharing"

possible_keys = ["usernames", "password", "id", "names_id"]

# error
login_error = chatlib.PROTOCOL_SERVER['login_failed_msg']

# important expressions

# hobbies
no_hobbies_delete_msg = "Didn't enter any hobbies so there is nothing to delete! "
no_hobbies_see_msg = "Didn't enter any hobbies so there is nothing to see! "

# search by username
no_username_msg = "There is no such username! "
exist_username_msg = "There is such username! "

# search by hobbies
no_similar_clients_msg = "No similar clients were found! "
no_similar_hobbies_msg = "You have no similar hobbies! "
cant_send_self_friendship_request = "You can't send friendship request to yourself! "
no_self_similar_hobbies = "It means nothing to have similar hobbies with yourself! "

# friendship requests
no_friendship_requests = "You have no friendship requests! "

# profile
no_friends = "You have no friends! "
no_pending_outgoing_requests = "Your have no pending outgoing requests! "

# tasks
no_tasks_delete_msg = "You have no tasks so there is nothing to delete here! "
no_tasks_edit_msg = "You have no tasks so there is nothing to edit here! "
no_tasks_see_msg = "You have no tasks so there is nothing to see here! "
no_tasks_specific_day = "You don't have tasks on that day! "

# shared diaries
no_outgoing_requests_to_share_diaries = "You haven't sent any diary sharing request yet! "
no_ingoing_requests_to_share_diaries = "You don't have any ingoing requests to share diaries! "
no_friends_to_add_to_recipients = "You have no friends to add to the recipients list! "
no_shared_diaries_groups_to_share_diaries = "There are no shared diaries groups you participate in or created! "
shared_diaries_group_is_deleted = "The group is deleted! "
no_group_sharing_tasks_requests = "There are not requests for task sharing in this group! "
no_group_shared_tasks = "There are no shared tasks of the group! "

# Hobbies in various topics
different_hobbies = {
    "music": ["guitar", "piano", "singing", "drums", "bass", "violin", "ukulele", "harmonica", "flute"],
    "sports": ["soccer", "basketball", "tennis", "swimming", "yoga", "cycling", "hiking", "skiing", "running"],
    "crafts": ["knitting", "sewing", "crochet", "quilting", "pottery", "jewelry making", "scrapbooking", "calligraphy", "painting"],
    "programming": ["web development", "data analysis", "machine learning", "game development", "mobile app development", "robotics", "cybersecurity", "blockchain", "artificial intelligence"],
    "reading": ["fiction", "non-fiction", "biography", "mystery", "history", "fantasy", "romance", "science fiction", "thriller"],
    "cooking": ["baking", "grilling", "sushi making", "vegetarian cooking", "candy making", "cocktail mixing", "soup making", "chocolate making", "fermenting"],
    "photography": ["landscape", "portrait", "nature", "wildlife", "macro", "street", "black and white", "long exposure", "architecture"],
    "gaming": ["board games", "card games", "video games", "role-playing games", "puzzle games", "strategy games", "sports games", "shooter games", "simulation games"],
    "gardening": ["flower gardening", "vegetable gardening", "indoor gardening", "herb gardening", "landscaping", "composting", "bonsai gardening", "terrariums", "hydroponics"]
}

search_by_username_index = '0'
search_by_hobbies_index = '1'
friendship_requests_index = '2'
friends_index = '3'
pending_outgoing_requests_index = '4'
shared_diaries_outgoing_requests_index = '5'
shared_diaries_ingoing_requests_index = '6'

# no twice
no_hobby_twice = "You can't enter the same hobby twice! "
no_task_twice = "You can't enter the same task twice! "

request_doesnt_exist = "The request doesn't exist anymore! "
no_diaries_sharing_request_twice = "Info column can't have the same values! "

group_doesnt_exist = "The group doesn't exist anymore! "
no_leaving_share_diaries_group_recipients = "You can't leave the group currently because you were already kicked from the group! "
no_leaving_share_diaries_group_manager = "You can't declare this recipients as the new manager beacuse he left the group! "
no_adding_these_friends = "All these friends / recipients deleted the friendship with you! "
no_kicking_share_diaries_group = "You can't kick this recipients currently because it will lead to having identical groups! "

no_share_task_request_twice = "Info column of the tasks (task info) can't have the same values! "
sharing_task_request_doesnt_exist = "The sharing task request doesn't exist anymore! "

# doesn't exist : everyone rejected/everyone approved

# Note: almost every function here will contain the following variables as inputs:
# conn - a specific client that is connected to the server
# cmd - the cmd within the client's full message to the server
# msg - the msg withing the client's full message to the server
# client_id - the id of conn (the id of the client)

# SOCKET CREATOR


def setup_socket():
    """
    Creates new listening socket and returns it
    Returns: the socket object
    """
    server_socket = socket.socket()
    server_socket.bind((paid.SERVER_IP, paid.SERVER_PORT))
    server_socket.listen()
    print("Server is up and running")
    return server_socket


def build_and_send_message(conn, code, msg):
    """
    Builds a new message using chatlib, wanted code and message.
    Prints debug info, then sends it to the given socket.
    Paramaters: conn (socket object), code (str), msg (str)
    Returns: Nothing
    """
    full_msg = chatlib.build_message(code, msg)
    print("[THE SERVER'S MESSAGE] ", full_msg)  # Debug print

    if full_msg != chatlib.ERROR_RETURN:
        messages_to_send.append((conn, full_msg))


def wise_recv(current_socket):
    """
    :param current_socket:
    :return:
    """
    global id_dictionary

    try:
        msg = current_socket.recv(10024)

        if msg == "":
            print("Received message to end the connection from ", tuple(current_socket.getpeername()))
            return "", trigger_word

        else:
            client_key = id_dictionary[str(current_socket.getpeername())][1]

            if client_key is None:
                return msg.decode(), opposite_trigger

            else:
                msg_after_decrypt = cf.decrypt(msg, client_key)
                return msg_after_decrypt, opposite_trigger

    except socket.error:
        print(tuple(current_socket.getpeername()), "disconnected!")
        return "", trigger_word


def recv_message_and_parse(client_socket):
    """
    Receives a new message from given socket.
    Prints debug info, then parses the message using chatlib.
    Paramaters: conn (socket object)
    Returns: cmd (str) and data (str) of the received message.
    If error occurred, will return None, None
    """
    data, flag = wise_recv(client_socket)

    if flag == trigger_word:
        handle_exit_message(client_socket, chatlib.PROTOCOL_CLIENT['exit_from_app'], "")

    if data == "":
        cmd, msg = "", ""

    else:
        cmd, msg = chatlib.parse_message(data)
        print("[THE CLIENT'S MESSAGE IS:] ", (cmd, msg))  # Debug print

        if cmd != chatlib.ERROR_RETURN or msg != chatlib.ERROR_RETURN:
            print("The data is: ", data)
            print("The command: ", cmd)
            print("The message: ", msg)
            print()

    return cmd, msg


def load_hobbies_dictionary():
    try:
        with open(HOBBIES_FILE_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def load_friendships_requests_dictionary():
    try:
        with open(FRIENDSHIPS_REQUESTS_FILE_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def load_friendships_dictionary():
    try:
        with open(FRIENDSHIPS_FILE_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def load_id_dictionary():
    try:
        with open(ID_FILE_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# INFO_FILE_PATH = os.path.join(os.getcwd(), 'info_dictionary_place.json')


def load_info_dictionary():
    try:
        with open(INFO_FILE_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_hobbies_dictionary(d):
    with open(HOBBIES_FILE_PATH, 'w') as f:
        json.dump(d, f)


def save_friendships_requests_dictionary(d):
    with open(FRIENDSHIPS_REQUESTS_FILE_PATH, 'w') as f:
        json.dump(d, f)


def save_friendships_dictionary(d):
    with open(FRIENDSHIPS_FILE_PATH, 'w') as f:
        json.dump(d, f)


def save_id_dictionary(d):
    with open(ID_FILE_PATH, 'w') as f:
        json.dump(d, f)


def save_info_dictionary(d):
    with open(INFO_FILE_PATH, 'w') as f:
        json.dump(d, f)


def handle_public_key_message(conn, message, client_id):
    """
    Calculates the shared key for conn and the server.
    conn = a client connection.
    message = the client's (=conn) message.
    client_id = the client's (=conn) id.
    """
    global id_dictionary  # the dictionary for all id's

    # ssv = server_secret_value

    server_secret_key = ssv.server_secret_val  # the secret value of the server
    server_secret_prime = ssv.p  # the prime
    client_public_key = int(message)  # the public key of the client

    server_key = pow(client_public_key, server_secret_key, server_secret_prime)  # calculating the server key
    id_dictionary[str(conn.getpeername())] = (client_id, str(server_key))  # adding to the id_dictionary

    save_id_dictionary(id_dictionary)  # saving the changes

    full_msg = str(ssv.server_public_val)
    build_and_send_message(conn, chatlib.PROTOCOL_SERVER['public_key_ok_msg'], full_msg)
    # sending to the client the server's public value


def handle_logout_message(conn):
    """
    Closes the given socket (in later chapters, also remove user from logged_users dictionary)
    Receives: socket
    Returns: None
    """
    global logged_users

    try:
        if conn.getpeername() in logged_users.keys():
            del logged_users[conn.getpeername()]

    except OSError:
        print("Not a client anymore!")

    msg = ""
    msg += "\t If you want to register : press register \n"
    msg += "\t If you want to login : press login \n"
    msg += "\t If you want to exit the app : press exit \n"
    msg += "\n"

    build_and_send_message(conn, chatlib.PROTOCOL_SERVER['logout_ok_msg'], msg)
    return "logged out the user"


def send_error(conn, cmd, error_msg):
    """
    Send error message with given message
    Receives: socket, message error string from called function
    Returns: None
    """
    build_and_send_message(conn, cmd, error_msg)


def is_syntax_valid(word):
    """
    :param word: the word that will be checked for correct syntax or not.
    :return: is the length of the word bigger than or equal 6, and is the word containing at least one digit
    """

    is_there_digits = False
    is_there_lowercase_letters = False
    another_check = True

    digits_list = [str(i) for i in range(10)]

    for letter in word:
        if letter in digits_list:
            is_there_digits = True

        if letter.islower():
            is_there_lowercase_letters = True

        if letter == "," or letter == "#":
            another_check = False

    return is_there_digits and is_there_lowercase_letters and another_check and 6 <= len(word) <= 15 and word != ""


def create_login_dictionary(key):
    login_dictionary = {}
    usernames_data = tb.list_of_values(cursor, users_table, "username")
    passwords_data = tb.list_of_values(cursor, users_table, "password")
    id_data = tb.list_of_values(cursor, users_table, "id")
    names_data = tb.list_of_values(cursor, users_table, "name")

    if key == possible_keys[0]:
        for i in range(len(usernames_data)):
            login_dictionary[usernames_data[i]] = (usernames_data[i], passwords_data[i])

    elif key == possible_keys[1]:
        for i in range(len(usernames_data)):
            login_dictionary[passwords_data[i]] = (usernames_data[i], passwords_data[i])

    elif key == possible_keys[2]:
        for i in range(len(usernames_data)):
            login_dictionary[id_data[i]] = (usernames_data[i], passwords_data[i])

    elif key == possible_keys[3]:
        for i in range(len(usernames_data)):
            login_dictionary[names_data[i]] = (usernames_data[i], passwords_data[i])

    return login_dictionary


def create_names_dictionary():
    login_dictionary = {}
    id_data = tb.list_of_values(cursor, users_table, "id")
    names_data = tb.list_of_values(cursor, users_table, "name")

    for i in range(len(id_data)):
        login_dictionary[id_data[i]] = names_data[i]

    return login_dictionary


def create_tasks_dictionary():
    tasks_dictionary = {}
    usernames_data = tb.list_of_values(cursor, tasks_table, "username")
    id_data = tb.list_of_values(cursor, tasks_table, "client_id")

    for i in range(len(id_data)):
        tasks_dictionary[id_data[i]] = usernames_data[i]

    print(tasks_dictionary)
    return tasks_dictionary


def is_match_and_valid_login(username, password):
    login_dictionary = create_login_dictionary(possible_keys[0])
    is_valid = is_syntax_valid(username) and is_syntax_valid(password)
    # print((username, password) not in list(login_dictionary.values()))
    return ((username, ae.md5_hash(password)) not in login_dictionary.values()) or (not is_valid)


def is_already_logged(username, password):
    global logged_users
    global id_dictionary

    usernames_list = tb.list_of_values(cursor, "users", "username")
    passwords_list = tb.list_of_values(cursor, "users", "password")
    id_list = tb.list_of_values(cursor, "users", "id")
    print(id_dictionary)

    for peer_name in logged_users.keys():
        curr_id = id_dictionary[str(peer_name)]
        index = 0
        for i in range(len(id_list)):
            if id_list[i] == curr_id:
                index = i

        curr_username = usernames_list[index]  # connected right now
        curr_password = passwords_list[index]  # connected right now

        if curr_username == username and curr_password == ae.md5_hash(password):
            return True

    return False


def handle_login_message(conn, cmd, msg, client_id):
    """
    Handles the client's request to log in to the app.
    """
    if cmd != chatlib.PROTOCOL_CLIENT['login_msg'] or msg == "":
        if cmd != chatlib.PROTOCOL_CLIENT['login_msg']:
            send_error(conn, chatlib.PROTOCOL_SERVER['login_failed_msg'], "ERROR! The command is not handle-login!")
        else:
            send_error(conn, chatlib.PROTOCOL_SERVER['login_failed_msg'], "ERROR! The message is empty!")

    else:
        username = msg.split("#")[0]
        password = msg.split("#")[1]
        print((username, password))

        if is_match_and_valid_login(username, password) or is_already_logged(username, password):  # send error - for each case
            if is_already_logged(username, password):
                build_and_send_message(conn, chatlib.PROTOCOL_SERVER['login_failed_msg'], "This user is already logged! ")

            elif not(is_syntax_valid(username) and is_syntax_valid(password)):
                build_and_send_message(conn, chatlib.PROTOCOL_SERVER['login_failed_msg'], "The syntax of the message is wrong! At least one digit, one lowercase letter, \n       no comma or hashtag and length between 6 and 15! ")

            else:
                build_and_send_message(conn, chatlib.PROTOCOL_SERVER['login_failed_msg'],
                                       "The user doesn't exist in the system! ")

        else:  # login the user - send login_ok, changing id in relevant tables, add to logged users
            print(f"Sending to the client {conn.getpeername()} LOGIN_OK...")
            logged_users[conn.getpeername()] = conn
            build_and_send_message(conn, chatlib.PROTOCOL_SERVER['login_ok_msg'], "")

            # change id in users, tasks
            print(username)
            name, user_id = tb.return_name_id_by_username(data_base_connection, username)
            known_row = [user_id, name, username, ae.md5_hash(password)]
            print(known_row)

            tb.change_users_row(data_base_connection, "id", client_id, known_row)
            username = create_login_dictionary("id")[client_id][0]
            print("Username: ", username)
            tb.change_tasks_rows_by_username(data_base_connection, "client_id", client_id, client_username=username)

        # add to user table - in register


def handle_register_message(conn, cmd, msg, client_id):
    """
    Handles the client's request to register to the app.
    """
    if cmd != chatlib.PROTOCOL_CLIENT['register_msg'] or msg == "":
        if cmd != chatlib.PROTOCOL_CLIENT['register_msg']:
            send_error(conn, chatlib.PROTOCOL_SERVER['register_failed_msg'], "ERROR! The command is not handle-register!")
        else:
            send_error(conn, chatlib.PROTOCOL_SERVER['register_failed_msg'], "ERROR! The message is empty!")

    else:
        name = msg.split("#")[0]
        username = msg.split("#")[1]
        password = msg.split("#")[2]

        usernames_list = tb.list_of_values(cursor, users_table, "username")

        if not(is_syntax_valid(username) and is_syntax_valid(password)) or username in usernames_list:  # send error - for each case
            if username in usernames_list:
                build_and_send_message(conn, chatlib.PROTOCOL_SERVER['register_failed_msg'],
                                       "Username is taken!")
            else:
                build_and_send_message(conn, chatlib.PROTOCOL_SERVER['register_failed_msg'],
                                       "The syntax of the message is wrong! At least one digit, one lowercase letter, \n       no comma or hashtag and length between 6 and 15! ")

        else:  # login the user - send login_ok, changing id in relevant tables, add to logged users
            print(f"Sending to the client {conn.getpeername()} REGISTER_OK...")
            logged_users[conn.getpeername()] = conn

            encrypted_password = ae.md5_hash(password)
            values_dict = {"id": client_id, "name": name, "username": username, "password": encrypted_password}
            tb.update_users_table(data_base_connection, values_dict)  # add to user table - in register
            build_and_send_message(conn, chatlib.PROTOCOL_SERVER['register_ok_msg'], "")


def send_client_username(conn, cmd, msg, client_id):
    """
    Sends the client it's username
    """
    login_dict = create_login_dictionary("id")
    client_username = login_dict[client_id][0]
    full_msg = client_username
    build_and_send_message(conn, chatlib.PROTOCOL_SERVER['send_username_ok_msg'], full_msg)


def handle_exit_message(conn, cmd, message):
    """
    Logging the client out and deleting the connection with it.
    """

    global logged_users
    print("End the connection with... ", tuple(conn.getpeername()))

    try:
        ready_to_write.remove(conn)
        client_sockets.remove(conn)

        if conn.getpeername() in logged_users.keys():
            del logged_users[conn.getpeername()]

    except OSError:
        print("Not a client anymore!")

    conn.close()


def handle_send_data(conn, cmd, msg, client_id):
    """
    Sends the user (conn) its data
    """
    print("Sending to the client its data... ")

    login_dictionary = create_login_dictionary(possible_keys[2])
    print(login_dictionary)
    (username, password) = login_dictionary[client_id]

    names_dict = create_names_dictionary()
    client_name = names_dict[client_id]

    msg_to_client = "Your data is: \n"
    msg_to_client += "     * Your name is: " + client_name + "\n"
    msg_to_client += "     * Your username is: " + username + "\n"
    build_and_send_message(conn, chatlib.PROTOCOL_SETTINGS_SERVER['see_data_ok_msg'], msg_to_client)


def handle_see_hobbies(conn, cmd, msg, client_id):
    """
    Sends the client (conn) its hobbies
    """
    global hobbies_dictionary

    print("Sending to the client its hobbies... ")
    login_dict = create_login_dictionary("id")
    client_username = login_dict[client_id][0]

    if client_username not in hobbies_dictionary.keys():
        msg_to_client = no_hobbies_see_msg

    else:
        client_hobbies = hobbies_dictionary[client_username]
        data_frame_hobbies = {}
        for i in range(len(client_hobbies)):
            data_frame_hobbies[i + 1] = client_hobbies[i]

        df = pd.DataFrame([data_frame_hobbies])
        df_after_transpose = df.T
        print(df_after_transpose)
        msg_to_client = df_after_transpose.to_json()

    build_and_send_message(conn, chatlib.PROTOCOL_SETTINGS_SERVER['see_hobbies_ok_msg'], msg_to_client)


def handle_add_hobby(conn, cmd, msg, client_id):
    """
    Adds a hobby to the client's hobbies dictionary
    """
    global hobbies_dictionary

    requested_hobby = msg
    print(msg)

    login_dict = create_login_dictionary("id")
    client_username = login_dict[client_id][0]

    # change the key to username (not id) -> when changing username -> change also.

    if requested_hobby == "":
        send_error(conn, chatlib.PROTOCOL_SETTINGS_SERVER['add_hobby_failed_msg'], "Empty hobby is invalid! ")

    if client_username not in hobbies_dictionary.keys():
        hobbies_dictionary[client_username] = []
        hobbies_dictionary[client_username].append(requested_hobby)
        save_hobbies_dictionary(hobbies_dictionary)

    else:
        print((requested_hobby, hobbies_dictionary[client_username]))
        if requested_hobby not in hobbies_dictionary[client_username]:
            hobbies_dictionary[client_username].append(requested_hobby)
            save_hobbies_dictionary(hobbies_dictionary)

        else:  # the hobby already exists in the client's hobbies list
            send_error(conn, chatlib.PROTOCOL_SETTINGS_SERVER['add_hobby_failed_msg'], no_hobby_twice)
            return

    print(hobbies_dictionary)
    full_msg = "The hobby " + requested_hobby + " added successfully! \n"
    build_and_send_message(conn, chatlib.PROTOCOL_SETTINGS_SERVER['add_hobby_ok_msg'], full_msg)


def handle_delete_hobby(conn, cmd, msg, client_id):
    """
    Deletes a hobby from the client's hobbies list.
    """
    requested_hobby_to_delete = msg  # the check is made in the client
    login_dict = create_login_dictionary("id")
    client_username = login_dict[client_id][0]

    if requested_hobby_to_delete not in hobbies_dictionary[client_username]:
        send_error(conn, chatlib.PROTOCOL_SETTINGS_SERVER['delete_hobby_failed_msg'], "The hobby doesn't exist! ")

    else:
        hobbies_dictionary[client_username].remove(requested_hobby_to_delete)
        if hobbies_dictionary[client_username] == []:
            del hobbies_dictionary[client_username]

        save_hobbies_dictionary(hobbies_dictionary)
        full_msg = "The hobby " + requested_hobby_to_delete + " was deleted successfully! \n"
        build_and_send_message(conn, chatlib.PROTOCOL_SETTINGS_SERVER['delete_hobby_ok_msg'], full_msg)

# change name


def handle_change_name(conn, cmd, msg, client_id):
    """
    Checking the username
    """
    if msg == "":
        send_error(conn, chatlib.PROTOCOL_SETTINGS_SERVER['change_name_failed_msg'], "ERROR! The message (aka your name) is empty!")

    else:
        print("Handling the client's message... ")
        # full_msg = "Are you sure (yes/no): \n"
        names_dict = create_names_dictionary()
        curr_name = names_dict[client_id]
        print(curr_name)

        users_row = tb.return_users_row(data_base_connection, client_id).T[0]  # the client_id is only once in the table
        name = str(users_row['name'])
        username = str(users_row['username'])
        password = str(users_row['password'])
        known_row = [client_id, name, username, password]
        print(msg)
        print(known_row)

        tb.change_users_row(data_base_connection, "name", msg, known_row)
        build_and_send_message(conn, chatlib.PROTOCOL_SETTINGS_SERVER['change_name_ok_msg'], "")


def handle_change_password(conn, cmd, msg, client_id):
    """
    Checking the password validity
    """
    if msg == "":
        send_error(conn, chatlib.PROTOCOL_SETTINGS_SERVER['change_password_failed_msg'], "ERROR! The message (aka your password) is empty!")

    else:
        print("Handling the client's message... ")
        if is_syntax_valid(msg):
            # full_msg = "Are you sure (yes/no): \n"
            users_row = tb.return_users_row(data_base_connection, client_id).T[0]

            name = str(users_row['name'])
            username = str(users_row['username'])
            password = str(users_row['password'])
            known_row = [client_id, name, username, password]
            tb.change_users_row(data_base_connection, "password", msg, known_row)

            full_msg = ""
            build_and_send_message(conn, chatlib.PROTOCOL_SETTINGS_SERVER['change_password_ok_msg'], full_msg)

        else:
            full_msg = "Your syntax of your wanted password is incorrect!"
            build_and_send_message(conn, chatlib.PROTOCOL_SETTINGS_SERVER['change_password_failed_msg'], full_msg)


def handle_new_task_message(conn, cmd, message, client_id):
    """
    Receives a client connection (conn), a command (cmd) and a message.
    The function adds (if it should) a new task for the client
    """
    if message == "":
        send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['new_task_failed_msg'], "ERROR! The message is empty!")

    else:
        msg_after_split = message.split("#")
        task_date = msg_after_split[0]
        task_info = msg_after_split[1]

        task_day = task_date.split('/')[0]
        task_month = task_date.split('/')[1]
        task_year = task_date.split('/')[2]

        login_dict = create_login_dictionary(possible_keys[2])
        client_username = login_dict[client_id][0]

        values_dict = {"day": task_day, "month": task_month, "year": task_year, "info": task_info, "did_finish": "0", "client_id": client_id, "username": client_username}
        values_list = [task_day, task_month, task_year, task_info, "0", client_id, client_username]
        does_exist = tb.return_tasks_row(data_base_connection, values_list)
        print(does_exist)

        if "#" in task_info:
            send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['new_task_failed_msg'], "The task's info can't have # (hashtag) ")

        else:
            if does_exist is None:
                # Updating the table
                tb.update_tasks_table(data_base_connection, values_dict)
                full_msg = "The tasks table updated successfully! "
                build_and_send_message(conn, chatlib.PROTOCOL_TASKS_SERVER['new_task_ok_msg'], full_msg)

            else:
                send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['new_task_failed_msg'], no_task_twice)
                return


def handle_tasks_calendar_message(conn, cmd, message, client_id):
    """
    Sends the client (conn) its own tasks calendar.
    """
    tasks_calendar = tb.return_part_of_tasks_by_id(data_base_connection, client_id)  # pandas
    unfinished_tasks = tb.return_unfinished_task_by_id(data_base_connection, client_id)

    print(f"The whole tasks calendar of {client_id}: \n")
    print(tasks_calendar)

    print(f"\nThe unfinished tasks calendar of {client_id}: \n")
    print(unfinished_tasks)

    if tasks_calendar.empty:
        full_msg = no_tasks_see_msg

    else:
        tasks_calendar = tasks_calendar.sort_values(by=['year', 'month', 'day'], ascending=[True, True, True])
        tasks_calendar = tasks_calendar.reset_index(drop=True)
        # msg_part_1 = "Here is your tasks calendar: "
        tasks_calendar_str = tasks_calendar.to_json()

        if unfinished_tasks.empty:
            full_msg = tasks_calendar_str

        else:
            msg_part_1 = tasks_calendar_str

            # sorting
            unfinished_tasks = unfinished_tasks.sort_values(by=['year', 'month', 'day'], ascending=[True, True, True])
            unfinished_tasks = unfinished_tasks.reset_index(drop=True)
            msg_part_2 = unfinished_tasks.to_json()

            full_msg = msg_part_1 + "#" + msg_part_2

    build_and_send_message(conn, chatlib.PROTOCOL_TASKS_SERVER['see_tasks_calendar_ok_msg'], full_msg)


def handle_edit_task(conn, cmd, message, client_id):
    """
    Handles the request properly.
    """
    if message == "":
        send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['edit_task_failed_msg'], "ERROR! The message is empty!")

    else:
        msg_after_split = message.split("#")
        wanted_column = msg_after_split[0]
        wanted_val = msg_after_split[1]
        task_list = msg_after_split[2].split("^")  # the requested task to change
        task_dict = {'day': task_list[0], 'month': task_list[1], 'year': task_list[2], 'info': task_list[3], 'did_finish': task_list[4]}

        known_day = task_dict['day']
        known_month = task_dict['month']
        known_year = task_dict['year']
        known_info = task_dict['info']
        known_did_finish = task_dict['did_finish']

        # client_id and known_username
        known_client_id = client_id
        login_dict = create_login_dictionary("id")
        known_username = login_dict[client_id][0]

        known_row = [known_day, known_month, known_year, known_info, known_did_finish, known_client_id, known_username]
        # print(known_row)

        if wanted_column == "did_finish":
            new_row = [known_day, known_month, known_year, known_info, wanted_val, known_client_id, known_username]
            does_exist = tb.return_tasks_row(data_base_connection, new_row)

            if does_exist is None:
                tb.change_tasks_row(data_base_connection, wanted_column, wanted_val, known_row)
            else:
                send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['edit_task_failed_msg'], no_task_twice)
                return

        if wanted_column == "info":
            new_row = [known_day, known_month, known_year, wanted_val, known_did_finish, known_client_id, known_username]
            does_exist = tb.return_tasks_row(data_base_connection, new_row)

            if does_exist is None:
                tb.change_tasks_row(data_base_connection, wanted_column, wanted_val, known_row)
            else:
                send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['edit_task_failed_msg'], no_task_twice)
                return

        elif wanted_column == "date":
            wanted_day = wanted_val.split('/')[0]
            wanted_month = wanted_val.split('/')[1]
            wanted_year = wanted_val.split('/')[2]

            # first part - what does the client want to change?
            check_dict = {'day different': False, 'month different': False, 'year different': False}
            if wanted_day != known_day:
                check_dict['day different'] = True
            if wanted_month != known_month:
                check_dict['month different'] = True
            if wanted_year != known_year:
                check_dict['year different'] = True

            # The change area - if it can.
            if check_dict['day different'] and check_dict['month different'] and check_dict['year different']:
                curr_row = [wanted_day, wanted_month, wanted_year, known_info, known_did_finish, known_client_id, known_username]
                does_exist = tb.return_tasks_row(data_base_connection, curr_row)

                if does_exist is None:
                    tb.change_tasks_row(data_base_connection, "day", wanted_day, known_row)
                    after_first_edit = [wanted_day, known_month, known_year, known_info, known_did_finish, known_client_id, known_username]

                    tb.change_tasks_row(data_base_connection, "month", wanted_month, after_first_edit)

                    after_second_edit = [wanted_day, wanted_month, known_year, known_info, known_did_finish, known_client_id, known_username]
                    tb.change_tasks_row(data_base_connection, "year", wanted_year, after_second_edit)
                else:
                    send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['edit_task_failed_msg'], no_task_twice)
                    return

            elif check_dict['day different'] and check_dict['month different'] and (not check_dict['year different']):
                curr_row = [wanted_day, wanted_month, known_year, known_info, known_did_finish, known_client_id, known_username]
                does_exist = tb.return_tasks_row(data_base_connection, curr_row)

                if does_exist is None:
                    tb.change_tasks_row(data_base_connection, "day", wanted_day, known_row)
                    after_first_edit = [wanted_day, known_month, known_year, known_info, known_did_finish, known_client_id, known_username]
                    tb.change_tasks_row(data_base_connection, "month", wanted_month, after_first_edit)
                else:
                    send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['edit_task_failed_msg'], no_task_twice)
                    return

            elif check_dict['day different'] and (not check_dict['month different']) and check_dict['year different']:
                curr_row = [wanted_day, known_month, wanted_year, known_info, known_did_finish, known_client_id, known_username]
                does_exist = tb.return_tasks_row(data_base_connection, curr_row)

                if does_exist is None:
                    tb.change_tasks_row(data_base_connection, "day", wanted_day, known_row)
                    after_first_edit = [wanted_day, known_month, known_year, known_info, known_did_finish, known_client_id, known_username]
                    tb.change_tasks_row(data_base_connection, "year", wanted_year, after_first_edit)
                else:
                    send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['edit_task_failed_msg'], no_task_twice)
                    return

            elif (not check_dict['day different']) and check_dict['month different'] and check_dict['year different']:
                curr_row = [known_day, wanted_month, wanted_year, known_info, known_did_finish, known_client_id, known_username]
                does_exist = tb.return_tasks_row(data_base_connection, curr_row)

                if does_exist is None:
                    tb.change_tasks_row(data_base_connection, "month", wanted_month, known_row)
                    after_first_edit = [known_day, wanted_month, known_year, known_info, known_did_finish, known_client_id, known_username]
                    tb.change_tasks_row(data_base_connection, "year", wanted_year, after_first_edit)
                else:
                    send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['edit_task_failed_msg'], no_task_twice)
                    return

            elif (not check_dict['day different']) and (not check_dict['month different']) and check_dict['year different']:
                curr_row = [known_day, known_month, wanted_year, known_info, known_did_finish, known_client_id, known_username]
                does_exist = tb.return_tasks_row(data_base_connection, curr_row)

                if does_exist is None:
                    tb.change_tasks_row(data_base_connection, "year", wanted_year, known_row)
                else:
                    send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['edit_task_failed_msg'], no_task_twice)
                    return

            elif check_dict['day different'] and (not check_dict['month different']) and (not check_dict['year different']):
                curr_row = [wanted_day, known_month, known_year, known_info, known_did_finish, known_client_id, known_username]
                does_exist = tb.return_tasks_row(data_base_connection, curr_row)

                if does_exist is None:
                    tb.change_tasks_row(data_base_connection, "day", wanted_day, known_row)
                else:
                    send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['edit_task_failed_msg'], no_task_twice)
                    return

            elif (not check_dict['day different']) and check_dict['month different'] and (not check_dict['year different']):
                curr_row = [known_day, wanted_month, known_year, known_info, known_did_finish, known_client_id, known_username]
                does_exist = tb.return_tasks_row(data_base_connection, curr_row)

                if does_exist is None:
                    tb.change_tasks_row(data_base_connection, "month", wanted_month, known_row)
                else:
                    send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['edit_task_failed_msg'], no_task_twice)
                    return

        full_msg = "The table tasks changed successfully! "
        build_and_send_message(conn, chatlib.PROTOCOL_TASKS_SERVER['edit_task_ok_msg'], full_msg)


def handle_delete_task(conn, cmd, message, client_id):
    """
    Deletes a task as the client requested.
    """
    if message == "":
        send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['delete_task_failed_msg'], "ERROR! The message is empty!")

    else:
        msg_after_split = message.split("#")
        msg_after_split.append(client_id)
        msg_after_split.append(create_login_dictionary("id")[client_id][0])
        does_task_exist = tb.return_tasks_row(data_base_connection, msg_after_split)
        if does_task_exist is not None:
            tb.delete_tasks_row_using_whole_row(data_base_connection, msg_after_split)
            full_msg = "The task was deleted successfully! "
            build_and_send_message(conn, chatlib.PROTOCOL_TASKS_SERVER['delete_task_ok_msg'], full_msg)
        else:
            send_error(conn, chatlib.PROTOCOL_TASKS_SERVER['delete_task_failed_msg'], "The task doesn't exist! ")


# search area

def handle_search_by_username_message(conn, cmd, message):
    """
    Handles search by username message.
    """
    if cmd != chatlib.PROTOCOL_SEARCH_CLIENT['search_by_username_msg'] or message == "":
        if cmd != chatlib.PROTOCOL_SEARCH_CLIENT['search_by_username_msg']:
            send_error(conn, chatlib.PROTOCOL_SEARCH_SERVER['search_by_username_failed_msg'], "ERROR! The command is not search-by-username")
        else:
            send_error(conn, chatlib.PROTOCOL_SEARCH_SERVER['search_by_username_failed_msg'], "ERROR! The message is empty!")

    else:
        wanted_username = message
        username_data = tb.list_of_values(cursor, users_table, "username")

        if wanted_username not in username_data:
            send_error(conn, chatlib.PROTOCOL_SEARCH_SERVER['search_by_username_failed_msg'], no_username_msg)

        else:
            build_and_send_message(conn, chatlib.PROTOCOL_SEARCH_SERVER['search_by_username_ok_msg'], exist_username_msg)


def are_hobbies_similar(first_hobbies_list, second_hobbies_list):
    """
    Returns if the hobbies list are similar or not.
    params: first_hobbies_list is the first hobbies list
    second_hobbies_list is the second hobbies list.
    """
    hobbies_keys = list(different_hobbies.keys())
    shared_topics = []
    is_similar = False
    similar_hobbies = {}

    first_hobbies_dict = {}
    for hobby_one in first_hobbies_list:
        for key in hobbies_keys:
            if hobby_one in different_hobbies[key]:
                if key not in first_hobbies_dict.keys():
                    first_hobbies_dict[key] = []
                first_hobbies_dict[key].append(hobby_one)

    second_hobbies_dict = {}
    for hobby_two in second_hobbies_list:
        for key in hobbies_keys:
            if hobby_two in different_hobbies[key]:
                if key not in second_hobbies_dict.keys():
                    second_hobbies_dict[key] = []
                second_hobbies_dict[key].append(hobby_two)

    first_keys_list = list(first_hobbies_dict.keys())
    second_keys_list = list(second_hobbies_dict.keys())

    for key in first_keys_list:
        if key in second_keys_list:
            is_similar = True
            shared_topics.append(key)

    if is_similar is False:
        return similar_hobbies, False

    else:
        for key in shared_topics:
            similar_hobbies[key] = []
            for hobby_one in first_hobbies_dict[key]:
                similar_hobbies[key].append(hobby_one)
            for hobby_two in second_hobbies_dict[key]:
                similar_hobbies[key].append(hobby_two)

        for key in similar_hobbies:
            similar_hobbies[key] = list(set(similar_hobbies[key]))

        similar_hobbies_values = []
        for key in similar_hobbies.keys():
            for val in similar_hobbies[key]:
                similar_hobbies_values.append(val)
        final_similar_hobbies_final = {'shared hobbies': similar_hobbies_values}
        return final_similar_hobbies_final, True


def find_similar_clients(client_id):
    """
    Searches for similar clients (in terms of hobbies). client_id is a client's id. Returns a similar usernames list.
    """
    global hobbies_dictionary

    usernames_list = tb.list_of_values(cursor, users_table, "username")  # the usernames_list int the app.
    similar_usernames_list = []

    login_dict = create_login_dictionary("id")
    client_username = login_dict[client_id][0]  # the client's username
    if client_username not in hobbies_dictionary.keys():
        return []

    else:
        client_hobbies_list = hobbies_dictionary[client_username]
        for username in usernames_list:
            if username in hobbies_dictionary.keys() and username != client_username:
                username_hobbies_list = hobbies_dictionary[username]
                similar_hobbies, are_similar = are_hobbies_similar(username_hobbies_list, client_hobbies_list)
                if are_similar:
                    similar_usernames_list.append((username, similar_hobbies)) # adding to the similar usernames list

    return similar_usernames_list


def handle_search_by_hobbies(conn, cmd, message, client_id):
    """
    Handle search by hobbies message.
    The function receives a client conneciton (conn), a command (cmd) and a message (cmd|message was the client's
    message to the server) the function searches for similar clients of the client using it's id and the previous function.
    Meaning, the find_similar_clients function.
    Then, if there aren't any similar client, the function will send [] with failed command.
    Otherwise, the function will send a json string representing the data frame with the similar hobbies usernames.
    """
    similar_usernames_and_hobbies_list = find_similar_clients(client_id)

    if similar_usernames_and_hobbies_list == []:
        full_msg = no_similar_clients_msg
        build_and_send_message(conn, chatlib.PROTOCOL_SEARCH_SERVER['search_by_hobbies_failed_msg'], full_msg)

    else:
        similar_usernames = []
        for username, hobbies in similar_usernames_and_hobbies_list:
            similar_usernames.append(username)

        data_frame_hobbies = {}
        for i in range(len(similar_usernames)):
            data_frame_hobbies[i + 1] = similar_usernames[i]

        df = pd.DataFrame(similar_usernames)
        df_after_transpose = df.T
        full_msg = df_after_transpose.to_json()
        build_and_send_message(conn, chatlib.PROTOCOL_SEARCH_SERVER['search_by_hobbies_ok_msg'], full_msg)


def build_username_data(conn, username, client_id):
    """
    Builds the username's data.
    """
    global hobbies_dictionary

    login_dict = {}
    usernames_list = tb.list_of_values(cursor, users_table, "username")
    names_list = tb.list_of_values(cursor, users_table, "name")

    for i in range(len(names_list)):
        login_dict[usernames_list[i]] = names_list[i]

    client_name = login_dict[username]

    msg_part_1 = "The basic data is: \n"
    msg_part_1 += "\t Name: " + client_name + "\n"
    msg_part_1 += "\t Username is: " + username + "\n"

    login_dict = create_login_dictionary("id")
    client_username = login_dict[client_id][0]

    if client_username not in hobbies_dictionary.keys():
        if username not in hobbies_dictionary.keys():
            msg_part_2 = no_hobbies_see_msg
            msg_part_3 = "You both don't have hobbies so there are no common hobbies! "
        else:
            client_hobbies = hobbies_dictionary[username]
            data_frame_hobbies = {}
            for i in range(len(client_hobbies)):
                data_frame_hobbies[i + 1] = client_hobbies[i]

            df = pd.DataFrame([data_frame_hobbies])
            df_after_transpose = df.T
            msg_part_2 = df_after_transpose.to_json()  # hobbies

            msg_part_3 = f"You don't have hobbies and {username} has so there are no common hobbies! "

    else:
        if username not in hobbies_dictionary.keys():
            msg_part_2 = no_hobbies_see_msg
            msg_part_3 = f"You have hobbies and {username} doesn't so there are no common hobbies! "

        else:
            client_hobbies = hobbies_dictionary[username]
            data_frame_hobbies = {}
            for i in range(len(client_hobbies)):
                data_frame_hobbies[i + 1] = client_hobbies[i]

            df = pd.DataFrame([data_frame_hobbies])
            df_after_transpose = df.T
            msg_part_2 = df_after_transpose.to_json()  # hobbies

            similar_hobbies, are_similar = are_hobbies_similar(client_hobbies, hobbies_dictionary[client_username])
            if username == client_username:
                msg_part_3 = no_self_similar_hobbies

            else:
                if not are_similar:
                    msg_part_3 = no_similar_hobbies_msg

                else:
                    similar_hobbies_df = pd.DataFrame(similar_hobbies)
                    # similar_hobbies_df_after_transpose = similar_hobbies_df.T
                    msg_part_3 = similar_hobbies_df.to_json()  # hobbies

    return msg_part_1, msg_part_2, msg_part_3


def are_they_friends(user1, user2):
    """
    Checking if user1 and user2 are friends in the app.
    """
    global friendships_dictionary

    check = False
    if user1 in friendships_dictionary:
        if user2 in friendships_dictionary[user1]:
            check = True

    return check


def did_already_send(user1, user2):
    """
    Checks whether user1 can send a friendship request to user2 or not.
    """
    check = True
    global friendships_requests_dictionary

    # checks if had user1 been already sent user2 a friendship request.
    if user2 in friendships_requests_dictionary.keys():
        if user1 in friendships_requests_dictionary[user2]:
            check = False

    return check


def handle_send_username_data(conn, cmd, message, client_id):
    """
    Sends the client (conn) the username (=message) data.
    """
    global hobbies_dictionary
    global friendships_dictionary

    # index: 0-> search by username, 1 -> search by hobbies, 2 -> friendship requests, 3 -> profile -> friends
    print("Sending to the client his data... ")
    msg_after_split = message.split("#")
    username = msg_after_split[1]
    str_index = msg_after_split[0]
    index = str_index

    print(index == '5')

    msg_part_1, msg_part_2, msg_part_3 = build_username_data(conn, username, client_id)

    login_dict = create_login_dictionary("id")
    client_username = login_dict[client_id][0]
    msg_part_4 = ""

    if index == search_by_username_index or index == search_by_hobbies_index:  # index = '0' or index = '1'
        if username == client_username:
            msg_part_4 = cant_send_self_friendship_request

        else:
            friend_check = are_they_friends(client_username, username)
            already_send_check = did_already_send(client_username, username)

            if friend_check or (not already_send_check):
                if friend_check:
                    msg_part_4 = f"You and {username} are already friends in the app! "

                else:
                    msg_part_4 = f"You already sent {username} a friendship request in the app! "

    full_msg = msg_part_1 + "#" + msg_part_2 + "#" + msg_part_3 + "#" + msg_part_4
    build_and_send_message(conn, chatlib.PROTOCOL_SEARCH_SERVER['username_data_ok_msg'], full_msg)


def handle_send_friendship_request_message(conn, cmd, message, client_id):
    """
    Sends the client with the given username a friendship request from conn
    """
    global friendships_requests_dictionary

    if cmd != chatlib.PROTOCOL_SEARCH_CLIENT['send_friendship_request_msg'] or message == "":
        if cmd != chatlib.PROTOCOL_SEARCH_CLIENT['send_friendship_request_msg']:
            send_error(conn, chatlib.PROTOCOL_SEARCH_SERVER['send_friendship_request_failed_msg'], "ERROR! The command is not send-friendship-request-msg")
        else:
            send_error(conn, chatlib.PROTOCOL_SEARCH_SERVER['send_friendship_request_failed_msg'], "ERROR! The message is empty!")

    else:
        username_to_send = message
        login_dict = create_login_dictionary("id")
        client_username = login_dict[client_id][0]

        if username_to_send == client_username:
            send_error(conn, chatlib.PROTOCOL_SEARCH_SERVER['send_friendship_request_failed_msg'], cant_send_self_friendship_request)
            return

        else:
            friend_check = are_they_friends(client_username, username_to_send)
            already_send_check = did_already_send(client_username, username_to_send)

            if not friend_check and already_send_check:  # they are not friends in the app
                if username_to_send not in friendships_requests_dictionary.keys():
                    friendships_requests_dictionary[username_to_send] = []
                friendships_requests_dictionary[username_to_send].append(client_username)
                save_friendships_requests_dictionary(friendships_requests_dictionary)
                full_msg = "The friendship request to " + message + " was sent successfully!"
                build_and_send_message(conn, chatlib.PROTOCOL_SEARCH_SERVER['send_friendship_request_ok_msg'], full_msg)

            else:
                if friend_check:
                    send_error(conn, chatlib.PROTOCOL_SEARCH_SERVER['send_friendship_request_failed_msg'], f"You and {username_to_send} are already friends in the app! ")
                    return
                else:
                    send_error(conn, chatlib.PROTOCOL_SEARCH_SERVER['send_friendship_request_failed_msg'], f"You already sent {username_to_send} a friendship request in the app! ")
                    return


def handle_see_friendship_requests(conn, cmd, message, client_id):
    """
    Sends the client its friendship requests.
    """
    global friendships_requests_dictionary

    if cmd != chatlib.PROTOCOL_CLIENT['see_friendship_requests_msg'] or message != "":
        if cmd != chatlib.PROTOCOL_CLIENT['see_friendship_requests_msg']:
            send_error(conn, chatlib.PROTOCOL_SERVER['see_friendship_requests_failed_msg'], "ERROR! The command is not see-friendship-requests-msg")
        else:
            send_error(conn, chatlib.PROTOCOL_SERVER['see_friendship_requests_failed_msg'], "ERROR! The message is not empty!")

    else:
        login_dict = create_login_dictionary("id")
        client_username = login_dict[client_id][0]

        if client_username not in friendships_requests_dictionary.keys():
            msg_part_1 = no_friendship_requests

        else:
            friendship_requests_sent = friendships_requests_dictionary[client_username]
            friendship_requests_dict = {}
            for i in range(len(friendship_requests_sent)):
                friendship_requests_dict[i + 1] = friendship_requests_sent[i]

            friendship_requests_data_frame = pd.DataFrame([friendship_requests_dict])
            friendship_requests_data_frame_after_transpose = friendship_requests_data_frame.T
            msg_part_1 = friendship_requests_data_frame_after_transpose.to_json()

        full_msg = msg_part_1
        build_and_send_message(conn, chatlib.PROTOCOL_SERVER['see_friendship_requests_ok_msg'], full_msg)


def handle_approve_friendship_request(conn, cmd, message, client_id):
    """
    Handling the request of the client to approve the request for friendship.
    """
    global friendships_requests_dictionary
    global friendships_dictionary

    if cmd != chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_CLIENT['approve_friendship_request_msg'] or message == "":
        if cmd != chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_CLIENT['approve_friendship_request_msg']:
            send_error(conn, chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_SERVER['approve_friendship_request_failed_msg'], "ERROR! The command is not approve-friendship-request-msg")
        else:
            send_error(conn, chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_SERVER['approve_friendship_request_failed_msg'], "ERROR! The message is empty!")

    else:
        username_to_approve = message
        login_dict = create_login_dictionary("id")
        client_username = login_dict[client_id][0]

        if client_username not in friendships_requests_dictionary.keys():
            send_error(conn, chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_SERVER['approve_friendship_request_failed_msg'], "The friendship request doesn't exist anymore")
            return

        else:
            if username_to_approve not in friendships_requests_dictionary[client_username]:
                send_error(conn, chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_SERVER['approve_friendship_request_failed_msg'], "The friendship request doesn't exist anymore")
                return

            else:
                friendships_requests_dictionary[client_username].remove(username_to_approve)
                if friendships_requests_dictionary[client_username] == []:
                    del friendships_requests_dictionary[client_username]

                if username_to_approve in friendships_requests_dictionary.keys():
                    if client_username in friendships_requests_dictionary[username_to_approve]:
                        friendships_requests_dictionary[username_to_approve].remove(client_username)
                        if friendships_requests_dictionary[username_to_approve] == []:
                            del friendships_requests_dictionary[username_to_approve]

                if client_username not in friendships_dictionary.keys():
                    friendships_dictionary[client_username] = []

                if username_to_approve not in friendships_dictionary.keys():
                    friendships_dictionary[username_to_approve] = []

                friendships_dictionary[client_username].append(username_to_approve)
                friendships_dictionary[username_to_approve].append(client_username)

                save_friendships_requests_dictionary(friendships_requests_dictionary)
                save_friendships_dictionary(friendships_dictionary)

                msg_part_1 = f"The request for friendship from {username_to_approve} was approved successfully!"

                full_msg = msg_part_1
                build_and_send_message(conn, chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_SERVER['approve_friendship_request_ok_msg'], full_msg)


def handle_reject_friendship_request(conn, cmd, message, client_id):
    """
    Handling the request of the client to reject the request for friendship.
    """
    global friendships_requests_dictionary
    global friendships_dictionary

    if cmd != chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_CLIENT['reject_friendship_request_msg'] or message == "":
        if cmd != chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_CLIENT['reject_friendship_request_msg']:
            send_error(conn, chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_SERVER['reject_friendship_request_failed_msg'], "ERROR! The command is not reject-friendship-request-msg")
        else:
            send_error(conn, chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_SERVER['reject_friendship_request_failed_msg'], "ERROR! The message is empty!")

    else:
        username_to_approve = message
        login_dict = create_login_dictionary("id")
        client_username = login_dict[client_id][0]

        if client_username not in friendships_requests_dictionary.keys():
            send_error(conn, chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_SERVER['reject_friendship_request_failed_msg'], "The friendship request doesn't exist anymore")
            return

        else:
            if username_to_approve not in friendships_requests_dictionary[client_username]:
                send_error(conn, chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_SERVER['reject_friendship_request_failed_msg'], "The friendship request doesn't exist anymore")
                return

            else:
                friendships_requests_dictionary[client_username].remove(username_to_approve)
                if friendships_requests_dictionary[client_username] == []:
                    del friendships_requests_dictionary[client_username]
                save_friendships_requests_dictionary(friendships_requests_dictionary)

                msg_part_1 = f"The request for friendship with {username_to_approve} was rejected successfully!"
                full_msg = msg_part_1
                build_and_send_message(conn, chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_SERVER['reject_friendship_request_ok_msg'], full_msg)


# profile area

def handle_profile_message(conn, cmd, message, client_id):
    """
    Handling the request of the client to go to the profile area.
    """
    if cmd != chatlib.PROTOCOL_CLIENT['profile_msg'] or message != "":
        if cmd != chatlib.PROTOCOL_CLIENT['profile_msg']:
            send_error(conn, chatlib.PROTOCOL_SERVER['profile_failed_msg'], "ERROR! The command is not profile-msg")
        else:
            send_error(conn, chatlib.PROTOCOL_SERVER['profile_failed_msg'], "ERROR! The message is not empty!")

    login_dict = create_login_dictionary("id")
    client_username = login_dict[client_id][0]
    first_msg, second_msg, third_msg = build_username_data(conn, client_username, client_id)

    full_msg = first_msg + "#" + second_msg
    build_and_send_message(conn, chatlib.PROTOCOL_SERVER['profile_ok_msg'], full_msg)
    return f"sent the user {conn.getpeername()} its options"


def handle_see_friends_message(conn, cmd, message, client_id):
    """
    Handles the request of the client to see his friends list.
    """
    global friendships_dictionary

    login_dict = create_login_dictionary("id")
    client_username = login_dict[client_id][0]

    if client_username not in friendships_dictionary.keys():
        msg_part_1 = no_friends

    else:
        friends_list = friendships_dictionary[client_username]
        friendship_requests_dict = {}
        for i in range(len(friends_list)):
            friendship_requests_dict[i + 1] = friends_list[i]

        friendship_requests_data_frame = pd.DataFrame([friendship_requests_dict])
        friendship_requests_data_frame_after_transpose = friendship_requests_data_frame.T
        msg_part_1 = friendship_requests_data_frame_after_transpose.to_json()

    full_msg = msg_part_1
    build_and_send_message(conn, chatlib.PROTOCOL_PROFILE_SERVER['see_friends_ok_msg'], full_msg)


def change_share_diary_outgoing_requests(addresser_username, username_to_delete):
    """
    Deleted username_to_delete from the recipients list of all the share diary requests that addresser_username sent.
    :param addresser_username: a client's username.
    :param username_to_delete: another client's username.
    """

    all_requesters = tb.list_of_values(cursor, diaries_sharing_requests_table, "addresser")
    print(all_requesters)

    if addresser_username in all_requesters:
        all_client_requests = tb.return_all_client_outgoing_share_diary_requests(data_base_connection,
                                                                                 addresser_username)
        for index in range(all_client_requests.shape[0]):
            specific_addresser_username_request = all_client_requests.iloc[index]
            print(specific_addresser_username_request)
            request_recipients = str(specific_addresser_username_request['recipients'])
            request_recipients_list = request_recipients.split(", ")
            print(request_recipients_list)

            if username_to_delete in request_recipients_list:
                new_request_recipients_list = [recipient for recipient in request_recipients_list if
                                               recipient != username_to_delete]
                print(new_request_recipients_list)
                new_recipients = ""
                for i in range(len(new_request_recipients_list)):
                    recipient = new_request_recipients_list[i]
                    new_recipients += recipient
                    if i < len(new_request_recipients_list) - 1:
                        new_recipients += ", "

                request_info = str(specific_addresser_username_request['info'])
                if new_recipients == "":
                    print(request_info)
                    tb.delete_diaries_sharing_requests_row(data_base_connection, request_info)
                    info_dictionary[info_dictionary_key].remove(request_info)
                    save_info_dictionary(info_dictionary)
                    return

                else:
                    tb.change_recipients_situation_share_diary_requests(data_base_connection, request_info, new_recipients)


def change_share_diary_groups(addresser_username, username_to_delete):
    """
    Deleted username_to_delete from the recipients list of all the share diary groups where addresser_username is the addresser.
    :param addresser_username: a client's username.
    :param username_to_delete: another client's username.
    """
    global info_dictionary
    all_requesters = tb.list_of_values(cursor, diaries_sharing_table, "addresser")
    print(all_requesters)
    if addresser_username in all_requesters:
        all_groups_client_manages = tb.return_all_share_diary_groups_client_username_manages(data_base_connection,
                                                                                 addresser_username)
        for index in range(all_groups_client_manages.shape[0]):
            specific_addresser_username_group = all_groups_client_manages.iloc[index]
            request_recipients = str(specific_addresser_username_group['recipients'])
            request_recipients_list = request_recipients.split(", ")

            if username_to_delete in request_recipients_list:
                new_request_recipients_list = [recipient for recipient in request_recipients_list if
                                               recipient != username_to_delete]
                new_recipients = ""
                for i in range(len(new_request_recipients_list)):
                    recipient = new_request_recipients_list[i]
                    new_recipients += recipient
                    if i < len(new_request_recipients_list) - 1:
                        new_recipients += ", "

                request_info = str(specific_addresser_username_group['info'])
                if new_recipients == "":
                    print(request_info)
                    tb.delete_diaries_sharing_groups_row(data_base_connection, request_info)
                    info_dictionary[info_dictionary_key].remove(request_info)
                    save_info_dictionary(info_dictionary)
                    return

                else:
                    tb.change_recipients_situation_share_diary_groups(data_base_connection, request_info, new_recipients)


def handle_delete_friend_message(conn, cmd, message, client_id):
    """
    Handles the request of the client to delete existing friend.
    """
    global friendships_dictionary

    login_dict = create_login_dictionary("id")
    client_username = login_dict[client_id][0]
    wanted_username = message

    print(f"Deleting {wanted_username} from being {client_username} friend ... ")
    if wanted_username not in friendships_dictionary.keys():
        send_error(conn, chatlib.PROTOCOL_PROFILE_SERVER['delete_friend_failed_msg'], "You are not friends in the app anymore! ")

    else:
        if client_username not in friendships_dictionary[wanted_username]:
            send_error(conn, chatlib.PROTOCOL_PROFILE_SERVER['delete_friend_failed_msg'], "You are not friends in the app anymore! ")

        else:
            friendships_dictionary[client_username].remove(wanted_username)
            friendships_dictionary[wanted_username].remove(client_username)  # friendship goes both ways

            if friendships_dictionary[client_username] == []:
                del friendships_dictionary[client_username]

            if friendships_dictionary[wanted_username] == []:
                del friendships_dictionary[wanted_username]

            save_friendships_dictionary(friendships_dictionary)

            # Share diary requests update
            change_share_diary_outgoing_requests(client_username, wanted_username)
            change_share_diary_outgoing_requests(wanted_username, client_username)

            # Share diary groups update
            change_share_diary_groups(client_username, wanted_username)
            change_share_diary_groups(wanted_username, client_username)

            full_msg = f"{wanted_username} was deleted successfully from your friends list! "
            build_and_send_message(conn, chatlib.PROTOCOL_PROFILE_SERVER['delete_friend_ok_msg'], full_msg)


def handle_see_pending_outgoing_requests(conn, cmd, message, client_id):
    """
    Handles the request of the client to see it's pending outgoing requests.
    """
    global friendships_requests_dictionary

    login_dict = create_login_dictionary("id")
    client_username = login_dict[client_id][0]

    requested_list = []
    for username in friendships_requests_dictionary.keys():
        if client_username in friendships_requests_dictionary[username]:
            requested_list.append(username)

    if requested_list != []:
        pending_outgoing_requests = {}
        for i in range(len(requested_list)):
            pending_outgoing_requests[i + 1] = requested_list[i]

        friendship_requests_data_frame = pd.DataFrame([pending_outgoing_requests])
        friendship_requests_data_frame_after_transpose = friendship_requests_data_frame.T
        msg_part_1 = friendship_requests_data_frame_after_transpose.to_json()

    else:
        msg_part_1 = no_pending_outgoing_requests

    full_msg = msg_part_1
    build_and_send_message(conn, chatlib.PROTOCOL_PROFILE_SERVER['see_pending_outgoing_requests_ok_msg'], full_msg)


def handle_delete_friendship_request(conn, cmd, message, client_id):
    """
    Handles the request of the client to delete a user from his pending outgoing requests
    """
    global friendships_requests_dictionary

    if cmd != chatlib.PROTOCOL_PROFILE_CLIENT['delete_friendship_request_msg'] or message == "":
        if cmd != chatlib.PROTOCOL_PROFILE_CLIENT['delete_friendship_request_msg']:
            send_error(conn, chatlib.PROTOCOL_PROFILE_SERVER['delete_friendship_request_failed_msg'], "ERROR! The command is not delete-friendship-request-msg")
        else:
            send_error(conn, chatlib.PROTOCOL_PROFILE_SERVER['delete_friendship_request_failed_msg'], "ERROR! The message is empty!")

    else:
        login_dict = create_login_dictionary("id")
        client_username = login_dict[client_id][0]
        wanted_username = message

        if wanted_username not in friendships_requests_dictionary.keys():
            send_error(conn, chatlib.PROTOCOL_PROFILE_SERVER['delete_friendship_request_failed_msg'], "The friendship request doesn't exist anymore! ")

        else:
            if client_username not in friendships_requests_dictionary[wanted_username]:
                send_error(conn, chatlib.PROTOCOL_PROFILE_SERVER['delete_friendship_request_failed_msg'], "The friendship request doesn't exist anymore! ")

            else:
                friendships_requests_dictionary[wanted_username].remove(client_username)  # removing ...
                if friendships_requests_dictionary[wanted_username] == []:
                    del friendships_requests_dictionary[wanted_username]
                save_friendships_requests_dictionary(friendships_requests_dictionary)

                msg_part_1 = f"{wanted_username} was deleted successfully from your friends requests list! "
                full_msg = msg_part_1
                build_and_send_message(conn, chatlib.PROTOCOL_PROFILE_SERVER['delete_friendship_request_ok_msg'], full_msg)


# shared diaries area

def handle_shared_diaries_message(conn, cmd, message, client_id):
    """
    Handles the client's request to go to the shared diaries' area.
    """
    global friendships_dictionary

    if cmd != chatlib.PROTOCOL_CLIENT['shared_diaries_msg'] or message != "":
        if cmd != chatlib.PROTOCOL_CLIENT['shared_diaries_msg']:
            send_error(conn, chatlib.PROTOCOL_SERVER['shared_diaries_failed_msg'], "ERROR! The command is not shared-diaries-msg")
        else:
            send_error(conn, chatlib.PROTOCOL_SERVER['shared_diaries_failed_msg'], "ERROR! The message is not empty!")

    else:
        login_dict = create_login_dictionary("id")
        client_username = login_dict[client_id][0]

        if client_username not in friendships_dictionary.keys():
            full_msg = no_friends

        else:
            full_msg = "You have friends in the app! "

        build_and_send_message(conn, chatlib.PROTOCOL_SERVER['shared_diaries_ok_msg'], full_msg)
        return f"sent the user {conn.getpeername()} its options"


def handle_shared_diaries_outgoing_requests_msg(conn, cmd, message, client_id):
    """
    Handles the request of the client to go to its outgoing requests area, in the shared diaries page.
    """
    global friendships_dictionary

    login_dict = create_login_dictionary("id")
    client_username = login_dict[client_id][0]
    all_requesters = tb.list_of_values(cursor, diaries_sharing_requests_table, "addresser")
    # the user not necessarily has friends in the app.

    if client_username not in friendships_dictionary.keys():
        failed_cmd = chatlib.PROTOCOL_SHARED_DIARIES_SERVER['outgoing_share_diary_requests_failed_msg']
        build_and_send_message(conn, failed_cmd, no_friends)
        return

    else:
        if client_username not in all_requesters:  # the user haven't sent any request yet
            msg_part_1 = no_outgoing_requests_to_share_diaries

            friends_list = friendships_dictionary[client_username]
            friendship_requests_dict = {}
            for i in range(len(friends_list)):
                friendship_requests_dict[i + 1] = friends_list[i]

            friendship_requests_data_frame = pd.DataFrame([friendship_requests_dict])
            friendship_requests_data_frame_after_transpose = friendship_requests_data_frame.T
            msg_part_2 = friendship_requests_data_frame_after_transpose.to_json()
            full_msg = msg_part_1 + "#" + msg_part_2


        else:
            msg_part_1 = "You have already sent requests to share your diary! "

            friends_list = friendships_dictionary[client_username]
            friendship_requests_dict = {}
            for i in range(len(friends_list)):
                friendship_requests_dict[i + 1] = friends_list[i]

            friendship_requests_data_frame = pd.DataFrame([friendship_requests_dict])
            friendship_requests_data_frame_after_transpose = friendship_requests_data_frame.T
            msg_part_2 = friendship_requests_data_frame_after_transpose.to_json()

            all_client_requests = tb.return_all_client_outgoing_share_diary_requests(data_base_connection, client_username)
            msg_part_3 = all_client_requests.to_json()
            full_msg = msg_part_1 + "#" + msg_part_2 + "#" + msg_part_3

        returned_cmd = chatlib.PROTOCOL_SHARED_DIARIES_SERVER['outgoing_share_diary_requests_ok_msg']
        build_and_send_message(conn, returned_cmd, full_msg)


def handle_new_share_diary_request(conn, cmd, message, client_id):
    """
    Handles the request of the client to send a request to share diaries,
    adds the request to the appropriate table.
    """
    import datetime

    if cmd != chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['new_share_diary_request_msg'] or message == "":
        if cmd != chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['new_share_diary_request_msg']:
            e = "ERROR! The command is not new-share-diary-request-msg"
            send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['new_share_diary_request_failed_msg'], e)
        else:
            send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['new_share_diary_request_failed_msg'], "ERROR! The message is empty!")

    else:
        client_username = create_login_dictionary("id")[client_id][0]

        msg_after_split = message.split("#")
        usernames_msg_str = msg_after_split[0]
        theme_msg = msg_after_split[1]
        info_msg = msg_after_split[2]
        time_msg = msg_after_split[3]

        print(usernames_msg_str)
        usernames_list = usernames_msg_str.split("$")

        final_usernames_msg = ""
        for i in range(len(usernames_list)):
            final_usernames_msg += usernames_list[i]
            if i < len(usernames_list) - 1:
                final_usernames_msg += ", "

        if client_username not in friendships_dictionary.keys():
            send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['new_share_diary_request_failed_msg'], no_adding_these_friends)
            return

        client_friends = friendships_dictionary[client_username]
        usernames_list = [friend for friend in final_usernames_msg.split(", ") if friend in client_friends]

        if usernames_list != []:
            last_day = str(time_msg.split("$")[0])
            last_month = str(time_msg.split("$")[1])
            last_year = str(time_msg.split("$")[2])
            last_date = last_day + "/" + last_month + "/" + last_year

            today = datetime.date.today()
            curr_day = str(today.day)
            curr_month = str(today.month)
            curr_year = str(today.year)
            curr_date = curr_day + "/" + curr_month + "/" + curr_year

            # dates_range = (curr_date, last_date)
            dates_range_str = curr_date + " -> " + last_date

            approvals_str = ""
            for i in range(len(usernames_list)):
                approvals_str += "-1"
                if i < len(usernames_list) - 1:
                    approvals_str += ", "

            login_dict = create_login_dictionary("id")
            client_username = login_dict[client_id][0]

            final_username_msg_str = ""
            for i in range(len(usernames_list)):
                final_username_msg_str += usernames_list[i]
                if i < len(usernames_list) - 1:
                    final_username_msg_str += ", "

            is_request_ok = True
            if info_dictionary_key in info_dictionary.keys():
                if info_msg in info_dictionary[info_dictionary_key]:
                    is_request_ok = False

            final_list_request = [client_username, final_username_msg_str, dates_range_str, approvals_str, theme_msg, info_msg]

            if is_request_ok:
                # add to the info json file
                if info_dictionary_key not in info_dictionary.keys():
                    info_dictionary[info_dictionary_key] = []
                info_dictionary[info_dictionary_key].append(info_msg)
                save_info_dictionary(info_dictionary)

                tb.update_diaries_sharing_requests_table(data_base_connection, final_list_request)
                msg_part_1 = "Only your remaining friends from the list were invited to the group! "

                full_msg = msg_part_1
                curr_cmd = chatlib.PROTOCOL_SHARED_DIARIES_SERVER['new_share_diary_request_ok_msg']
                build_and_send_message(conn, curr_cmd, full_msg)

            else:
                send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['new_share_diary_request_failed_msg'], no_diaries_sharing_request_twice)
                return

        else:  # check friends
            send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['new_share_diary_request_failed_msg'], no_adding_these_friends)


def handle_shared_diaries_ingoing_requests_msg(conn, cmd, message, client_id):
    """
    Sends the client its ingoing requests, as he requested.
    """

    login_dict = create_login_dictionary("id")
    client_username = login_dict[client_id][0]
    ingoing_requests = tb.all_client_ingoing_share_diary_requests(data_base_connection, client_username)

    if not ingoing_requests.empty:
        msg_part_1 = ingoing_requests.to_json()

    else:
        msg_part_1 = no_ingoing_requests_to_share_diaries

    full_msg = msg_part_1
    curr_cmd = chatlib.PROTOCOL_SHARED_DIARIES_SERVER['ingoing_share_diary_requests_ok_msg']
    build_and_send_message(conn, curr_cmd, full_msg)


def handle_approve_share_diary_request(conn, cmd, message, client_id):
    """
    Approves a share diary request, as the client requested.
    """
    if cmd != chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['approve_share_diary_request_msg'] or message == "":
        if cmd != chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['approve_share_diary_request_msg']:
            e = "ERROR! The command is not approve-share-diary-request-msg"
            send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['approve_share_diary_request_failed_msg'], e)
        else:
            send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['approve_share_diary_request_failed_msg'], "ERROR! The message is empty!")

    else:
        request_info = message.split("#")[-1]
        specific_request = tb.return_diaries_sharing_requests_row(data_base_connection, request_info)
        if specific_request is None:
            send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['approve_share_diary_request_failed_msg'], request_doesnt_exist)
            return

        else:
            client_username = create_login_dictionary("id")[client_id][0]
            request_addresser = str(specific_request['addresser'][0])
            request_recipients = str(specific_request['recipients'][0])
            request_dates_range = str(specific_request['dates_range'][0])
            request_theme = str(specific_request['theme'][0])
            request_info = str(specific_request['info'][0])

            approval_situation = str(specific_request['approvals'][0]).split(", ")
            recipients_list = request_recipients.split(", ")

            if client_username in recipients_list:
                place = recipients_list.index(client_username)
                if approval_situation[place] == "1":
                    build_and_send_message(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['approve_share_diary_request_failed_msg'], "You already approved the request! ")

                else:
                    approval_situation[place] = "1"
                    tb.change_approval_situation(data_base_connection, request_info, place, "1")
                    msg_part_1 = "The table changed successfully! "
                    print(approval_situation)

                    if all(approval_situation[i] == "1" for i in range(len(approval_situation))):
                        # delete row -> add to groups
                        print(request_info)
                        tb.delete_diaries_sharing_requests_row(data_base_connection, request_info)
                        new_values_groups_list = [request_addresser, request_recipients, request_dates_range, request_theme, request_info]

                        tb.update_diaries_sharing_groups_table(data_base_connection, new_values_groups_list)
                        msg_part_1 += "\n       All the recipients approved the request so a new group is now opened! \n"

                    full_msg = msg_part_1
                    curr_cmd = chatlib.PROTOCOL_SHARED_DIARIES_SERVER['approve_share_diary_request_ok_msg']
                    build_and_send_message(conn, curr_cmd, full_msg)

            else:
                send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['approve_share_diary_request_failed_msg'], request_doesnt_exist)


def handle_reject_share_diary_request(conn, cmd, message, client_id):
    """
    Rejects a share diary request, as the client requested.
    """
    global info_dictionary

    if cmd != chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['reject_share_diary_request_msg'] or message == "":
        if cmd != chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['reject_share_diary_request_msg']:
            e = "ERROR! The command is not reject-share-diary-request-msg"
            send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['reject_share_diary_request_failed_msg'], e)
        else:
            send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['reject_share_diary_request_failed_msg'], "ERROR! The message is empty!")

    else:
        client_username = create_login_dictionary("id")[client_id][0]
        msg_after_split = message.split("#")
        request_info = msg_after_split[-1]

        specific_request = tb.return_diaries_sharing_requests_row(data_base_connection, request_info)
        if specific_request is None:
            send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['reject_share_diary_request_failed_msg'], request_doesnt_exist)
            return

        else:
            approval_situation = str(specific_request['approvals'][0]).split(", ")
            recipients_list = str(specific_request['recipients'][0]).split(", ")

            if client_username in recipients_list:
                place = recipients_list.index(client_username)

                new_approval_situation = ""
                for i in range(len(approval_situation)):
                    if i != place:
                        new_approval_situation += approval_situation[i]
                        if i < len(recipients_list) - 1:
                            new_approval_situation += ", "

                new_recipients = ""
                for i in range(len(recipients_list)):
                    if i != place:
                        new_recipients += recipients_list[i]
                        if i < len(recipients_list) - 1:
                            new_recipients += ", "

                tb.delete_approvals_val(data_base_connection, request_info, new_approval_situation)
                tb.change_recipients_situation_share_diary_requests(data_base_connection, request_info, new_recipients)
                msg_part_1 = "The table was changed successfully! "

                if len(recipients_list) == 1:
                    # delete request
                    print(request_info)
                    tb.delete_diaries_sharing_requests_row(data_base_connection, request_info)
                    info_dictionary[info_dictionary_key].remove(request_info)
                    save_info_dictionary(info_dictionary)
                    msg_part_1 += "\nAll the recipients declined the request so the request was deleted! \n"

                full_msg = msg_part_1
                curr_cmd = chatlib.PROTOCOL_SHARED_DIARIES_SERVER['reject_share_diary_request_ok_msg']
                build_and_send_message(conn, curr_cmd, full_msg)

            else:
                send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['reject_share_diary_request_failed_msg'], request_doesnt_exist)


# see shared diaries area

def handle_see_shared_diaries_groups_message(conn, cmd, message, client_id):
    """
    Handles the client's request to see it's shared diaries.
    """
    login_dict = create_login_dictionary("id")
    client_username = login_dict[client_id][0]
    all_groups = tb.return_all_share_diary_groups_containing_client(data_base_connection, client_username)

    if all_groups is not None:
        msg_part_1 = all_groups.to_json()

    else:
        msg_part_1 = no_shared_diaries_groups_to_share_diaries

    full_msg = msg_part_1
    curr_cmd = chatlib.PROTOCOL_SHARED_DIARIES_SERVER['see_shared_diaries_groups_ok_msg']
    build_and_send_message(conn, curr_cmd, full_msg)


def handle_see_specific_shared_diaries_group_message(conn, cmd, message, client_id):
    """
    Sends the client the specific shared diaries group.
    """
    if cmd != chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['see_specific_shared_diaries_group_msg'] or message == "":
        if cmd != chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['see_specific_shared_diaries_group_msg']:
            e = "ERROR! The command is not see-specific-shared-diaries-group-msg"
            send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['see_specific_shared_diaries_group_failed_msg'], e)
        else:
            send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['see_specific_shared_diaries_group_failed_msg'], "ERROR! The message is empty!")

    else:
        client_username = create_login_dictionary("id")[client_id][0]
        group_info = message
        specific_group = tb.return_diaries_sharing_groups_row(data_base_connection, group_info)
        if specific_group is None:
            send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['see_specific_shared_diaries_group_failed_msg'], group_doesnt_exist)
            return
        else:
            group_manager = str(specific_group['addresser'][0])
            group_recipients = str(specific_group['recipients'][0]).split(", ")

            if client_username in group_recipients or client_username == group_manager:
                msg_part_1 = specific_group.to_json()   # first msg - basic data about the group

                # second msg - the shared diary
                usernames_list = [group_manager]
                for recipient in group_recipients:
                    usernames_list.append(recipient)
                shared_diary = tb.return_parts_of_tasks_groups(data_base_connection, usernames_list)

                # sorting
                sorted_shared_diary = shared_diary.sort_values(by=['year', 'month', 'day'], ascending=[True, True, True])
                sorted_shared_diary = sorted_shared_diary.reset_index(drop=True)

                msg_part_2 = sorted_shared_diary.to_json()  # the shared diary - sorted by dates
                full_msg = msg_part_1 + "#" + msg_part_2
                curr_cmd = chatlib.PROTOCOL_SHARED_DIARIES_SERVER['see_specific_shared_diaries_group_ok_msg']
                build_and_send_message(conn, curr_cmd, full_msg)

            else:
                send_error(conn, chatlib.PROTOCOL_SHARED_DIARIES_SERVER['see_specific_shared_diaries_group_failed_msg'], group_doesnt_exist)


def handle_client_message(conn, cmd, message, client_id):
    """
    Gets message code and data and calls the right function to handle command
    Receives: socket, message code and data
    Returns: None
    """
    global logged_users	 # To be used later
    latest_cmd = cmd.split("%")[0]

    if latest_cmd not in chatlib.PROTOCOL_CLIENT.values() and latest_cmd not in chatlib.PROTOCOL_SETTINGS_CLIENT.values() and latest_cmd not in chatlib.PROTOCOL_SEARCH_CLIENT.values() and latest_cmd not in chatlib.PROTOCOL_TASKS_CLIENT.values() and latest_cmd not in chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_CLIENT.values() and latest_cmd not in chatlib.PROTOCOL_PROFILE_CLIENT.values() and latest_cmd not in chatlib.PROTOCOL_SHARED_DIARIES_CLIENT.values():
        send_error(conn, login_error, "We are not familiar with the command!") # not really login error - change that!

    else:
        # login, register, and logout
        if latest_cmd == chatlib.PROTOCOL_CLIENT['login_msg']:
            handle_login_message(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_CLIENT['register_msg']:
            handle_register_message(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_CLIENT['logout_msg']:
            handle_logout_message(conn)

        # send username
        elif latest_cmd == chatlib.PROTOCOL_CLIENT['send_username_msg']:
            send_client_username(conn, latest_cmd, message, client_id)

        # exit from app
        elif latest_cmd == chatlib.PROTOCOL_CLIENT['exit_from_app']:
            handle_exit_message(conn, latest_cmd, message)

        # settings area
        elif latest_cmd == chatlib.PROTOCOL_SETTINGS_CLIENT['see_data_msg']:
            handle_send_data(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_SETTINGS_CLIENT['see_hobbies_msg']:
            handle_see_hobbies(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_SETTINGS_CLIENT['add_hobby_msg']:
            handle_add_hobby(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_SETTINGS_CLIENT['delete_hobby_msg']:
            handle_delete_hobby(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_SETTINGS_CLIENT['change_name_msg']:
            handle_change_name(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_SETTINGS_CLIENT['change_password_msg']:
            handle_change_password(conn, latest_cmd, message, client_id)

        # tasks area
        elif latest_cmd == chatlib.PROTOCOL_TASKS_CLIENT['new_task_msg']:
            handle_new_task_message(conn, cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_TASKS_CLIENT['see_tasks_calendar_msg']:
            handle_tasks_calendar_message(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_TASKS_CLIENT['edit_task_msg']:
            handle_edit_task(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_TASKS_CLIENT['delete_task_msg']:
            handle_delete_task(conn, latest_cmd, message, client_id)

        # search area
        elif latest_cmd == chatlib.PROTOCOL_SEARCH_CLIENT['search_by_username_msg']:
            handle_search_by_username_message(conn, latest_cmd, message)

        elif latest_cmd == chatlib.PROTOCOL_SEARCH_CLIENT['search_by_hobbies_msg']:
            handle_search_by_hobbies(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_SEARCH_CLIENT['username_data_msg']:
            handle_send_username_data(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_SEARCH_CLIENT['send_friendship_request_msg']:
            handle_send_friendship_request_message(conn, latest_cmd, message, client_id)

        # see friendship requests area
        elif latest_cmd == chatlib.PROTOCOL_CLIENT['see_friendship_requests_msg']:
            handle_see_friendship_requests(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_CLIENT['approve_friendship_request_msg']:
            handle_approve_friendship_request(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_CLIENT['reject_friendship_request_msg']:
            handle_reject_friendship_request(conn, latest_cmd, message, client_id)

        # profile area
        elif latest_cmd == chatlib.PROTOCOL_CLIENT['profile_msg']:
            handle_profile_message(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_PROFILE_CLIENT['see_friends_msg']:
            handle_see_friends_message(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_PROFILE_CLIENT['delete_friend_msg']:
            handle_delete_friend_message(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_PROFILE_CLIENT['see_pending_outgoing_requests_msg']:
            handle_see_pending_outgoing_requests(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_PROFILE_CLIENT['delete_friendship_request_msg']:
            handle_delete_friendship_request(conn, latest_cmd, message, client_id)

        # shared diaries area
        elif latest_cmd == chatlib.PROTOCOL_CLIENT['shared_diaries_msg']:
            handle_shared_diaries_message(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['outgoing_share_diary_requests_msg']:
            handle_shared_diaries_outgoing_requests_msg(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['new_share_diary_request_msg']:
            handle_new_share_diary_request(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['ingoing_share_diary_requests_msg']:
            handle_shared_diaries_ingoing_requests_msg(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['approve_share_diary_request_msg']:
            handle_approve_share_diary_request(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['reject_share_diary_request_msg']:
            handle_reject_share_diary_request(conn, latest_cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['see_shared_diaries_groups_msg']:
            handle_see_shared_diaries_groups_message(conn, cmd, message, client_id)

        elif latest_cmd == chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['see_specific_shared_diaries_group_msg']:
            handle_see_specific_shared_diaries_group_message(conn, cmd, message, client_id)


def print_logged_clients(list_of_clients):
    counter = 1
    for sock in list_of_clients:
        print("Socket number ", counter, ":", sock.getpeername())
        counter += 1


def main():
    # The main function

    global logged_users
    global ready_to_write
    global client_sockets
    global messages_to_send
    global hobbies_dictionary
    global friendships_requests_dictionary
    global friendships_dictionary
    global id_dictionary
    global info_dictionary

    logged_users = {}
    hobbies_dictionary = load_hobbies_dictionary()
    friendships_requests_dictionary = load_friendships_requests_dictionary()
    friendships_dictionary = load_friendships_dictionary()
    info_dictionary = load_info_dictionary()
    id_dictionary = load_id_dictionary()
    id_dictionary = {}
    save_id_dictionary(id_dictionary)

    server_socket = setup_socket()
    print("Listening for clients... ")
    client_sockets = []
    messages_to_send = []

    while True:
        ready_to_read, ready_to_write, in_error = select.select([server_socket] + client_sockets, client_sockets, [])

        for current_socket in ready_to_read:
            if current_socket is server_socket:
                (client_socket, client_address) = server_socket.accept()
                print(f"new client connected: {client_address}")
                client_sockets.append(client_socket)

                client_id = uuid.uuid4()
                client_id = str(client_id).replace('-', '')
                id_dictionary[str(client_socket.getpeername())] = (client_id, None)
                save_id_dictionary(id_dictionary)

            else:
                peer_name = str(current_socket.getpeername())
                client_id = id_dictionary[peer_name][0]

                print("New data from client!")

                cmd, msg = recv_message_and_parse(current_socket)

                if (cmd == "" and msg == "") or (cmd == chatlib.PROTOCOL_CLIENT['exit_from_app']):
                    del id_dictionary[str(peer_name)]
                    save_id_dictionary(id_dictionary)

                    try:
                        client_sockets.remove(current_socket)
                        ready_to_write.remove(current_socket)
                        if tuple(current_socket.getpeername()) in logged_users.keys():
                            del (logged_users[tuple(current_socket.getpeername())])

                    except:
                        print("Not a socket!")

                    finally:
                        current_socket.close()

                else:
                    if cmd == chatlib.PROTOCOL_CLIENT['public_key_msg']:
                        if current_socket.getpeername() not in logged_users.keys():
                            handle_public_key_message(current_socket, msg, client_id)

                    else:
                        handle_client_message(current_socket, cmd, msg, client_id)

            print("\nThe logged users are: \n")
            print_logged_clients(logged_users.values())

        for message in messages_to_send:
            current_socket, data = message

            # encryption
            curr_cmd, msg = chatlib.parse_message(data)
            if curr_cmd != chatlib.PROTOCOL_SERVER['public_key_ok_msg']:
                peer_name = str(current_socket.getpeername())
                client_secret_key = id_dictionary[peer_name][1]
                encrypted_data = cf.encrypt(data, client_secret_key)

            else:
                encrypted_data = data.encode()

            current_socket.send(encrypted_data)
            messages_to_send.remove(message)


if __name__ == '__main__':
    main()
