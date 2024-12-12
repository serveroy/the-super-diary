"""This file will contain the parsing of the messages (client side <-> server side) """

# protocol messages

PROTOCOL_CLIENT = {
    "login_msg": "LOGIN",
    "register_msg": "REGISTER",
    "profile_msg": "PROFILE",
    "see_friendship_requests_msg": "SEE_FRIENDSHIP_REQUESTS",
    "shared_diaries_msg": "SHARED_DIARIES",

    "exit_from_app": "EXIT",
    "public_key_msg": "PUBLIC_KEY",
    "send_username_msg": "SEND_USERNAME",
    "logout_msg": "LOGOUT"
}

PROTOCOL_SETTINGS_CLIENT = {
    "see_data_msg": "SEE_DATA",
    "change_name_msg": "CHANGE_NAME",
    "change_password_msg": "CHANGE_PASSWORD",
    "see_hobbies_msg": "SEE_HOBBIES",
    "add_hobby_msg": "ADD_HOBBY",
    "delete_hobby_msg": "DELETE_HOBBY"
}

PROTOCOL_SEARCH_CLIENT = {
    "search_by_username_msg": "SEARCH_BY_USERNAME",
    "search_by_hobbies_msg": "SEARCH_BY_HOBBIES",
    "username_data_msg": "USERNAME_DATA",
    "send_friendship_request_msg": "SEND_FRIENDSHIP_REQUEST"
}

PROTOCOL_TASKS_CLIENT = {
    "see_tasks_calendar_msg": "SEE_TASKS_CALENDAR",  # whole tasks calendar -> specific task?
    "new_task_msg": "NEW_TASK",
    "delete_task_msg": "DELETE_TASK",
    # "does_task_exist_msg": "DOES_TASK_EXIST",
    "edit_task_msg": "EDIT_TASK"
}

PROTOCOL_FRIENDSHIP_REQUESTS_CLIENT = {
    "approve_friendship_request_msg": "APPROVE_FRIENDSHIP_REQUEST",
    "reject_friendship_request_msg": "REJECT_FRIENDSHIP_REQUEST"
}

PROTOCOL_PROFILE_CLIENT = {
    "see_friends_msg": "SEE_FRIENDS",  # see list -> delete or see data
    "delete_friend_msg": "DELETE_FRIEND",
    "see_pending_outgoing_requests_msg": "SEE_PENDING_OUTGOING_REQUESTS",
    "delete_friendship_request_msg": "DELETE_FRIENDSHIP_REQUEST"  # delete
}

PROTOCOL_SHARED_DIARIES_CLIENT = {
    "outgoing_share_diary_requests_msg": "OUTGOING_SHARE_DIARY_REQUESTS",
    "new_share_diary_request_msg": "NEW_SHARE_DIARY_REQUEST",

    "ingoing_share_diary_requests_msg": "INGOING_SHARE_DIARY_REQUESTS",
    "approve_share_diary_request_msg": "APPROVE_SHARE_DIARY_REQUEST",
    "reject_share_diary_request_msg": "REJECT_SHARE_DIARY_REQUEST",

    "see_shared_diaries_groups_msg": "SEE_SHARED_DIARIES_GROUPS",
    "see_specific_shared_diaries_group_msg": "SEE_SPECIFIC_SHARED_DIARIES_GROUP"
}

PROTOCOL_SERVER = {
    "login_ok_msg": "LOGIN_OK",
    "login_failed_msg": "LOGIN_ERROR",

    "register_ok_msg": "REGISTER_OK",
    "register_failed_msg": "REGISTER_FAILED",

    "profile_ok_msg": "PROFILE_OK",
    "profile_failed_msg": "PROFILE_FAILED",

    "shared_diaries_ok_msg": "SHARED_DIARIES_OK",
    "shared_diaries_failed_msg": "SHARED_DIARIES_FAILED",

    "see_friendship_requests_ok_msg": "SEE_FRIENDSHIP_REQUESTS_OK",
    "see_friendship_requests_failed_msg": "SEE_FRIENDSHIP_REQUESTS_FAILED",

    "exit_ok_msg": "EXIT_OK",
    "exit_failed_msg": "EXIT_FAILED",

    "public_key_ok_msg": "PUBLIC_KEY_OK",
    "public_key_failed_msg": "PUBLIC_KEY_FAILED",

    "send_username_ok_msg": "SEND_USERNAME_OK",
    "send_username_failed_msg": "SEND_USERNAME_FAILED",

    "logout_ok_msg": "LOGOUT_OK",
    "logout_failed_msg": "LOGOUT_FAILED"
}

PROTOCOL_SETTINGS_SERVER = {
    "see_data_ok_msg": "SEE_DATA_OK",
    "see_data_failed_msg": "SEE_DATA_FAILED",

    "change_data_ok_msg": "CHANGE_DATA_OK",
    "change_data_failed_msg": "CHANGE_DATA_FAILED",

    "change_name_ok_msg": "CHANGE_NAME_OK",
    "change_name_failed_msg": "CHANGE_NAME_FAILED",

    "change_password_ok_msg": "CHANGE_PASSWORD_OK",
    "change_password_failed_msg": "CHANGE_PASSWORD_FAILED",

    "hobbies_ok_msg": "HOBBIES_OK",
    "hobbies_failed_msg": "HOBBIES_FAILED",

    "see_hobbies_ok_msg": "SEE_HOBBIES_OK",
    "see_hobbies_failed_msg": "SEE_HOBBIES_FAILED",

    "add_hobby_ok_msg": "ADD_HOBBY_OK",
    "add_hobby_failed_msg": "ADD_HOBBY_FAILED",

    "delete_hobby_ok_msg": "DELETE_HOBBY_OK",
    "delete_hobby_failed_msg": "DELETE_HOBBY_FAILED"
}

PROTOCOL_SEARCH_SERVER = {
    "search_by_username_ok_msg": "SEARCH_BY_USERNAME_OK",
    "search_by_username_failed_msg": "SEARCH_BY_USERNAME_FAILED",

    "search_by_hobbies_ok_msg": "SEARCH_BY_HOBBIES_OK",
    "search_by_hobbies_failed_msg": "SEARCH_BY_HOBBIES_FAILED",

    "username_data_ok_msg": "USERNAME_DATA_OK",
    "username_data_failed_msg": "USERNAME_DATA_FAILED",

    "send_friendship_request_ok_msg": "SEND_FRIENDSHIP_REQUEST_OK",
    "send_friendship_request_failed_msg": "SEND_FRIENDSHIP_REQUEST_FAILED"
}

PROTOCOL_TASKS_SERVER = {
    "see_tasks_calendar_ok_msg": "SEE_TASKS_CALENDAR_OK",
    "see_tasks_calendar_failed_msg": "SEE_TASKS_CALENDAR_FAILED",

    "new_task_ok_msg": "NEW_TASK_OK",
    "new_task_failed_msg": "NEW_TASK_FAILED",

    "edit_task_ok_msg": "EDIT_TASK_OK",
    "edit_task_failed_msg": "EDIT_TASK_FAILED",

    # "does_task_exist_ok_msg": "DOES_TASK_EXIST_OK",
    # "does_task_exist_failed_msg": "DOES_TASK_EXIST_FAILED",

    "delete_task_ok_msg": "DELETE_TASK_OK",
    "delete_task_failed_msg": "DELETE_TASK_FAILED"
}

PROTOCOL_FRIENDSHIP_REQUESTS_SERVER = {
    "approve_friendship_request_ok_msg": "APPROVE_FRIENDSHIP_REQUEST_OK",
    "approve_friendship_request_failed_msg": "APPROVE_FRIENDSHIP_REQUEST_FAILED",

    "reject_friendship_request_ok_msg": "REJECT_FRIENDSHIP_REQUEST_OK",
    "reject_friendship_request_failed_msg": "REJECT_FRIENDSHIP_REQUEST_FAILED"
}

PROTOCOL_PROFILE_SERVER = {
    "see_friends_ok_msg": "SEE_FRIENDS_OK",  # see list -> delete or see data
    "see_friends_failed_msg": "SEE_FRIENDS_FAILED",

    "delete_friend_ok_msg": "DELETE_FRIEND_OK",
    "delete_friend_failed_msg": "DELETE_FRIEND_FAILED",

    "share_diary_ok_msg": "SHARE_DIARY_OK",
    "share_diary_failed_msg": "SHARE_DIARY_FAILED",

    "see_pending_outgoing_requests_ok_msg": "SEE_PENDING_OUTGOING_REQUESTS_OK",
    "see_pending_outgoing_requests_failed_msg": "SEE_PENDING_OUTGOING_REQUESTS_FAILED",

    "delete_friendship_request_ok_msg": "DELETE_FRIENDSHIP_REQUEST_OK",
    "delete_friendship_request_failed_msg": "DELETE_FRIENDSHIP_REQUEST_FAILED",
}

PROTOCOL_SHARED_DIARIES_SERVER = {
    "outgoing_share_diary_requests_ok_msg": "OUTGOING_SHARE_DIARY_REQUESTS_OK",
    "outgoing_share_diary_requests_failed_msg": "OUTGOING_SHARE_DIARY_REQUESTS_FAILED",

    "new_share_diary_request_ok_msg": "NEW_SHARE_DIARY_REQUEST_OK",
    "new_share_diary_request_failed_msg": "NEW_SHARE_DIARY_REQUEST_FAILED",

    "ingoing_share_diary_requests_ok_msg": "INGOING_SHARE_DIARY_REQUESTS_OK",
    "ingoing_share_diary_requests_failed_msg": "INGOING_SHARE_DIARY_REQUESTS_FAILED",

    "approve_share_diary_request_ok_msg": "APPROVE_SHARE_DIARY_REQUEST_OK",
    "approve_share_diary_request_failed_msg": "APPROVE_SHARE_DIARY_REQUEST_FAILED",

    "reject_share_diary_request_ok_msg": "REJECT_SHARE_DIARY_REQUEST_OK",
    "reject_share_diary_request_failed_msg": "REJECT_SHARE_DIARY_REQUEST_FAILED",

    "see_shared_diaries_groups_ok_msg": "SEE_SHARED_DIARIES_GROUPS_OK",
    "see_shared_diaries_groups_failed_msg": "SEE_SHARED_DIARIES_GROUPS_FAILED",

    "see_specific_shared_diaries_group_ok_msg": "SEE_SPECIFIC_SHARED_DIARIES_GROUP_OK",
    "see_specific_shared_diaries_group_failed_msg": "SEE_SPECIFIC_SHARED_DIARIES_GROUP_FAILED"
}

ERROR_RETURN = None

# settings -> change password ...


def build_message_with_correct_inputs(cmd, data):
    """
    Gets valid command name and data field according to the protocol.
    Returns: str
    """

    full_msg = cmd + "|" + data
    return full_msg


def handle_client_message(cmd, data):
    full_msg = ""
    curr_cmd = cmd.split("%")[0]

    if curr_cmd != PROTOCOL_CLIENT['login_msg'] and curr_cmd != PROTOCOL_CLIENT['register_msg']:
        full_msg = build_message_with_correct_inputs(cmd, data)

        # if data != "":
        #     full_msg = ERROR_RETURN
        #
        # else:
        #     full_msg = build_message_with_correct_inputs(cmd, data)

    else:
        if cmd == PROTOCOL_CLIENT['login_msg'] or cmd == PROTOCOL_CLIENT['register_msg']:
            parts_of_login = data.split("#")
            if len(parts_of_login) >= 2:
                full_msg = build_message_with_correct_inputs(cmd, data)
            else:
                full_msg = ERROR_RETURN

    return full_msg


def handle_server_message(cmd, data):
    curr_cmd = cmd.split("%")[0]

    if curr_cmd == PROTOCOL_SERVER['login_ok_msg'] or curr_cmd == PROTOCOL_SERVER['register_ok_msg']:  # change that
        if data != "":
            full_msg = ERROR_RETURN
        else:
            full_msg = build_message_with_correct_inputs(cmd, data)

    else:
        full_msg = build_message_with_correct_inputs(cmd, data)

    return full_msg


def is_in_client_values(curr_cmd, msg):
    first_check = curr_cmd in PROTOCOL_CLIENT.values() or curr_cmd in PROTOCOL_SETTINGS_CLIENT.values()
    second_check = first_check or curr_cmd in PROTOCOL_SEARCH_CLIENT.values()
    third_check = second_check or curr_cmd in PROTOCOL_TASKS_CLIENT.values()
    forth_check = third_check or curr_cmd in PROTOCOL_PROFILE_CLIENT.values()
    fifth_check = forth_check or curr_cmd in PROTOCOL_FRIENDSHIP_REQUESTS_CLIENT.values()
    sixth_check = fifth_check or curr_cmd in PROTOCOL_SHARED_DIARIES_CLIENT.values()

    return sixth_check and type(msg) == str


def is_in_server_values(curr_cmd, msg):
    first_check = curr_cmd in PROTOCOL_SERVER.values() or curr_cmd in PROTOCOL_SETTINGS_SERVER.values()
    second_check = first_check or curr_cmd in PROTOCOL_SEARCH_SERVER.values()
    third_check = second_check or curr_cmd in PROTOCOL_TASKS_SERVER.values()
    forth_check = third_check or curr_cmd in PROTOCOL_PROFILE_SERVER.values()
    fifth_check = forth_check or curr_cmd in PROTOCOL_FRIENDSHIP_REQUESTS_SERVER.values()
    sixth_check = fifth_check or curr_cmd in PROTOCOL_SHARED_DIARIES_SERVER.values()

    return sixth_check and type(msg) == str


def is_valid(curr_cmd, msg):
    return is_in_client_values(curr_cmd, msg) or is_in_server_values(curr_cmd, msg)


def build_message(cmd, msg):
    curr_cmd = cmd.split("%")[0]
    print(curr_cmd)

    if not is_valid(curr_cmd, msg):
        full_msg = ERROR_RETURN

    else:
        if is_in_client_values(curr_cmd, msg):
            full_msg = handle_client_message(cmd, msg)

        else:
            full_msg = handle_server_message(cmd, msg)

    return full_msg


def parse_message(data):
    """
    Parses protocol message and returns command name and data field
    Returns: cmd (str), data (str). If some error occurred, returns None, None
    """
    data_after_split = data.split("|", 1)

    cmd = data_after_split[0]
    msg = data_after_split[1]

    return cmd, msg
