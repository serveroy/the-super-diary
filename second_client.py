import socket
from datetime import datetime
import datetime
import chatlib
import pandas as pd
import numpy as np
import re
import json
import sys  # in order to close the app in case of receiving an empty message from the server.

# kivy imports - GUI
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.uix.image import Image
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivymd.uix.button import MDRaisedButton
from kivy.uix.boxlayout import BoxLayout
from kivy.graphics import Color, Rectangle
from kivy.clock import Clock
from kivy.metrics import dp
from kivymd.uix.datatables import MDDataTable
from kivymd.app import MDApp
from kivy.base import EventLoop

# new import
from kivymd.uix.button import MDIconButton

from cyphers import cypher_functions as cf, client_secret_value as csv
import port_and_ip_data as paid


# Define global variable
global client_key
global hobby
global screen_flow

# important expressions

# hobbies
no_hobbies_delete_msg = "Didn't enter any hobbies so there is nothing to delete! "
no_hobbies_see_msg = "Didn't enter any hobbies so there is nothing to see! "

# tasks
no_tasks_delete_msg = "You have no tasks so there is nothing to delete here! "
no_tasks_edit_msg = "You have no tasks so there is nothing to edit here! "
no_tasks_see_msg = "You have no tasks so there is nothing to see here! "
no_tasks_specific_day = "You don't have tasks on that day! "

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

# shared diaries
no_outgoing_requests_to_share_diaries = "You haven't sent any diary sharing request yet! "
no_ingoing_requests_to_share_diaries = "You don't have any ingoing requests to share diaries! "
no_friends_to_add_to_recipients = "You have no friends to add to the recipients list! "
no_shared_diaries_groups_to_share_diaries = "There are no shared diaries groups you participate in or created! "
shared_diaries_group_is_deleted = "The group is deleted! "
no_group_sharing_tasks_requests = "There are not requests for task sharing in this group! "
no_group_shared_tasks = "There are no shared tasks of the group! "

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

logo_path = r'C:\‏‏final_project - עותק\project_logo.png'
hobbies_picture_path = r'C:\‏‏final_project - עותק\hobby-picture.png'
search_picture_path = r'C:\‏‏final_project - עותק\search-curr-picture.jpg'
refresh_picture_path = r'C:\‏‏final_project - עותק\refresh_picture.jpg'

# doesn't exist : everyone rejected/everyone approved


def connect():
    """
    Connects the socket to the server.
    """
    my_socket = socket.socket()
    my_socket.connect((paid.SERVER_IP, paid.SERVER_PORT))
    return my_socket


def build_and_send_message(conn, cmd, msg):
    """
    Builds a new message using chatlib, wanted code and message.
    Prints debug info, then sends it to the given socket.
    Paramaters: conn (socket object), code (str), msg (str)
    Returns: Nothing
    """
    global client_key

    full_msg = chatlib.build_message(cmd, msg)
    full_msg_after_cypher = cf.encrypt(full_msg, client_key)

    print("[THE CLIENT'S MESSAGE BEFORE CYPHER] ", full_msg)  # Debug print
    print("[THE CLIENT'S MESSAGE AFTER CYPHER] ", full_msg_after_cypher)  # Debug print

    conn.send(full_msg_after_cypher)


def wise_recv(conn):
    try:
        global client_key
        data = conn.recv(10024)

    except:
        print("Server went down!")
        conn.close()
        return

    print("Data: ", (data, type(data)))
    real_data = cf.decrypt(data, client_key)
    print(real_data)

    return real_data


class MyApp(MDApp):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.conn = connect()

    def build(self):
        """
        Builds the screen manager and returns it.
        """
        global screen_flow
        screen_manager = MyScreenManager(conn=self.conn)
        screen_manager.current = "first_screen"
        screen_flow["current"] = "first_screen"
        return screen_manager

    def on_start(self):
        """
        Receives the client_key from the server and updates it.
        """
        global client_key
        client_key = get_key(self.conn)
        if client_key is None:
            sys.exit(1)
        print("Key: ", client_key)

    def restart_app(self):
        """
        Restarts the app.
        """
        EventLoop.close()
        self.stop()
        MyApp().run()


class MyScreenManager(ScreenManager):
    def __init__(self, conn, **kwargs):
        super().__init__(**kwargs)
        self.transition = SlideTransition(duration=0.001)

        self.conn = conn
        # first, login and register screens
        self.add_widget(FirstScreen(conn=self.conn, name="first_screen"))  # first screen
        self.add_widget(LoginScreen(conn=self.conn, name="login_screen"))  # login screen
        self.add_widget(RegisterScreen(conn=conn, name="register_screen"))  # register screen
        self.add_widget(MainScreen(conn=conn, name="main_screen"))  # main screen

        # settings screens
        self.add_widget(SettingsScreen(conn=conn, name="settings_screen"))  # settings screen
        self.add_widget(SeeDataScreen(conn=conn, name="see_data_screen"))  # see data screen
        self.add_widget(ChangeDataScreen(conn=conn, name="change_data_screen"))  # change data screen
        self.add_widget(ChangeNameScreen(conn=conn, name="change_name_screen"))  # change name screen
        self.add_widget(ChangePasswordScreen(conn=conn, name="change_password_screen"))  # change password screen
        self.add_widget(HobbiesScreen(conn=conn, name="hobbies_screen"))  # hobbies screen
        self.add_widget(AddHobbyScreen(conn=conn, name="add_hobby_screen"))  # add hobby screen
        self.add_widget(SeeHobbiesScreen(conn=conn, name="see_hobbies_screen"))  # see hobbies screen
        self.add_widget(DeleteHobbyScreen(conn=conn, name="delete_hobby_screen"))  # see hobbies screen

        # search screens
        self.add_widget(SearchScreen(conn=conn, name="search_screen"))
        self.add_widget(SearchByUsernameScreen(conn=conn, name="search_by_username_screen"))  # sub screen 1 - search by username
        self.add_widget(SearchByHobbiesScreen(conn=conn, name="search_by_hobbies_screen"))  # sub screen 2 - search by hobbies
        self.add_widget(SeeUserDataScreen(conn=conn, name="see_user_data_screen"))  # see user data screen

        # friendship requests screen
        self.add_widget(FriendshipRequestsScreen(conn=conn, name="friendship_requests_screen"))

        # profile screens
        self.add_widget(ProfileScreen(conn=conn, name="profile_screen"))   # profile screen
        self.add_widget(SeeFriendsScreen(conn=conn, name="see_friends_screen"))   # see friends screen
        self.add_widget(SeeOutgoingFriendshipRequestsScreen(conn=conn, name="see_outgoing_friendship_requests_screen")) # see outgoing friendship requests screen

        # tasks screens
        self.add_widget(TasksScreen(conn=conn, name="tasks_screen"))  # tasks screen
        self.add_widget(SeeTasksScreen(conn=conn, name="see_tasks_screen"))  # see tasks screen
        self.add_widget(SeeSpecificTaskScreen(conn=conn, name="see_specific_task_screen"))  # see tasks screen
        self.add_widget(EditSpecificTaskScreen(conn=conn, name="edit_specific_task_screen"))  # add new task screen
        self.add_widget(AddNewTaskScreen(conn=conn, name="add_new_task_screen"))  # add new task screen

        # shared diaries screens
        self.add_widget(SharedDiariesScreen(conn=conn, name="shared_diaries_screen"))    # shared diaries screen
        self.add_widget(OutgoingShareDiaryRequestsScreen(conn=conn, name="outgoing_share_diary_requests_screen"))
        self.add_widget(SendShareDiaryRequestScreen(conn=conn, name="send_share_diary_request_screen"))

        self.add_widget(IngoingShareDiaryRequestsScreen(conn=conn, name="ingoing_share_diary_requests_screen"))
        self.add_widget(SeeSpecificIngoingShareDiaryRequestScreen(conn=conn, name="see_specific_ingoing_share_diary_request_screen"))
        self.add_widget(SeeSharedDiariesScreen(conn=conn, name="see_shared_diaries_screen"))
        self.add_widget(SeeSpecificShareDiaryGroupScreen(conn=conn, name="see_specific_share_diary_group_screen"))


class FirstScreen(Screen):
    def __init__(self, conn, name="first_screen", **kwargs):
        super().__init__(name=name, **kwargs)

        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.4, 0.4), pos_hint={'center_x': 0.5, 'top': 0.95}))

        # add the label below the image
        self.add_widget(Label(text="Welcome to the super diary!\n        Your options are: ", font_size=self.width/3, size_hint=(1, 0.2), pos_hint={'center_x': 0.5, 'top': 0.6}, color=(0, 0, 0, 1)))

        # create a horizontal BoxLayout for the buttons
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2), pos_hint={'center_x': 0.5, 'top': 0.4}, padding=(20, 0, 20, 0))

        # add the buttons to the BoxLayout
        layout.add_widget(MDRaisedButton(text="Login", size_hint=(0.2, 0.8), font_size=self.width/4, on_press=self.on_login_button_press))
        layout.add_widget(MDRaisedButton(text="Register", size_hint=(0.2, 0.8), font_size=self.width/4, on_press=self.on_register_button_press))
        layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width/4, on_press=self.exit_app))

        # add the BoxLayout to the screen
        self.add_widget(layout)
        self.conn = conn

    def update_rect(self, *args):
        """
        Updating the rect value.
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_login_button_press(self, instance):
        """
        Switching to the login screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "login_screen"
        self.manager.current = "login_screen"  # Switch to the login_screen

    def on_register_button_press(self, instance):
        """
        Switching to the register screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "register_screen"
        self.manager.current = "register_screen"  # Switch to the register_screen

    def exit_app(self, instance):
        """
        Exiting the app.
        :param instance: the button instance that triggered the event.
        """
        App.get_running_app().stop()


# login screen

class LoginScreen(Screen):
    def __init__(self, conn, name="login_screen", **kwargs):
        super().__init__(name=name, **kwargs)

        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # create the message label widget
        self.message_label = Label(text="", font_size=self.width * 0.25, size_hint=(1, 0.1), pos_hint={'top': 0.45},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        # create the welcome label widget
        welcome_label = Label(text="Welcome", font_size=self.width * 0.5, size_hint=(1, 0.1), pos_hint={'top': 0.9},
                              color=(0, 0, 0, 1))
        self.add_widget(welcome_label)

        # username and password input boxes
        username_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.1))  # create the username layout widget
        username_layout.pos_hint = {'top': 0.75, 'center_x': 0.45}   # position the username_layout just below the welcome_label

        # create the username label widget
        self.username_label = Label(text="Username: ", font_size=self.width * 0.3, size=(self.width*0.9, self.height*0.05), size_hint=(0.2, 1), color=(0, 0, 1, 1))
        username_layout.add_widget(self.username_label)
        self.username_label.pos_hint = {'top': 0.75, 'right': 0.15}

        # create the username input widget
        self.username_input = TextInput(multiline=False, size_hint=(0.6, 0.5), size=(self.width * 0.6, self.height * 0.05),
                                   font_size=self.width * 0.15)
        username_layout.add_widget(self.username_input)
        self.add_widget(username_layout)  # add the username_layout to the root widget

        # create the password layout widget
        password_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.1))

        # create the password label widget
        self.password_label = Label(text="Password: ", font_size=self.width * 0.3, size_hint=(0.2, 1), color=(0, 0, 1, 1))
        password_layout.add_widget(self.password_label)
        # position the username_label to the left of the username_input
        self.password_label.pos_hint = {'top': 0.6, 'right': 0.1}

        # create the username input widget
        self.password_input = TextInput(multiline=False, size_hint=(0.6, 0.5), size=(self.width * 0.6, self.height * 0.05),
                                        font_size=self.width * 0.15)
        password_layout.add_widget(self.password_input)
        # position the username_layout just below the welcome_label
        password_layout.pos_hint = {'top': 0.6, 'center_x': 0.45}

        # add the username_layout to the root widget
        self.add_widget(password_layout)
        self.conn = conn

        login_button = MDRaisedButton(text="Login", font_size=self.width*0.3, size_hint=(0.2, 0.1))
        login_button.pos_hint = {'top': 0.3, 'center_x': 0.3}
        login_button.bind(on_press=self.login)
        self.add_widget(login_button)

        back_button = MDRaisedButton(text="Go back to first screen", font_size=self.width*0.3, size_hint=(0.4, 0.1))
        back_button.pos_hint = {'top': 0.3, 'center_x': 0.7}
        back_button.bind(on_press=self.switch_to_first_screen)
        back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        self.add_widget(back_button)

    def update_rect(self, *args):
        self.rect.pos = self.pos
        self.rect.size = self.size

    def switch_to_first_screen(self, instance):
        """
        Switching to the first screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "first_screen"
        self.manager.current = "first_screen"  # Switch to the register_screen

    def clear_inputs_and_outputs(self, instance):
        """
        Clearing specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.username_input.text = ''
        self.password_input.text = ''
        self.message_label.text = ''

    def handle_server_response_to_login_message(self, data):
        """
        Handles the server response to a login message.
        :param data: the data received from the server.
        """
        command, message = chatlib.parse_message(data)
        print("The message: ", (command, message))  # print in the cmd

        if data == chatlib.ERROR_RETURN or command == chatlib.PROTOCOL_SERVER['login_failed_msg']:
            self.message_label.text = f"The login failed! {message}"  # A text input on the screen.
        else:
            self.message_label.text = "Logged in successfully! "
            self.username_input.text = ''
            self.password_input.text = ''
            self.message_label.text = ''

            global screen_flow
            screen_flow["prev"] = screen_flow["current"]
            screen_flow["current"] = "main_screen"
            self.manager.current = "main_screen"  # Switch to the main_screen

    def login(self, instance):
        """
        Sends the server a login request.
        :param instance: the button instance that triggered the event.
        """
        username = self.username_input.text
        password = self.password_input.text
        if "#" in username or "#" in password:
            self.message_label.text = "You can't enter # in username or in password! "
            return
        whole_message = username + "#" + password
        build_and_send_message(self.conn, chatlib.PROTOCOL_CLIENT['login_msg'], whole_message)
        # use Clock.schedule_once to wait for the server response asynchronously
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        Clock.schedule_once(lambda dt: self.handle_server_response_to_login_message(data))


# register screen

class RegisterScreen(Screen):
    def __init__(self, conn, name="register_screen", **kwargs):
        super().__init__(name=name, **kwargs)

        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # create the message label widget
        self.message_label = Label(text="", font_size=self.width * 0.25, size_hint=(1, 0.1), pos_hint={'top': 0.3},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        # create the welcome label widget
        welcome_label = Label(text="Welcome :) ", font_size=self.width * 0.5, size_hint=(1, 0.1), pos_hint={'top': 0.9},
                              color=(0, 0, 0, 1))
        self.add_widget(welcome_label)

        # name
        # create the name layout widget
        name_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.1))  # create the username layout widget
        name_layout.pos_hint = {'top': 0.75, 'center_x': 0.45}   # position the name_layout just below the welcome_label

        # create the name label widget
        self.name_label = Label(text="Name: ", font_size=self.width * 0.3, size=(self.width*0.9, self.height*0.05), size_hint=(0.2, 1), color=(0, 0, 1, 1))
        self.name_label.pos_hint = {'top': 0.75, 'right': 0.15}
        name_layout.add_widget(self.name_label)

        # create the name input widget
        self.name_input = TextInput(multiline=False, size_hint=(0.6, 0.5), size=(self.width * 0.6, self.height * 0.05),
                                   font_size=self.width * 0.15)
        name_layout.add_widget(self.name_input)
        self.add_widget(name_layout)  # add the name to the root widget

        # username
        # create the username layout widget
        username_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.1))

        # create the username label widget
        self.username_label = Label(text="Username: ", font_size=self.width * 0.3, size_hint=(0.2, 1), color=(0, 0, 1, 1))
        username_layout.add_widget(self.username_label)
        # position the username_label to the left of the username_input
        self.username_label.pos_hint = {'top': 0.6, 'right': 0.1}

        # create the username input widget
        self.username_input = TextInput(multiline=False, size_hint=(0.6, 0.5), size=(self.width * 0.6, self.height * 0.05),
                                        font_size=self.width * 0.15)
        username_layout.add_widget(self.username_input)
        # position the username_layout just below the name_layout
        username_layout.pos_hint = {'top': 0.6, 'center_x': 0.45}
        self.add_widget(username_layout)

        # password
        # create the password layout widget
        password_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.1))

        # create the password label widget
        self.password_label = Label(text="Password: ", font_size=self.width * 0.3, size_hint=(0.2, 1), color=(0, 0, 1, 1))
        password_layout.add_widget(self.password_label)
        # position the username_label to the left of the username_input
        self.password_label.pos_hint = {'top': 0.45, 'right': 0.1}

        # create the password input widget
        self.password_input = TextInput(multiline=False, size_hint=(0.6, 0.5), size=(self.width * 0.6, self.height * 0.05),
                                        font_size=self.width * 0.15)
        password_layout.add_widget(self.password_input)
        # position the password_layout just below the username_layout
        password_layout.pos_hint = {'top': 0.45, 'center_x': 0.45}

        # add the username_layout to the root widget
        self.add_widget(password_layout)
        self.conn = conn

        register_button = MDRaisedButton(text="Register", font_size=self.width*0.3, size_hint=(0.2, 0.1))
        register_button.pos_hint = {'top': 0.15, 'center_x': 0.3}
        register_button.bind(on_press=self.register)
        self.add_widget(register_button)

        back_button = MDRaisedButton(text="Go back to first screen", font_size=self.width*0.3, size_hint=(0.4, 0.1))
        back_button.pos_hint = {'top': 0.15, 'center_x': 0.7}
        back_button.bind(on_press=self.switch_to_first_screen)
        back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        self.add_widget(back_button)

    def update_rect(self, *args):
        """
        Updates the rect value
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def switch_to_first_screen(self, instance):
        """
        Switches to the first screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "first_screen"
        self.manager.current = "first_screen"  # Switch to the register_screen

    def clear_inputs_and_outputs(self, instance):
        """
        Clearing specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.name_input.text = ''
        self.username_input.text = ''
        self.password_input.text = ''
        self.message_label.text = ''

    def handle_server_response_to_register_message(self, data):
        """
        Handles the server response to a login message.
        :param data: the data received from the server.
        """
        command, message = chatlib.parse_message(data)
        print("The message: ", (command, message))  # print in the cmd

        if data == chatlib.ERROR_RETURN or command == chatlib.PROTOCOL_SERVER['register_failed_msg']:
            self.message_label.text = f"The register failed! {message}"  # A text input on the screen.
        else:
            self.message_label.text = "Registered successfully! "
            self.username_input.text = ''
            self.password_input.text = ''
            self.message_label.text = ''

            global screen_flow
            screen_flow["prev"] = screen_flow["current"]
            screen_flow["current"] = "main_screen"
            self.manager.current = "main_screen"  # Switch to the main_screen

    def register(self, instance):
        """
        Sends the server a register request.
        :param instance: the button instance that triggered the event.
        """
        name = self.name_input.text
        username = self.username_input.text
        password = self.password_input.text
        if "#" in username or "#" in password or "#" in name:
            self.message_label.text = "You can't enter # in name or in username or in password! "
            return
        whole_message = name + "#" + username + "#" + password
        build_and_send_message(self.conn, chatlib.PROTOCOL_CLIENT['register_msg'], whole_message)
        # use Clock.schedule_once to wait for the server response asynchronously
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        Clock.schedule_once(lambda dt: self.handle_server_response_to_register_message(data))

# main screen class


class MainScreen(Screen):
    def __init__(self, conn, name="main_screen", **kwargs):
        super().__init__(name=name, **kwargs)

        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="The super diary", font_size=self.width*0.5, size_hint=(1, 0.2), pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        # add the buttons to the BoxLayout
        # create a horizontal BoxLayout for the buttons
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2), pos_hint={'center_x': 0.5, 'top': 0.6}, padding=(20, 0, 20, 0))
        layout.add_widget(MDRaisedButton(text="Profile", size_hint=(0.2, 0.8), font_size=self.width/4, on_press=self.on_profile_button_press))
        layout.add_widget(MDRaisedButton(text="Settings", size_hint=(0.2, 0.8), font_size=self.width/4, on_press=self.on_settings_button_press))
        layout.add_widget(MDRaisedButton(text="Tasks", size_hint=(0.2, 0.8), font_size=self.width/4, on_press=self.on_tasks_button_press))
        self.add_widget(layout)

        # add another layout
        second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2), pos_hint={'center_x': 0.5, 'top': 0.4}, padding=(20, 0, 20, 0))
        second_layout.add_widget(MDRaisedButton(text="Search", size_hint=(0.2, 0.8), font_size=self.width/4, on_press=self.on_search_button_press))
        second_layout.add_widget(MDRaisedButton(text="See friendship requests", size_hint=(0.2, 0.8), font_size=self.width/4, on_press=self.on_friendship_requests_press))
        second_layout.add_widget(MDRaisedButton(text="Shared Diaries", size_hint=(0.2, 0.8), font_size=self.width/4, on_press=self.on_shared_diaries_button_press))
        self.add_widget(second_layout)

        # self.add_widget(Button(text="Exit", size_hint=(0.2, 0.8), font_size=self.width/4, on_press=self.exit_app, ))
        # add exit

        # add the BoxLayout to the screen
        self.conn = conn

    def update_rect(self, *args):
        """
        Updates the rect value.
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_profile_button_press(self, instance):
        """
        Switches to the first screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "profile_screen"
        self.manager.current = "profile_screen"  # Switch to the profile_screen

    def on_settings_button_press(self, instance):
        """
        Switches to the first screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "settings_screen"
        self.manager.current = "settings_screen"  # Switch to the settings_screen

    def on_tasks_button_press(self, instance):
        """
        Switches to the tasks screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "tasks_screen"
        self.manager.current = "tasks_screen"  # Switch to the tasks_screen

    def on_search_button_press(self, instance):
        """
        Switches to the search screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "search_screen"
        self.manager.current = "search_screen"  # Switch to the search_screen

    def on_friendship_requests_press(self, instance):
        """
        Switches to the friendship requests screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "friendship_requests_screen"
        self.manager.current = "friendship_requests_screen"  # Switch to friendship_requests screen

    def on_shared_diaries_button_press(self, instance):
        """
        Switches to the shared diaries screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "shared_diaries_screen"
        self.manager.current = "shared_diaries_screen"  # Switch to shared tasks screen

    # def exit_app(self, instance):
    #     App.get_running_app().stop()


class SettingsScreen(Screen):
    def __init__(self, conn, name="settings_screen", **kwargs):
        super().__init__(name=name, **kwargs)

        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Settings Area", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        # add the buttons to the BoxLayout
        # create a horizontal BoxLayout for the buttons
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.6}, padding=(20, 0, 20, 0))
        layout.add_widget(MDRaisedButton(text="Main screen", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_main_screen_button_press))
        layout.add_widget(MDRaisedButton(text="See data", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_see_data_button_press))
        layout.add_widget(MDRaisedButton(text="Change data", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_change_data_button_press))
        self.add_widget(layout)

        # add another layout
        second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2), pos_hint={'center_x': 0.5, 'top': 0.4}, padding=(20, 0, 20, 0))
        second_layout.add_widget(MDRaisedButton(text="Hobbies", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_hobbies_button_press))
        second_layout.add_widget(MDRaisedButton(text="Disconnect", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_disconnect_button_press))
        second_layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(second_layout)

        # add the BoxLayout to the screen
        # print(App.get_running_app().root.prev_screen)
        self.conn = conn

    def update_rect(self, *args):
        """
        Updates the rect value.
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_main_screen_button_press(self, instance):
        """
        Switches to the first screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "main_screen"
        self.manager.current = "main_screen"  # Switch to the main_screen

    def on_see_data_button_press(self, instance):
        """
        Switches to the see data screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_data_screen"
        self.manager.current = "see_data_screen"  # Switch to the see_data_screen

    def on_change_data_button_press(self, instance):
        """
        Switches to the change data screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "change_data_screen"
        self.manager.current = "change_data_screen"  # Switch to the change_data_screen

    def on_hobbies_button_press(self, instance):
        """
        Switches to the hobbies screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "hobbies_screen"
        self.manager.current = "hobbies_screen"  # Switch to the hobbies_screen

    def on_disconnect_button_press(self, instance):
        """
        Doing a logout from the server, closing the client and switching to the first screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        # logout
        print("Doing a logout... \n")
        build_and_send_message(self.conn, chatlib.PROTOCOL_CLIENT['logout_msg'], "")
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)

        # screen change
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "first_screen"
        self.manager.current = "first_screen"  # Switch to friends screen
        # summary - the client sends the server a logout request and move back to *first* screen.

        self.conn.close()
        app = App.get_running_app()
        app.restart_app()

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()


class SeeDataScreen(Screen):
    def __init__(self, conn, name="see_data_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # create the message label widget
        self.message_label = Label(text="", font_size=self.width * 0.35, size_hint=(1, 0.1), pos_hint={'top': 0.55},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Settings Area - Your Data", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        # add the buttons to the BoxLayout
        # create a horizontal BoxLayout for the buttons
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.3}, padding=(20, 0, 20, 0))
        layout.add_widget(MDRaisedButton(text="Settings", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_settings_button_press))
        layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(layout)
        self.conn = conn
        # add exit button

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_enter(self):
        """
        Calling to the see data function if the previous screen is the settings screen.
        """
        global screen_flow
        print(screen_flow["prev"])
        if screen_flow["prev"] == "settings_screen":
            self.see_data()

    def see_data(self):
        """
        Asking the server to show the user's data.
        """
        cmd = chatlib.PROTOCOL_SETTINGS_CLIENT['see_data_msg']
        build_and_send_message(self.conn, cmd, "")
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)

        cmd, msg = chatlib.parse_message(data)
        if cmd == chatlib.PROTOCOL_SETTINGS_SERVER['see_data_ok_msg']:
            msg_after_split = msg.split("#")
            client_data = msg_after_split[0]
            self.message_label.text = client_data

        else:
            self.message_label.text = msg

        return data

    def on_settings_button_press(self, instance):
        """
        Switches to the settings screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "settings_screen"
        self.manager.current = "settings_screen"  # Switch to the settings_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_screen"
        App.get_running_app().stop()


class ChangeDataScreen(Screen):
    def __init__(self, conn, name="change_data_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.5, 'top': 0.75}))

        # add the label to the left of the image
        self.add_widget(Label(text="Settings Area - Change Data", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        # add the buttons to the BoxLayout
        # create a horizontal BoxLayout for the buttons
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                  pos_hint={'center_x': 0.5, 'top': 0.5}, padding=(20, 0, 20, 0))
        layout.add_widget(MDRaisedButton(text="Change name", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.change_name_press))
        layout.add_widget(MDRaisedButton(text="Change password", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.change_password_press))
        self.add_widget(layout)

        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                  pos_hint={'center_x': 0.5, 'top': 0.3}, padding=(20, 0, 20, 0))
        layout.add_widget(MDRaisedButton(text="Settings", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_back_button_press))
        layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(layout)

        self.conn = conn
        # add exit button

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_back_button_press(self, instance):
        """
        Switches to the settings screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "settings_screen"
        self.manager.current = "settings_screen"  # Switch back to the settings_screen

    def change_name_press(self, instance):  # show pop-up function
        """
        Switches to the change name screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "settings_screen"
        self.manager.current = "change_name_screen"  # Switch to the change name screen

    def change_password_press(self, instance):  # show pop-up function
        """
        Switches to the change password screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "settings_screen"
        self.manager.current = "change_password_screen"  # Switch to the change password screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_screen"
        App.get_running_app().stop()


class ChangeNameScreen(Screen):
    def __init__(self, conn, name="change_name_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.5, 'top': 0.75}))

        # add the label to the left of the image
        self.add_widget(Label(text="Settings Area - Change name", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        # create a back buttons
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.25}, padding=(20, 0, 20, 0))
        back_button = MDRaisedButton(text="Change data", size_hint=(0.1, 0.3), font_size=self.width / 4)
        back_button.bind(on_press=self.on_back_button_press)
        back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        layout.add_widget(back_button)

        layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.1, 0.3), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(layout)

        self.conn = conn
        name_layout = BoxLayout(orientation='horizontal', size_hint=(0.8, 0.1))  # create the username layout widget
        name_layout.pos_hint = {'top': 0.5, 'center_x': 0.4}  # position the name_layout just below the welcome_label

        # create the name label widget
        self.name_label = Label(text="Enter your new name: ", font_size=self.width * 0.3, size=(self.width * 0.9, self.height * 0.05),
                                size_hint=(0.7, 0.1), color=(0, 0, 1, 1))
        self.name_label.pos_hint = {'top': 0.4, 'center_x': 0.6}
        name_layout.add_widget(self.name_label)

        # create the name input widget
        self.name_input = TextInput(multiline=False, size_hint=(0.6, 0.5), size=(self.width * 0.6, self.height * 0.05),
                                    font_size=self.width * 0.15)
        name_layout.add_widget(self.name_input)
        self.add_widget(name_layout)  # add the name to the root widget

        name_button = MDRaisedButton(text="Change name", font_size=self.width*0.3, size_hint=(0.5, 0.1))
        name_button.pos_hint = {'top': 0.35, 'center_x': 0.5}
        name_button.bind(on_press=self.change_name)
        self.add_widget(name_button)

        self.message_label = Label(text="", font_size=self.width * 0.35, size_hint=(1, 0.1), pos_hint={'top': 0.23},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_back_button_press(self, instance):
        """
        Switches to the change data screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "change_data_screen"
        self.manager.current = "change_data_screen"  # Switch to the change_data_screen

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.name_input.text = ''
        self.message_label.text = ''

    def handle_server_response_to_name_input_message(self, data):
        """
        Handles the server response to a change name request.
        :param data: the data received from the server.
        """
        command, message = chatlib.parse_message(data)
        print("The message: ", (command, message))  # print in the cmd

        if data == chatlib.ERROR_RETURN or command == chatlib.PROTOCOL_SETTINGS_SERVER['change_name_failed_msg']:
            self.message_label.text = f"The name input is invalid! {message}"  # A text input on the screen.
        else:
            self.message_label.text = "Changed name successfully! "

    def change_name(self, instance):
        """
        Sends the server a change name request.
        :param instance: the button instance that triggered the event.
        """
        name = self.name_input.text
        whole_message = name
        build_and_send_message(self.conn, chatlib.PROTOCOL_SETTINGS_CLIENT['change_name_msg'], whole_message)
        # use Clock.schedule_once to wait for the server response asynchronously
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        Clock.schedule_once(lambda dt: self.handle_server_response_to_name_input_message(data))

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_screen"
        App.get_running_app().stop()


class ChangePasswordScreen(Screen):
    def __init__(self, conn, name="change_password_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.5, 'top': 0.75}))

        # add the label to the left of the image
        self.add_widget(Label(text="Settings Area - Change password", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        # create a back buttons
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.25}, padding=(20, 0, 20, 0))
        back_button = MDRaisedButton(text="Change data", size_hint=(0.1, 0.3), font_size=self.width / 4)
        back_button.bind(on_press=self.on_back_button_press)
        back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        layout.add_widget(back_button)

        layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.1, 0.3), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(layout)

        self.conn = conn
        password_layout = BoxLayout(orientation='horizontal', size_hint=(0.8, 0.1))  # create the password layout widget
        password_layout.pos_hint = {'top': 0.5, 'center_x': 0.4}  # position the name_layout just below the welcome_label

        # create the name label widget
        self.password_layout = Label(text="Enter your new password: ", font_size=self.width * 0.3, size=(self.width * 0.9, self.height * 0.05),
                                size_hint=(0.7, 0.1), color=(0, 0, 1, 1))
        self.password_layout.pos_hint = {'top': 0.4, 'center_x': 0.6}
        password_layout.add_widget(self.password_layout)

        # create the name input widget
        self.password_input = TextInput(multiline=False, size_hint=(0.6, 0.5), size=(self.width * 0.6, self.height * 0.05),
                                    font_size=self.width * 0.15)
        password_layout.add_widget(self.password_input)
        self.add_widget(password_layout)  # add the name to the root widget

        password_button = MDRaisedButton(text="Change password", font_size=self.width*0.3, size_hint=(0.5, 0.1))
        password_button.pos_hint = {'top': 0.35, 'center_x': 0.5}
        password_button.bind(on_press=self.change_password)
        self.add_widget(password_button)

        self.message_label = Label(text="", font_size=self.width * 0.35, size_hint=(1, 0.1), pos_hint={'top': 0.23},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_back_button_press(self, instance):
        """
        Switches to the change data screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "change_data_screen"
        self.manager.current = "change_data_screen"  # Switch to the change_data_screen

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.password_input.text = ''
        self.message_label.text = ''

    def handle_server_response_to_password_input_message(self, data):
        """
        Handles the server response to a change name request.
        :param data: the data received from the server.
        """
        command, message = chatlib.parse_message(data)
        print("The message: ", (command, message))  # print in the cmd

        if data == chatlib.ERROR_RETURN or command == chatlib.PROTOCOL_SETTINGS_SERVER['change_password_failed_msg']:
            self.message_label.text = f"The password input was incorrect! {message}"  # A text input on the screen.
        else:
            self.message_label.text = "Changed password successfully! "

    def change_password(self, instance):
        """
        Sends the server a change name request.
        :param instance: the button instance that triggered the event.
        """
        password = self.password_input.text
        whole_message = password
        build_and_send_message(self.conn, chatlib.PROTOCOL_SETTINGS_CLIENT['change_password_msg'], whole_message)
        # use Clock.schedule_once to wait for the server response asynchronously
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        Clock.schedule_once(lambda dt: self.handle_server_response_to_password_input_message(data))

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_screen"
        App.get_running_app().stop()


class HobbiesScreen(Screen):
    def __init__(self, conn, name="hobbies_screen", **kwargs):
        super().__init__(name=name, **kwargs)

        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Hobbies Area", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        # add the buttons to the BoxLayout
        # create a horizontal BoxLayout for the buttons
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.7}, padding=(20, 0, 20, 0))
        layout.add_widget(MDRaisedButton(text="See hobbies", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_see_hobbies_button_press))
        layout.add_widget(MDRaisedButton(text="Add hobby", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_add_hobby_button_press))
        self.add_widget(layout)

        # add another layout
        second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2), pos_hint={'center_x': 0.5, 'top': 0.5}, padding=(20, 0, 20, 0))
        second_layout.add_widget(MDRaisedButton(text="Settings", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_settings_button_press))
        second_layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(second_layout)
        self.conn = conn

        # add an image at the bottom
        self.add_widget(Image(source=hobbies_picture_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.5, 'top': 0.25}))

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_see_hobbies_button_press(self, instance):
        """
        Switches to the see hobbies screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_hobbies_screen"
        self.manager.current = "see_hobbies_screen"  # Switch to the main_screen

    def on_add_hobby_button_press(self, instance):
        """
        Switches to the add hobby screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "add_hobby_screen"
        self.manager.current = "add_hobby_screen"  # Switch to the see_data_screen

    def on_delete_hobby_button_press(self, instance):
        """
        Switches to the delete hobby screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "delete_hobby_screen"
        self.manager.current = "delete_hobby_screen"  # Switch to the change_data_screen

    def on_settings_button_press(self, instance):
        """
        Switches to the settings screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "settings_screen"
        self.manager.current = "settings_screen"  # Switch to the hobbies_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()


class AddHobbyScreen(Screen):
    def __init__(self, conn, name="add_hobby_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Hobbies Area - Add hobby", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        # Create the label widget
        self.hobby_label = Label(text='Enter hobby: ', font_size=30, size_hint=(0.4, 0.1), pos_hint={'center_x': 0.17, 'top': 0.65}, color=(0,0,1,1))
        self.hobby_textinput = TextInput(size_hint=(0.5, 0.1), pos_hint={'center_x': 0.5, 'top': 0.65})

        # Add the label and text input to the box layout
        self.add_widget(self.hobby_label)
        self.add_widget(self.hobby_textinput)

        add_hobby_button = MDRaisedButton(text="press me to add the hobby", font_size=self.width*0.3, size_hint=(0.5, 0.1))
        add_hobby_button.pos_hint = {'top': 0.5, 'center_x': 0.5}
        add_hobby_button.bind(on_press=self.add_hobby)
        self.add_widget(add_hobby_button)

        # creating a message label
        self.message_label = Label(text="", font_size=self.width * 0.35, size_hint=(1, 0.1), pos_hint={'top': 0.35},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.3}, padding=(20, 0, 20, 0))
        hobbies_back_button = MDRaisedButton(text="Hobbies", size_hint=(0.2, 0.6), font_size=self.width / 4)
        hobbies_back_button.bind(on_press=self.hobbies_back_button_press)
        hobbies_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        layout.add_widget(hobbies_back_button)
        layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(layout)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.hobby_textinput.text = ''
        self.message_label.text = ''

    def hobbies_back_button_press(self, instance):
        """
        Switches to the hobbies screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "hobbies_screen"
        self.manager.current = "hobbies_screen"  # Switch to the main_screen

    def add_hobby(self, instance):
        """
        Sends the server a request to add a hobby to the client's hobbies list.
        :param instance: the button instance that triggered the event.
        """
        wanted_hobby = self.hobby_textinput.text
        print("Asked the server to add the hobby: ", wanted_hobby)
        if wanted_hobby == "":
            self.message_label.text = f"Error! Empty hobby is invalid! "
            return

        cmd = chatlib.PROTOCOL_SETTINGS_CLIENT['add_hobby_msg']
        build_and_send_message(self.conn, cmd, wanted_hobby)
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_SETTINGS_SERVER['add_hobby_ok_msg']:
            self.message_label.text = f"Success! {msg}"  # A text input on the screen.
        elif curr_cmd == chatlib.PROTOCOL_SETTINGS_SERVER['add_hobby_failed_msg']:
            self.message_label.text = f"Error! {msg}"

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()


class SeeHobbiesScreen(Screen):
    def __init__(self, conn, name="see_hobbies_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Hobbies Area - See hobbies", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.99}, color=(0, 0, 0, 1)))

        # creating a message label
        self.message_label = Label(text="", font_size=self.width * 0.5, size_hint=(1, 0.6), pos_hint={'top': 0.6},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        # here will be the hobbies dataframe

        self.box_layout = BoxLayout(size_hint=(0.5, 0.7), pos_hint={"center_x": 0.5, "center_y": 0.5})
        self.add_widget(self.box_layout)

        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.2}, padding=(20, 0, 20, 0))

        hobbies_back_button = MDRaisedButton(text="Hobbies", size_hint=(0.2, 0.6), font_size=self.width / 4)
        hobbies_back_button.bind(on_press=self.hobbies_back_button_press)
        hobbies_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        layout.add_widget(hobbies_back_button)
        layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(layout)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.message_label.text = ''
        self.box_layout.clear_widgets()

    def hobbies_back_button_press(self, instance):
        """
        Switches to the hobbies screen.
        :param instance: the button instance that triggered the event.
        """
        self.message_label.text = ''
        self.box_layout.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "hobbies_screen"
        self.manager.current = "hobbies_screen"  # Switch to the main_screen

    def move_to_delete_hobby_screen(self):
        """
        Switches to the delete hobby screen.
        """
        self.message_label.text = ''
        self.box_layout.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "delete_hobby_screen"
        self.manager.current = "delete_hobby_screen"  # Switch to the main_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def on_enter(self):
        """
        If the last screen is the hobbies screen or the delete hobby screen,
        the function sends the server a request to see the client's hobbies list,
        and it shows the client the server response.
        """
        global screen_flow
        if screen_flow["prev"] == "hobbies_screen" or screen_flow["prev"] == "delete_hobby_screen":
            print("Asking the server to see my hobbies... \n")
            cmd = chatlib.PROTOCOL_SETTINGS_CLIENT['see_hobbies_msg']
            build_and_send_message(self.conn, cmd, "")
            data = wise_recv(self.conn)
            if data is None:
                return
            curr_cmd, msg = chatlib.parse_message(data)
            if curr_cmd == chatlib.PROTOCOL_SETTINGS_SERVER['see_hobbies_ok_msg']:
                hobbies_msg = msg.split("#")[0]

                if hobbies_msg != no_hobbies_see_msg:
                    # show the hobbies database
                    hobbies_df = pd.read_json(hobbies_msg)
                    hobbies_df.set_index(pd.Index(range(1, len(hobbies_df) + 1)), inplace=True)
                    print(hobbies_df)

                    column_name = [str(name) for name in hobbies_df.columns][0]
                    values_list = [str(hobbies_df.iloc[i][0]) for i in range(hobbies_df.shape[0])]

                    # create the MDDataTable widget
                    table = MDDataTable(
                        size_hint=(1, 1),
                        column_data=[(column_name, 200)],
                        row_data=[(d,) for d in values_list],
                        rows_num=len(values_list),
                        # check=True,
                        use_pagination=False
                    )

                    def on_row_press(instance_table, instance_row):
                        """
                        Handles a case when a row in the table is pressed,
                        specifically updated the screen flow dictionary and moves to the delete hobby screen,
                        through the move_to_delete_hobby_screen function.
                        :param instance_table: refers to the MDDataTable instance.
                        :param instance_row: refers to the row that was pressed.
                        """
                        # Display the pressed row's data
                        row_data = instance_table.row_data[instance_row.index][0]
                        print("Pressed row data:", row_data)
                        screen_flow["hobby to delete"] = row_data
                        self.move_to_delete_hobby_screen()

                    table.bind(on_row_press=on_row_press)  # Bind the custom event
                    self.box_layout.add_widget(table)

                else:
                    self.message_label.text = hobbies_msg

            else:
                self.message_label.text = msg


class DeleteHobbyScreen(Screen):
    global screen_flow

    def __init__(self, conn, name="delete_hobby_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn

        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Hobbies Area - Delete hobby", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.99}, color=(0, 0, 0, 1)))

        self.hobby_delete_or_not_label = Label(text="Do you want to delete the hobby? ", font_size=self.width * 0.5,
                                               size_hint=(1, 0.6), pos_hint={'top': 0.8},
                                               color=(0, 0, 1, 1))
        self.add_widget(self.hobby_delete_or_not_label)

        # buttons - yes or no
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.5}, padding=(20, 0, 20, 0))
        layout.add_widget(
            MDRaisedButton(text="Yes", size_hint=(0.2, 0.4), font_size=self.width / 4, on_press=self.delete_hobby))

        self.hobby_deleted_or_not = Label(text="", font_size=self.width * 0.5, size_hint=(1, 0.6),
                                          pos_hint={'top': 0.48},
                                          color=(0, 0, 1, 1))
        self.add_widget(self.hobby_deleted_or_not)

        second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                  pos_hint={'center_x': 0.5, 'top': 0.25}, padding=(20, 0, 20, 0))
        see_hobbies_back_button = MDRaisedButton(text="See hobbies", size_hint=(0.2, 0.6), font_size=self.width / 4)
        see_hobbies_back_button.bind(on_press=self.see_hobbies_back_button_press)
        see_hobbies_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        second_layout.add_widget(see_hobbies_back_button)
        second_layout.add_widget(
            MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 4, on_press=self.exit_app))

        self.add_widget(layout)
        self.add_widget(second_layout)

    def on_pre_enter(self):
        if "times_in_delete_hobby" not in screen_flow.keys():
            screen_flow["times_in_delete_hobby"] = 0
        screen_flow["times_in_delete_hobby"] += 1

        self.hobby_to_delete = screen_flow.get("hobby to delete")

        if screen_flow["times_in_delete_hobby"] == 1:
            self.hobby_message_label = Label(text=f"The hobby is: {self.hobby_to_delete}", font_size=self.width * 0.5,
                                             size_hint=(1, 0.6), pos_hint={'top': 0.9},
                                             color=(0, 0, 1, 1))
        else:
            self.hobby_message_label = Label(text=f"The hobby is: {self.hobby_to_delete}", font_size=self.width * 0.05,
                                             size_hint=(1, 0.6), pos_hint={'top': 0.9},
                                             color=(0, 0, 1, 1))

        self.add_widget(self.hobby_message_label)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.hobby_message_label.text = ''
        self.hobby_deleted_or_not.text = ''

    def see_hobbies_back_button_press(self, instance):
        """
        Switches to the see hobbies screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_hobbies_screen"
        self.manager.current = "see_hobbies_screen"  # Switch to the main_screen

    def delete_hobby(self, instance):
        """
        Asks the server to delete a specific hobby from the client's hobbies list,
        and shows to server's response on the screen.
        :param instance: the button instance that triggered the event.
        """
        hobby_to_delete = self.hobby_to_delete
        cmd = chatlib.PROTOCOL_SETTINGS_CLIENT['delete_hobby_msg']
        build_and_send_message(self.conn, cmd, hobby_to_delete)
        data = wise_recv(self.conn)
        if data is None:
            return
        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_SETTINGS_SERVER['delete_hobby_ok_msg']:
            msg_after_split = msg.split("#")
            hobbies_msg = msg_after_split[0]
            self.hobby_deleted_or_not.text = f"Success! {hobbies_msg}"

        elif curr_cmd == chatlib.PROTOCOL_SETTINGS_SERVER['delete_hobby_failed_msg']:
            self.hobby_deleted_or_not.text = f"Failed! {msg}"

    def exit_app(self, instance):
        """
        Exist the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()


class SearchScreen(Screen):
    def __init__(self, conn, name="search_screen", **kwargs):
        super().__init__(name=name, **kwargs)

        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Search Area", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        # add the buttons to the BoxLayout
        # create a horizontal BoxLayout for the buttons
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.6}, padding=(20, 0, 20, 0))
        layout.add_widget(MDRaisedButton(text="Search by username", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_search_by_username_button_press))
        layout.add_widget(MDRaisedButton(text="Search by hobbies", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_search_by_hobbies_button_press))
        self.add_widget(layout)

        # add another layout
        second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2), pos_hint={'center_x': 0.5, 'top': 0.4}, padding=(20, 0, 20, 0))
        second_layout.add_widget(MDRaisedButton(text="Main screen", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_main_screen_button_press))
        second_layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(second_layout)
        self.conn = conn

        # add an image at the bottom
        self.add_widget(Image(source=search_picture_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.5, 'top': 0.22}))

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_search_by_username_button_press(self, instance):
        """
        Switches to the search by username screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "search_by_username_screen"
        self.manager.current = "search_by_username_screen"  # Switch to the search_by_username_screen

    def on_search_by_hobbies_button_press(self, instance):
        """
        Switches to the search by hobbies screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "search_by_hobbies_screen"
        self.manager.current = "search_by_hobbies_screen"  # Switch to the search_by_hobbies_screen

    def on_main_screen_button_press(self, instance):
        """
        Switches to the main screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "main_screen"
        self.manager.current = "main_screen"  # Switch to the main_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()


# search by username screen

class SearchByUsernameScreen(Screen):
    def __init__(self, conn, name="search_by_username_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn

        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Search by username area", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        # search bar
        # username and password input boxes
        username_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.1))  # create the username layout widget
        username_layout.pos_hint = {'top': 0.7, 'center_x': 0.45}   # position the username_layout just below the welcome_label

        # create the username label widget
        self.username_label = Label(text="Username: ", font_size=self.width * 0.3, size=(self.width*0.9, self.height*0.05), size_hint=(0.2, 1), color=(0, 0, 1, 1))
        username_layout.add_widget(self.username_label)
        self.username_label.pos_hint = {'top': 0.7, 'right': 0.15}

        # create the username input widget
        self.username_input = TextInput(multiline=False, size_hint=(0.6, 0.5), size=(self.width * 0.6, self.height * 0.05),
                                   font_size=self.width * 0.15)
        username_layout.add_widget(self.username_input)
        self.add_widget(username_layout)  # add the username_layout to the root widget

        # create the message label widget
        self.message_label = Label(text="", font_size=self.width * 0.35, size_hint=(1, 0.1), pos_hint={'top': 0.4},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        # create a horizontal BoxLayout for the buttons
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.6}, padding=(20, 0, 20, 0))
        layout.add_widget(MDRaisedButton(text="Search user", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_search_user_button_press))
        self.add_widget(layout)

        # add another layout
        second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2), pos_hint={'center_x': 0.5, 'top': 0.3}, padding=(20, 0, 20, 0))
        second_layout.add_widget(MDRaisedButton(text="Search", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_search_button_press))
        second_layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(second_layout)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_search_button_press(self, instance):
        """
        Switches to the search screen.
        :param instance: the button instance that triggered the event.
        """
        self.username_input.text = ''
        self.message_label.text = ''

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "search_screen"
        self.manager.current = "search_screen"  # Switch to the search_screen

    def move_to_see_user_data_screen(self):
        """
        Switches to the see user data screen.
        """
        self.username_input.text = ''
        self.message_label.text = ''

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_user_data_screen"
        self.manager.current = "see_user_data_screen"  # Switch to the see_user_data_screen

    def handle_server_response_to_search_user_message(self, data):
        """
        Handles the server response to the search by username request, and prints it on the screen.
        :param data: The server's response to the search by username request.
        """
        command, message = chatlib.parse_message(data)
        print("The message: ", (command, message))  # print in the cmd

        if command == chatlib.PROTOCOL_SEARCH_SERVER['search_by_username_failed_msg']:
            self.message_label.text = f"The search failed! {message}"  # A text input on the screen.

        elif command == chatlib.PROTOCOL_SEARCH_SERVER['search_by_username_ok_msg']:
            self.message_label.text = "The search succeeded, such username exist in the app! "
            screen_flow["user to see"] = self.username_input.text
            self.move_to_see_user_data_screen()

    def on_search_user_button_press(self, instance):
        """
        Sends the server a request to search a specific user (by username) in the app.
        :param instance: the button instance that triggered the event.
        """
        username = self.username_input.text
        print("The username we are searching is: ", username)
        build_and_send_message(self.conn, chatlib.PROTOCOL_SEARCH_CLIENT['search_by_username_msg'], username)
        # use Clock.schedule_once to wait for the server response asynchronously
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        Clock.schedule_once(lambda dt: self.handle_server_response_to_search_user_message(data))

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()


class SearchByHobbiesScreen(Screen):
    def __init__(self, conn, name="search_by_hobbies_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Search by hobbies", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.99}, color=(0, 0, 0, 1)))

        # refresh button
        self.refresh_button = MDIconButton(icon=refresh_picture_path, size_hint=(0.05, 0.07),
                                           font_size=self.width / 4, pos_hint={'center_x': 0.84, 'top': 0.92},
                                           on_press=self.refresh_screen, icon_size="50sp")
        self.add_widget(self.refresh_button)

        self.message_label = Label(text="", font_size=self.width * 0.5, size_hint=(1, 0.6), pos_hint={'top': 0.8},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        self.box_layout = BoxLayout(size_hint=(0.5, 0.7), pos_hint={"center_x": 0.5, "center_y": 0.5})
        self.add_widget(self.box_layout)

        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.2}, padding=(20, 0, 20, 0))

        search_back_button = MDRaisedButton(text="Search", size_hint=(0.2, 0.6), font_size=self.width / 4)
        search_back_button.bind(on_press=self.search_back_button)
        search_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        layout.add_widget(search_back_button)
        layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(layout)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.box_layout.clear_widgets()
        self.message_label.text = ''

    def search_back_button(self, instance):
        """
        Moving back to the search screen.
        """
        self.box_layout.clear_widgets()
        self.message_label.text = ''
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "search_screen"
        self.manager.current = "search_screen"  # Switch to the main_screen

    def move_to_see_user_data_screen(self):
        """
        Moving forward to the see user data screen.
        """
        self.box_layout.clear_widgets()
        self.message_label.text = ''

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_user_data_screen"
        self.manager.current = "see_user_data_screen"  # Switch to the main_screen

    def refresh_screen(self, instance):
        """
        Refreshes the screen
        :param instance: the button instance that triggered the event.
        """
        self.box_layout.clear_widgets()
        self.message_label.text = ''
        self.on_enter()  # Call the on_enter method to add the widgets to the layout

    def on_enter(self):
        """
        If the previous screen is the search screen.
        the function asks the server to search by hobbies
        Specifically, asks the server for similar client by the hobbies list (search by hobbies).
        """
        global screen_flow

        if screen_flow["prev"] == "search_screen":
            print("Asking the server to see my similar clients (by hobbies) ... \n")
            cmd = chatlib.PROTOCOL_SEARCH_CLIENT['search_by_hobbies_msg']
            build_and_send_message(self.conn, cmd, "")
            data = wise_recv(self.conn)
            if data is None:
                return
            curr_cmd, msg = chatlib.parse_message(data)
            if curr_cmd == chatlib.PROTOCOL_SEARCH_SERVER['search_by_hobbies_ok_msg']:
                common_users_msg = msg.split("#")[0]
                if common_users_msg != no_similar_clients_msg:
                    # show the common users dataframe
                    common_users_df = pd.read_json(common_users_msg)
                    common_users_df.set_index(pd.Index(range(1, len(common_users_df) + 1)), inplace=True)
                    print(common_users_df)

                    column_name = [str(name) for name in common_users_df.columns][0]
                    values_list = [str(common_users_df.iloc[i][0]) for i in range(common_users_df.shape[0])]

                    # create the MDDataTable widget
                    table = MDDataTable(
                        size_hint=(1, 1),
                        column_data=[(column_name, 200)],
                        row_data=[(d,) for d in values_list],
                        rows_num=len(values_list),
                        # check=True,
                        use_pagination=False
                    )

                    def on_row_press(instance_table, instance_row):
                        """
                        Handles a case when a row in the table is pressed,
                        specifically updated the screen flow dictionary and moves to the delete hobby screen,
                        through the move_to_delete_hobby_screen function.
                        :param instance_table: refers to the MDDataTable instance.
                        :param instance_row: refers to the row that was pressed.
                        """

                        # Display the pressed row's data
                        row_data = instance_table.row_data[instance_row.index][0]
                        print("Pressed row data:", row_data)
                        screen_flow["user to see"] = row_data
                        # other stuff the client will need to keep track of, in the short term.

                        self.move_to_see_user_data_screen()

                    table.bind(on_row_press=on_row_press)  # Bind the custom event
                    self.box_layout.add_widget(table)

                else:
                    self.message_label.text = common_users_msg

            else:
                self.message_label.text = "There are no users with common hobbies to yours! "

    def exit_app(self, instance):
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()


class BorderedBoxLayout(BoxLayout):
    """
    Creating 3 boxes on the screen.
    """
    border_width = 2  # Adjust the border width as desired

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Set the border color and width
        with self.canvas.before:
            Color(0, 0, 1, 1)
            self.border = Rectangle(pos=self.pos, size=self.size, width=self.border_width)

    def on_size(self, *args):
        self.border.pos = self.pos
        self.border.size = self.size


def is_json_string(s):
    """
    Returns True if s is a json string, and False otherwise.
    :param s: a variable.
    """
    try:
        json_object = json.loads(s)
        return True
    except ValueError:
        return False


# see user data screen - an important screen! that's were you send a friendship request in the app.

class SeeUserDataScreen(Screen):
    global screen_flow

    def __init__(self, conn, name="see_user_data_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn

        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()

    def search_back_button_press(self, instance):
        """
        Switching to the search screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "search_screen"
        self.manager.current = "search_screen"  # Switch to the search_screen

    def see_friends_back_button_press(self, instance):
        """
        Switching to the see friends screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_friends_screen"
        self.manager.current = "see_friends_screen"  # Switch to the see_friends_screen

    def see_outgoing_friendship_requests_back_button_press(self, instance):
        """
        Switching to the see outgoing friendship requests screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_outgoing_friendship_requests_screen"
        self.manager.current = "see_outgoing_friendship_requests_screen"  # Switch to the see_friends_screen

    def friendship_requests_back_button_press(self, instance):
        """
        Switching to the see friendship requests screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "friendship_requests_screen"
        self.manager.current = "friendship_requests_screen"  # Switch to the search_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def on_send_friendship_request_press(self, instance):
        """
        Asks the server to send a specific user a friendship request,
        and prints the server's response on the screen.
        :param instance: the button instance that triggered the event.
        """
        username_to_send_friendship_request = screen_flow.get("user to see")
        cmd = chatlib.PROTOCOL_SEARCH_CLIENT['send_friendship_request_msg']
        build_and_send_message(self.conn, cmd, username_to_send_friendship_request)
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_SEARCH_SERVER['send_friendship_request_ok_msg']:
            self.friendship_request_sent_or_not.text = f"Success! {msg}"
        elif curr_cmd == chatlib.PROTOCOL_SEARCH_SERVER['send_friendship_request_failed_msg']:
            self.friendship_request_sent_or_not.text = f"Failed! {msg}"

    def on_approve_friendship_request_press(self, instance):
        """
        Asks the server to approve the friendship request from a specific user,
        and prints the server's response on the screen.
        :param instance: the button instance that triggered the event.
        """
        username_to_approve_friendship_request = screen_flow.get("user to see")
        cmd = chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_CLIENT['approve_friendship_request_msg']
        build_and_send_message(self.conn, cmd, username_to_approve_friendship_request)
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_SERVER['approve_friendship_request_ok_msg']:
            self.server_response_to_friendship_request_handling.text = f"Success! {msg}"
        elif curr_cmd == chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_SERVER['approve_friendship_request_failed_msg']:
            self.server_response_to_friendship_request_handling.text = f"Failed! {msg}"

    def on_reject_friendship_request_press(self, instance):
        """
        Asks the server to reject the friendship request from a specific user,
        and prints the server's response on the screen.
        :param instance: the button instance that triggered the event.
        """
        username_to_reject_friendship_request = screen_flow.get("user to see")
        cmd = chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_CLIENT['reject_friendship_request_msg']
        build_and_send_message(self.conn, cmd, username_to_reject_friendship_request)
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_SERVER['reject_friendship_request_ok_msg']:
            self.server_response_to_friendship_request_handling.text = f"Success! {msg}"
        elif curr_cmd == chatlib.PROTOCOL_FRIENDSHIP_REQUESTS_SERVER['reject_friendship_request_failed_msg']:
            self.server_response_to_friendship_request_handling.text = f"Failed! {msg}"

    def on_delete_friend_press(self, instance):
        """
        Asks the server to delete a specific friend from the client's friends list,
        and prints the server's response on the screen.
        :param instance: the button instance that triggered the event.
        """
        friend_to_delete = screen_flow.get("user to see")
        cmd = chatlib.PROTOCOL_PROFILE_CLIENT['delete_friend_msg']
        build_and_send_message(self.conn, cmd, friend_to_delete)
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_PROFILE_SERVER['delete_friend_ok_msg']:
            self.server_response_to_friend_deletion.text = f"Success! {msg}"
        elif curr_cmd == chatlib.PROTOCOL_PROFILE_SERVER['delete_friend_failed_msg']:
            self.server_response_to_friend_deletion.text = f"Failed! {msg}"

    def on_delete_friendship_request_press(self, instance):
        """
        Asks the server to delete a specific friendship request
        from the client's outgoing friendship requests list,
        and prints the server's response on the screen.
        :param instance: the button instance that triggered the event.
        """
        friend_to_delete = screen_flow.get("user to see")
        cmd = chatlib.PROTOCOL_PROFILE_CLIENT['delete_friendship_request_msg']
        build_and_send_message(self.conn, cmd, friend_to_delete)
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_PROFILE_SERVER['delete_friendship_request_ok_msg']:
            self.server_response_to_friend_deletion.text = f"Success! {msg}"
        elif curr_cmd == chatlib.PROTOCOL_PROFILE_SERVER['delete_friendship_request_failed_msg']:
            self.server_response_to_friend_deletion.text = f"Failed! {msg}"

    def refresh_screen(self, instance):
        """
        Refreshes the screen
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()
        self.on_pre_enter()
        self.on_enter()  # Call the on_enter method to add the widgets to the layout

    def on_pre_enter(self):
        """
        Shows the user's username on the screen.
        """
        global screen_flow

        if "times_in_see_user_data" not in screen_flow.keys():
            screen_flow["times_in_see_user_data"] = 0
        screen_flow["times_in_see_user_data"] += 1
        self.user_to_see = screen_flow.get("user to see")

        if screen_flow["times_in_see_user_data"] == 1:
            self.user_message_label = Label(text=f"The user is: {self.user_to_see}", font_size=self.width * 0.5,
                                            size_hint=(1, 0.6), pos_hint={'top': 0.97}, color=(0, 0, 1, 1))
        else:
            self.user_message_label = Label(text=f"The user is: {self.user_to_see}", font_size=self.width * 0.05,
                                             size_hint=(1, 0.6), pos_hint={'top': 0.97}, color=(0, 0, 1, 1))
        self.add_widget(self.user_message_label)

    def on_enter(self):
        """
        Asking the server for the specific user's data, and shows the data on the screen in 3 boxes:
        left box - the user's name and username,
        middle box - the user's hobbies,
        right box - the user's common hobbies with the requesting user.
        """
        global screen_flow

        # first design
        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="See user data area", font_size=self.width * 0.05, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.99}, color=(0, 0, 0, 1)))

        self.refresh_button = MDIconButton(icon=refresh_picture_path, size_hint=(0.05, 0.07),
                                           pos_hint={'center_x': 0.84, 'top': 0.92},
                                           on_press=self.refresh_screen, icon_size="50sp")
        self.add_widget(self.refresh_button)

        # here will be the user username

        # buttons - send friendship request, return to search and return to exit.
        self.layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'y': 0.25}, padding=(20, 0, 20, 0))

        # s_1 = "The response for the friendship request (if sent) ..."
        self.friendship_request_sent_or_not = Label(text="",
                                                    font_size=self.width * 0.02, size_hint=(1, 0.6),
                                                    pos_hint={'top': 0.5},
                                                    color=(0, 0, 1, 1))

        # s_2 = "The response from the server for your decision ... "
        self.server_response_to_friendship_request_handling = Label(text="",
                                                           font_size=self.width * 0.02, size_hint=(1, 0.6),
                                                           pos_hint={'top': 0.47},
                                                           color=(0, 0, 1, 1))

        self.server_response_to_friend_deletion = Label(text="",
                                                           font_size=self.width * 0.02, size_hint=(1, 0.6),
                                                           pos_hint={'top': 0.47},
                                                           color=(0, 0, 1, 1))

        self.add_widget(self.friendship_request_sent_or_not)
        self.add_widget(self.server_response_to_friendship_request_handling)
        self.add_widget(self.server_response_to_friend_deletion)
        self.add_widget(self.layout)

        # first widgets - for both cases
        if "prev" in screen_flow.keys():
            if screen_flow["prev"] == "search_by_username_screen" or screen_flow["prev"] == "search_by_hobbies_screen":
                self.layout.add_widget(
                    MDRaisedButton(text="Send friendship request", size_hint=(0.2, 0.4), font_size=self.width / 40,
                           on_press=self.on_send_friendship_request_press))

                second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                          pos_hint={'center_x': 0.5, 'top': 0.23}, padding=(20, 0, 20, 0))
                search_by_button = MDRaisedButton(text="Search", size_hint=(0.2, 0.6), font_size=self.width / 40)
                search_by_button.bind(on_press=self.search_back_button_press)
                search_by_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
                second_layout.add_widget(search_by_button)
                second_layout.add_widget(
                    MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 40, on_press=self.exit_app))

                self.add_widget(second_layout)

            elif screen_flow["prev"] == "friendship_requests_screen":
                # approve and reject buttons
                self.first_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                         pos_hint={'center_x': 0.5, 'top': 0.4}, padding=(20, 0, 20, 0))
                self.first_layout.add_widget(MDRaisedButton(text="Approve request", size_hint=(0.2, 0.6), font_size=self.width / 40,
                                               on_press=self.on_approve_friendship_request_press))
                self.first_layout.add_widget(MDRaisedButton(text="Reject request", size_hint=(0.2, 0.6), font_size=self.width / 40,
                                               on_press=self.on_reject_friendship_request_press))

                # going back (to friendship requests screen) or exit the app
                self.second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                          pos_hint={'center_x': 0.5, 'top': 0.23}, padding=(20, 0, 20, 0))
                friendship_requests_back_button = MDRaisedButton(text="Friendship requests", size_hint=(0.2, 0.6),
                                                 font_size=self.width / 40)
                friendship_requests_back_button.bind(on_press=self.friendship_requests_back_button_press)
                friendship_requests_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
                self.second_layout.add_widget(friendship_requests_back_button)
                self.second_layout.add_widget(
                    MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 40, on_press=self.exit_app))

                self.add_widget(self.first_layout)
                self.add_widget(self.second_layout)

            elif screen_flow["prev"] == "see_friends_screen":
                # delete friend button
                self.first_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                         pos_hint={'center_x': 0.5, 'top': 0.4}, padding=(20, 0, 20, 0))
                self.first_layout.add_widget(MDRaisedButton(text="Delete friend", size_hint=(0.2, 0.6), font_size=self.width / 40,
                                               on_press=self.on_delete_friend_press))

                # going back (to see friends screen) or exit the app
                self.second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                          pos_hint={'center_x': 0.5, 'top': 0.23}, padding=(20, 0, 20, 0))
                see_friends_back_button = MDRaisedButton(text="See friends", size_hint=(0.2, 0.6),
                                                 font_size=self.width / 40)
                see_friends_back_button.bind(on_press=self.see_friends_back_button_press)
                see_friends_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
                self.second_layout.add_widget(see_friends_back_button)
                self.second_layout.add_widget(
                    MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 40, on_press=self.exit_app))

                self.add_widget(self.first_layout)
                self.add_widget(self.second_layout)

            elif screen_flow["prev"] == "see_outgoing_friendship_requests_screen":
                # delete outgoing friendship request request button
                self.first_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                         pos_hint={'center_x': 0.5, 'top': 0.4}, padding=(20, 0, 20, 0))
                self.first_layout.add_widget(MDRaisedButton(text="Delete friendship request", size_hint=(0.2, 0.6), font_size=self.width / 40,
                                               on_press=self.on_delete_friendship_request_press))

                # going back (to see friends screen) or exit the app
                self.second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                          pos_hint={'center_x': 0.5, 'top': 0.23}, padding=(20, 0, 20, 0))
                see_friends_back_button = MDRaisedButton(text="See outgoing friendship requests", size_hint=(0.2, 0.6),
                                                 font_size=self.width / 40)
                see_friends_back_button.bind(on_press=self.see_outgoing_friendship_requests_back_button_press)
                see_friends_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
                self.second_layout.add_widget(see_friends_back_button)
                self.second_layout.add_widget(
                    MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 40, on_press=self.exit_app))

                self.add_widget(self.first_layout)
                self.add_widget(self.second_layout)

        # the user data
        self.cols = 3
        self.spacing = 10
        self.padding = 10
        self.pos_hint = {'center_y': 0.5}

        # Create the left, middle, and right boxes
        self.left_box = BorderedBoxLayout(orientation='horizontal')
        self.middle_box = BorderedBoxLayout(orientation='horizontal')
        self.right_box = BorderedBoxLayout(orientation='horizontal')

        # # Create a container box to hold the three boxes
        self.container_box = BoxLayout(orientation='horizontal')
        self.container_box.size_hint_y = 0.6
        self.container_box.add_widget(self.left_box)
        self.container_box.add_widget(self.middle_box)
        self.container_box.add_widget(self.right_box)
        self.container_box.size_hint_y = None
        self.container_box.height = dp(200)  # Adjust the height as desired
        self.container_box.pos_hint = {'y': 0.35}  # Adjust the position as desired
        #
        # # Add the container box to the grid layout
        self.add_widget(self.container_box)
        #
        # # Set the size hint for each box to make them equal in size
        # # Adjusted size_hint_x values for the boxes
        self.left_box.size_hint_x = 0.3
        self.middle_box.size_hint_x = 0.3
        self.right_box.size_hint_x = 0.3

        # Create the label in the middle box
        middle_box_text = f"{self.user_to_see}'s hobbies: "
        self.label = Label(text=middle_box_text, font_size='30sp', pos_hint={'center_x': 0.5, 'center_y': 0.58}, color=(0,0,0,1))
        self.add_widget(self.label)

        # Create the label in the right box
        client_username = ask_for_username(self.conn)
        right_box_text = f"{self.user_to_see}'s and your - {client_username}'s shared hobbies: "
        self.right_label = Label(text=right_box_text, font_size='20sp', pos_hint={'center_x': 0.85, 'center_y': 0.58}, color=(0,0,0,1))
        self.add_widget(self.right_label)

        specific_username = screen_flow.get("user to see")
        # ask for user data
        cmd = chatlib.PROTOCOL_SEARCH_CLIENT['username_data_msg']
        if screen_flow["prev"] == "search_by_username_screen":
            build_and_send_message(self.conn, cmd, search_by_username_index + "#" + specific_username)

        elif screen_flow["prev"] == "search_by_hobbies_screen":
            build_and_send_message(self.conn, cmd, search_by_username_index + "#" + specific_username)

        elif screen_flow["prev"] == "friendship_requests_screen":
            build_and_send_message(self.conn, cmd, friendship_requests_index + "#" + specific_username)

        elif screen_flow["prev"] == "see_friends_screen":
            build_and_send_message(self.conn, cmd, friends_index + "#" + specific_username)

        elif screen_flow["prev"] == "see_outgoing_friendship_requests_screen":
            build_and_send_message(self.conn, cmd, pending_outgoing_requests_index + "#" + specific_username)

        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)

        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_SEARCH_SERVER['username_data_ok_msg']:
            msg_after_split = msg.split("#")
            # showing the data on the screen
            user_basic_data_msg = msg_after_split[0]  # the basic data about the user
            client_hobbies_msg = msg_after_split[1]  # the hobbies of the client
            similar_hobbies_msg = msg_after_split[2]  # similar hobbies with the client (if there are/can be).
            # send_friendship_request_msg = msg_after_split[3]
            # show only if necessary, when the client will ask specific_username a friendship request

            # show user_basic_msg - left box
            left_label = Label(text=user_basic_data_msg, font_size='20sp')
            self.left_box.add_widget(left_label)

            # show client_hobbies_msg - middle box
            # check if client_hobbies_msg == no_hobbies_see_msg
            if client_hobbies_msg == no_hobbies_see_msg:
                middle_label = Label(text=client_hobbies_msg)
                self.middle_box.add_widget(middle_label)

            else:
                client_hobbies_df = pd.read_json(client_hobbies_msg)
                client_hobbies_df.set_index(pd.Index(range(1, len(client_hobbies_df) + 1)), inplace=True)
                print(client_hobbies_df)

                column_name = [str(name) for name in client_hobbies_df.columns][0]
                values_list = [str(client_hobbies_df.iloc[i][0]) for i in range(client_hobbies_df.shape[0])]

                # create the MDDataTable widget
                middle_table = MDDataTable(
                    size_hint=(1, None),
                    height=self.container_box.height*0.7,  # Adjust the height as desired
                    column_data=[(column_name, 200)],
                    row_data=[(d,) for d in values_list],
                    rows_num=len(values_list),
                    # check=True,
                    use_pagination=False
                )

                # Add the MDDataTable widget to the left box
                self.middle_box.add_widget(middle_table)

            # show similar_hobbies_msg - right box
            if not is_json_string(similar_hobbies_msg):
                right_label = Label(text=similar_hobbies_msg, pos_hint={'center_x': 0.85, 'center_y': 0.45}, font_size='15sp')
                self.add_widget(right_label)

            else:
                similar_hobbies_df = pd.read_json(similar_hobbies_msg)
                similar_hobbies_df.set_index(pd.Index(range(1, len(similar_hobbies_df) + 1)), inplace=True)
                print(similar_hobbies_df)

                # column name and values list
                column_name = [str(name) for name in similar_hobbies_df.columns][0]
                values_list = [str(similar_hobbies_df.iloc[i][0]) for i in range(similar_hobbies_df.shape[0])]

                # create the MDDataTable widget
                right_table = MDDataTable(
                    size_hint=(1, None),
                    height=self.container_box.height*0.7,  # Adjust the height as desired
                    column_data=[(column_name, 200)],
                    row_data=[(d,) for d in values_list],
                    rows_num=len(values_list),
                    # check=True,
                    use_pagination=False
                )

                # Add the MDDataTable widget to the right box
                self.right_box.add_widget(right_table)


class FriendshipRequestsScreen(Screen):
    def __init__(self, conn, name="friendship_requests_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Friendship requests screen", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.99}, color=(0, 0, 0, 1)))

        self.refresh_button = MDIconButton(icon=refresh_picture_path, size_hint=(0.05, 0.07),
                                           pos_hint={'center_x': 0.84, 'top': 0.92},
                                           on_press=self.refresh_screen, icon_size="50sp")
        self.add_widget(self.refresh_button)

        # creating a message label
        self.message_label = Label(text="", font_size=self.width * 0.5, size_hint=(1, 0.6), pos_hint={'top': 0.6},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        # here will be the hobbies dataframe

        self.box_layout = BoxLayout(size_hint=(0.5, 0.7), pos_hint={"center_x": 0.5, "center_y": 0.5})
        self.add_widget(self.box_layout)

        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.2}, padding=(20, 0, 20, 0))

        hobbies_back_button = MDRaisedButton(text="Main screen", size_hint=(0.2, 0.6), font_size=self.width / 4)
        hobbies_back_button.bind(on_press=self.main_screen_button_press)
        hobbies_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        layout.add_widget(hobbies_back_button)
        layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(layout)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.message_label.text = ''
        self.box_layout.clear_widgets()

    def main_screen_button_press(self, instance):
        """
        Switching to the main screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "main_screen"
        self.manager.current = "main_screen"  # Switch to the main_screen

    def move_to_see_user_data_screen(self):
        """
        Switching to the see user data screen.
        """
        self.message_label.text = ''
        self.box_layout.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_user_data_screen"
        self.manager.current = "see_user_data_screen"  # Switch to the main_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def refresh_screen(self, instance):
        """
        Refreshes the screen
        :param instance: the button instance that triggered the event.
        """
        self.message_label.text = ''
        self.box_layout.clear_widgets()
        self.on_enter()  # Call the on_enter method to add the widgets to the layout

    def on_enter(self):
        """
        If the previous screen is the main screen or the see user data screen,
        the function asks the server for the client's ingoing friendship requests list,
        and shows the server's response on the screen.
        """
        global screen_flow
        if screen_flow["prev"] == "main_screen" or screen_flow["prev"] == "see_user_data_screen":
            print("Asking the server to see my friendship requests... \n")
            cmd = chatlib.PROTOCOL_CLIENT['see_friendship_requests_msg']
            build_and_send_message(self.conn, cmd, "")
            data = wise_recv(self.conn)
            if data is None:
                return
            curr_cmd, msg = chatlib.parse_message(data)
            if curr_cmd == chatlib.PROTOCOL_SERVER['see_friendship_requests_ok_msg']:
                friendship_requests_msg = msg.split("#")[0]

                if friendship_requests_msg != no_friendship_requests:
                    # show the friendship requests database
                    friendship_requests_df = pd.read_json(friendship_requests_msg)
                    friendship_requests_df.set_index(pd.Index(range(1, len(friendship_requests_df) + 1)), inplace=True)
                    print(friendship_requests_df)

                    column_name = [str(name) for name in friendship_requests_df.columns][0]
                    values_list = [str(friendship_requests_df.iloc[i][0]) for i in range(friendship_requests_df.shape[0])]

                    # create the MDDataTable widget
                    table = MDDataTable(
                        size_hint=(1, 1),
                        column_data=[(column_name, 200)],
                        row_data=[(d,) for d in values_list],
                        rows_num=len(values_list),
                        # check=True,
                        use_pagination=False
                    )

                    def on_row_press(instance_table, instance_row):
                        """
                        Handles a case when a row in the table is pressed,
                        specifically updated the screen flow dictionary and moves to the delete hobby screen,
                        through the move_to_delete_hobby_screen function.
                        :param instance_table: refers to the MDDataTable instance.
                        :param instance_row: refers to the row that was pressed.
                        """

                        # Display the pressed row's data
                        row_data = instance_table.row_data[instance_row.index][0]
                        print("Pressed row data:", row_data)
                        screen_flow["user to see"] = row_data
                        self.move_to_see_user_data_screen()

                    table.bind(on_row_press=on_row_press)  # Bind the custom event
                    self.box_layout.add_widget(table)

                else:
                    self.message_label.text = friendship_requests_msg

            else:
                self.message_label.text = msg


# profile screens

class ProfileScreen(Screen):
    def __init__(self, conn, name="profile_screen", **kwargs):
        super().__init__(name=name, **kwargs)

        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Profile Area", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        # create the message label widget
        self.message_label = Label(text="", font_size=self.width * 0.35, size_hint=(1, 0.1), pos_hint={'top': 0.75},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        # add the buttons to the BoxLayout
        # create a horizontal BoxLayout for the buttons
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.37}, padding=(20, 0, 20, 0))
        layout.add_widget(MDRaisedButton(text="See friends", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_see_friends_button_press))
        layout.add_widget(MDRaisedButton(text="See outgoing friendship requests", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_see_outgoing_friendship_requests_press))
        self.add_widget(layout)

        # add another layout
        second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2), pos_hint={'center_x': 0.5, 'top': 0.2}, padding=(20, 0, 20, 0))
        second_layout.add_widget(MDRaisedButton(text="Main screen", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_main_screen_button_press))
        second_layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(second_layout)

        # add the BoxLayout to the screen
        # print(App.get_running_app().root.prev_screen)
        self.conn = conn

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_main_screen_button_press(self, instance):
        """
        Switching to the main screen.
        :param instance: the button instance that triggered the event.
        """
        self.container_box.clear_widgets()
        self.message_label.text = ''

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "main_screen"
        self.manager.current = "main_screen"  # Switch to the main_screen

    def on_see_friends_button_press(self, instance):
        """
        Switching to the see friends screen.
        :param instance: the button instance that triggered the event.
        """
        self.container_box.clear_widgets()
        self.message_label.text = ''

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_friends_screen"
        self.manager.current = "see_friends_screen"  # Switch to the see_friends_screen

    def on_see_outgoing_friendship_requests_press(self, instance):
        """
        Switching to the see outgoing friendship requests screen.
        :param instance: the button instance that triggered the event.
        """
        self.container_box.clear_widgets()
        self.message_label.text = ''

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_outgoing_friendship_requests_screen"
        self.manager.current = "see_outgoing_friendship_requests_screen"  # Switch to the see_outgoing_friendship_requests_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def on_enter(self):
        """
        If the previous screen is the main screen or the see friends screen or the see outgoing friendship requests screen,
        the function runs the see_data function in the class using the call self.see_data()
        """
        global screen_flow
        print(screen_flow["prev"])
        if screen_flow["prev"] == "main_screen" or screen_flow["prev"] == "see_friends_screen" or screen_flow["prev"] == "see_outgoing_friendship_requests_screen":
            self.see_data()

    def see_data(self):
        """
        Asking the server enter to the profile area, and the server's response will include the user's name and username
        the will be presented in the left box, and the client's hobbies - that will be presented in the right box.
        """
        # Create the left, middle, and right boxes
        self.left_box = BorderedBoxLayout(orientation='horizontal')
        self.right_box = BorderedBoxLayout(orientation='horizontal')

        # # Create a container box to hold the three boxes
        self.container_box = BoxLayout(orientation='horizontal')
        self.container_box.size_hint_y = 0.6
        self.container_box.add_widget(self.left_box)
        self.container_box.add_widget(self.right_box)
        self.container_box.size_hint_y = None
        self.container_box.height = dp(200)  # Adjust the height as desired
        self.container_box.pos_hint = {'y': 0.35}  # Adjust the position as desired
        #
        # # Add the container box to the grid layout
        self.add_widget(self.container_box)
        #
        # # Set the size hint for each box to make them equal in size
        # # Adjusted size_hint_x values for the boxes
        self.left_box.size_hint_x = 0.5
        self.right_box.size_hint_x = 0.5

        # Create the label in the right box
        right_box_text = f"Your hobbies: "
        self.label = Label(text=right_box_text, font_size='30sp', pos_hint={'center_x': 0.7, 'center_y': 0.58}, color=(0,0,0,1))
        self.add_widget(self.label)

        # ask for user data
        cmd = chatlib.PROTOCOL_CLIENT['profile_msg']
        build_and_send_message(self.conn, cmd, "")
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        curr_cmd, msg = chatlib.parse_message(data)

        if curr_cmd == chatlib.PROTOCOL_SERVER['profile_ok_msg']:
            msg_after_split = msg.split("#")
            # showing the data on the screen
            user_basic_data_msg = msg_after_split[0]  # the basic data about the user
            client_hobbies_msg = msg_after_split[1]  # the hobbies of the client

            # show only if necessary, when the client will ask specific_username a friendship request
            # show user_basic_msg - left box
            left_label = Label(text=user_basic_data_msg, font_size='20sp')
            self.left_box.add_widget(left_label)

            # show client_hobbies_msg - middle box
            # check if client_hobbies_msg == no_hobbies_see_msg
            if client_hobbies_msg == no_hobbies_see_msg:
                middle_label = Label(text=client_hobbies_msg)
                self.right_box.add_widget(middle_label)

            else:
                client_hobbies_df = pd.read_json(client_hobbies_msg)
                client_hobbies_df.set_index(pd.Index(range(1, len(client_hobbies_df) + 1)), inplace=True)
                print(client_hobbies_df)

                column_name = [str(name) for name in client_hobbies_df.columns][0]
                values_list = [str(client_hobbies_df.iloc[i][0]) for i in range(client_hobbies_df.shape[0])]

                # create the MDDataTable widget
                right_table = MDDataTable(
                    size_hint=(1, None),
                    height=self.container_box.height*0.7,  # Adjust the height as desired
                    column_data=[(column_name, 200)],
                    row_data=[(d,) for d in values_list],
                    rows_num=len(values_list),
                    # check=True,
                    use_pagination=False
                )

                # Add the MDDataTable widget to the left box
                self.right_box.add_widget(right_table)

        # elif curr_cmd == chatlib.PROTOCOL_SEARCH_SERVER['username_data_failed_msg']:
        #     pass - add a label.


class SeeFriendsScreen(Screen):
    def __init__(self, conn, name="see_friends_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Profile area - see friends", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.99}, color=(0, 0, 0, 1)))

        # refresh button
        self.refresh_button = MDIconButton(icon=refresh_picture_path, size_hint=(0.05, 0.07),
                                           pos_hint={'center_x': 0.84, 'top': 0.92},
                                           on_press=self.refresh_screen, icon_size="50sp")
        self.add_widget(self.refresh_button)

        # creating a message label
        self.message_label = Label(text="", font_size=self.width * 0.5, size_hint=(1, 0.6), pos_hint={'top': 0.6},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        # here will be the hobbies dataframe

        self.box_layout = BoxLayout(size_hint=(0.5, 0.7), pos_hint={"center_x": 0.5, "center_y": 0.5})
        self.add_widget(self.box_layout)

        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.2}, padding=(20, 0, 20, 0))

        profile_back_button = MDRaisedButton(text="Profile", size_hint=(0.2, 0.6), font_size=self.width / 4)
        profile_back_button.bind(on_press=self.profile_button_press)
        profile_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        layout.add_widget(profile_back_button)
        layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(layout)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.message_label.text = ''
        self.box_layout.clear_widgets()

    def profile_button_press(self, instance):
        """
        Switching to the profile screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "profile_screen"
        self.manager.current = "profile_screen"  # Switch to the profile_screen

    def move_to_see_user_data_screen(self):
        """
        Switching to the see user data screen.
        """
        self.message_label.text = ''
        self.box_layout.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_user_data_screen"
        self.manager.current = "see_user_data_screen"  # Switch to the main_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def refresh_screen(self, instance):
        """
        Refreshes the screen
        :param instance: the button instance that triggered the event.
        """
        self.message_label.text = ''
        self.box_layout.clear_widgets()
        self.on_enter()  # Call the on_enter method to add the widgets to the layout

    def on_enter(self):
        """
        If the previous screen is the profile screen or the see user data screen,
        the function will ask the server for the client's friends list,
        and show the server's response on the app as a text if the server sent that the client has no friends in the app,
        and as a scrollable table otherwise.
        """
        global screen_flow
        if screen_flow["prev"] == "profile_screen" or screen_flow["prev"] == "see_user_data_screen":
            print("Asking the server to see my friends list... \n")
            cmd = chatlib.PROTOCOL_PROFILE_CLIENT['see_friends_msg']
            build_and_send_message(self.conn, cmd, "")
            data = wise_recv(self.conn)
            if data is None:
                return
            curr_cmd, msg = chatlib.parse_message(data)
            if curr_cmd == chatlib.PROTOCOL_PROFILE_SERVER['see_friends_ok_msg']:
                friends_msg = msg.split("#")[0]

                if friends_msg != no_friends:
                    # show the friendship requests data-frame.
                    friends_df = pd.read_json(friends_msg)
                    friends_df.set_index(pd.Index(range(1, len(friends_df) + 1)), inplace=True)
                    print(friends_df)

                    column_name = [str(name) for name in friends_df.columns][0]
                    values_list = [str(friends_df.iloc[i][0]) for i in range(friends_df.shape[0])]

                    # create the MDDataTable widget
                    table = MDDataTable(
                        size_hint=(1, 1),
                        column_data=[(column_name, 200)],
                        row_data=[(d,) for d in values_list],
                        rows_num=len(values_list),
                        # check=True,
                        use_pagination=False
                    )

                    def on_row_press(instance_table, instance_row):
                        """
                        Handles a case when a row in the table is pressed,
                        specifically updated the screen flow dictionary and moves to the delete hobby screen,
                        through the move_to_delete_hobby_screen function.
                        :param instance_table: refers to the MDDataTable instance.
                        :param instance_row: refers to the row that was pressed.
                        """

                        # Display the pressed row's data
                        row_data = instance_table.row_data[instance_row.index][0]
                        print("Pressed row data:", row_data)
                        screen_flow["user to see"] = row_data
                        self.move_to_see_user_data_screen()

                    table.bind(on_row_press=on_row_press)  # Bind the custom event
                    self.box_layout.add_widget(table)

                else:
                    self.message_label.text = friends_msg

            else:
                self.message_label.text = msg


class SeeOutgoingFriendshipRequestsScreen(Screen):
    def __init__(self, conn, name="see_outgoing_friendship_requests_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Profile area - see outgoing friendship requests", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.99}, color=(0, 0, 0, 1)))

        # refresh button
        self.refresh_button = MDIconButton(icon=refresh_picture_path, size_hint=(0.05, 0.07),
                                           pos_hint={'center_x': 0.84, 'top': 0.92},
                                           on_press=self.refresh_screen, icon_size="50sp")
        self.add_widget(self.refresh_button)

        # creating a message label
        self.message_label = Label(text="", font_size=self.width * 0.5, size_hint=(1, 0.6), pos_hint={'top': 0.6},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        # here will be the hobbies dataframe

        self.box_layout = BoxLayout(size_hint=(0.5, 0.7), pos_hint={"center_x": 0.5, "center_y": 0.5})
        self.add_widget(self.box_layout)

        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.2}, padding=(20, 0, 20, 0))

        profile_back_button = MDRaisedButton(text="Profile", size_hint=(0.2, 0.6), font_size=self.width / 4)
        profile_back_button.bind(on_press=self.profile_button_press)
        profile_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        layout.add_widget(profile_back_button)
        layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(layout)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.message_label.text = ''
        self.box_layout.clear_widgets()

    def profile_button_press(self, instance):
        """
        Switching to the profile screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "profile_screen"
        self.manager.current = "profile_screen"  # Switch to the profile_screen

    def move_to_see_user_data_screen(self):
        """
        Switching to the see user data screen.
        """
        self.message_label.text = ''
        self.box_layout.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_user_data_screen"
        self.manager.current = "see_user_data_screen"  # Switch to the main_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def refresh_screen(self, instance):
        """
        Refreshes the screen
        :param instance: the button instance that triggered the event.
        """
        self.message_label.text = ''
        self.box_layout.clear_widgets()
        self.on_enter()  # Call the on_enter method to add the widgets to the layout

    def on_enter(self):
        """
        If the previous screen is the profile screen or the see user data screen,
        the function will ask the server for the client's outgoing friendship requests list,
        and show the server's response on the app as a text if the server sent that the client currently doesn't have
        any pending outgoing friendship requests in the app, and as a scrollable table otherwise.
        """
        global screen_flow
        if screen_flow["prev"] == "profile_screen" or screen_flow["prev"] == "see_user_data_screen":
            print("Asking the server to see my outgoing friendship requests list... \n")
            cmd = chatlib.PROTOCOL_PROFILE_CLIENT['see_pending_outgoing_requests_msg']
            build_and_send_message(self.conn, cmd, "")
            data = wise_recv(self.conn)
            if data is None:
                return
            curr_cmd, msg = chatlib.parse_message(data)
            if curr_cmd == chatlib.PROTOCOL_PROFILE_SERVER['see_pending_outgoing_requests_ok_msg']:
                pending_outgoing_friendship_requests_msg = msg.split("#")[0]

                if pending_outgoing_friendship_requests_msg != no_pending_outgoing_requests:
                    # show the friendship requests database
                    pending_outgoing_friendship_requests_df = pd.read_json(pending_outgoing_friendship_requests_msg)
                    pending_outgoing_friendship_requests_df.set_index(pd.Index(range(1, len(pending_outgoing_friendship_requests_df) + 1)), inplace=True)
                    print(pending_outgoing_friendship_requests_df)

                    column_name = [str(name) for name in pending_outgoing_friendship_requests_df.columns][0]
                    values_list = [str(pending_outgoing_friendship_requests_df.iloc[i][0]) for i in range(pending_outgoing_friendship_requests_df.shape[0])]

                    # create the MDDataTable widget
                    table = MDDataTable(
                        size_hint=(1, 1),
                        column_data=[(column_name, 200)],
                        row_data=[(d,) for d in values_list],
                        rows_num=len(values_list),
                        # check=True,
                        use_pagination=False
                    )

                    def on_row_press(instance_table, instance_row):
                        """
                        Handles a case when a row in the table is pressed,
                        specifically updated the screen flow dictionary and moves to the delete hobby screen,
                        through the move_to_delete_hobby_screen function.
                        :param instance_table: refers to the MDDataTable instance.
                        :param instance_row: refers to the row that was pressed.
                        """

                        # Display the pressed row's data
                        row_data = instance_table.row_data[instance_row.index][0]
                        print("Pressed row data:", row_data)
                        screen_flow["user to see"] = row_data
                        self.move_to_see_user_data_screen()

                    table.bind(on_row_press=on_row_press)  # Bind the custom event
                    self.box_layout.add_widget(table)

                else:
                    self.message_label.text = pending_outgoing_friendship_requests_msg

            else:
                self.message_label.text = msg


# tasks screens

class TasksScreen(Screen):
    def __init__(self, conn, name="tasks_screen", **kwargs):
        super().__init__(name=name, **kwargs)

        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Tasks Area", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        # add the buttons to the BoxLayout
        # create a horizontal BoxLayout for the buttons
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.6}, padding=(20, 0, 20, 0))
        layout.add_widget(MDRaisedButton(text="See tasks", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_see_tasks_button_press))
        layout.add_widget(MDRaisedButton(text="Add new task", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_add_new_task_button_press))
        self.add_widget(layout)

        # add another layout
        second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2), pos_hint={'center_x': 0.5, 'top': 0.4}, padding=(20, 0, 20, 0))
        second_layout.add_widget(MDRaisedButton(text="Main screen", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_main_screen_button_press))
        second_layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(second_layout)

        self.conn = conn

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_main_screen_button_press(self, instance):
        """
        Switching to the see main screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "main_screen"
        self.manager.current = "main_screen"  # Switch to the main_screen

    def on_see_tasks_button_press(self, instance):
        """
        Switching to the see tasks screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_tasks_screen"
        self.manager.current = "see_tasks_screen"  # Switch to the see_tasks_screen

    def on_add_new_task_button_press(self, instance):
        """
        Switching to the add new task screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "change_data_screen"
        self.manager.current = "add_new_task_screen"  # Switch to the add_new_task_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()


class AddNewTaskScreen(Screen):
    def __init__(self, conn, name="add_new_task_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn

        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Tasks area - add new task", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        # date input box
        self.date_label = Label(text='Pick the date (day/month/year): ', font_size=30, size_hint=(0.4, 0.1),
                                pos_hint={'center_x': 0.2, 'top': 0.67}, color=(0, 0, 1, 1))
        self.date_input = TextInput(size_hint=(0.5, 0.05), pos_hint={'center_x': 0.6, 'top': 0.65})
        self.add_widget(self.date_label)
        self.add_widget(self.date_input)

        # task info input box
        self.info_label = Label(text='Pick the info of the task (unique): ', font_size=30, size_hint=(0.4, 0.1),
                                pos_hint={'center_x': 0.2, 'top': 0.57}, color=(0, 0, 1, 1))
        self.info_input = TextInput(size_hint=(0.5, 0.05), pos_hint={'center_x': 0.6, 'top': 0.55})
        self.add_widget(self.info_label)
        self.add_widget(self.info_input)

        # create the message label widget
        self.message_label = Label(text="", font_size=self.width * 0.35, size_hint=(1, 0.1), pos_hint={'top': 0.3},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        # create a horizontal BoxLayout for the buttons
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.5}, padding=(20, 0, 20, 0))
        layout.add_widget(MDRaisedButton(text="Add task", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_add_task_button_press))
        self.add_widget(layout)

        # add another layout
        second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2), pos_hint={'center_x': 0.5, 'top': 0.2}, padding=(20, 0, 20, 0))
        second_layout.add_widget(MDRaisedButton(text="Tasks", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_tasks_button_press))
        second_layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(second_layout)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_tasks_button_press(self, instance):
        """
        Switching to the tasks screen.
        :param instance: the button instance that triggered the event.
        """
        self.date_input.text = ''
        self.info_input.text = ''
        self.message_label.text = ''

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "tasks_screen"
        self.manager.current = "tasks_screen"  # Switch to the tasks_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def on_add_task_button_press(self, instance):
        """
        The function extracts the date and info of the task from the date_input the info_input respectively,
        and if the validity check will go well (otherwise an error msg will be printed),
        it'll send a request to the server to add a task to the client's task calendar,
        with date=the text in date_input, info = the text in info_input.

        :param instance: the button instance that triggered the event.
        """
        print("Asking the server to add a new task... ")

        task_date = self.date_input.text
        task_info = self.info_input.text

        if not val_date(task_date):
            self.message_label.text = "ERROR! Wrong format Enter again the date of the task: (in DD/MM/YYYY) ... "

        else:
            if not is_date_after_today_add_new_task(task_date):
                self.message_label.text = "ERROR! The date you entered is invalid! "

            else:
                # no date before today

                if task_info == "":
                    self.message_label.text = "ERROR! Empty task info is invalid! "

                elif "#" in task_info or "^" in task_info:
                    self.message_label.text = "ERROR! Info with # or ^ is invalid! "

                else:
                    build_and_send_message(self.conn, chatlib.PROTOCOL_TASKS_CLIENT['new_task_msg'], task_date + "#" + task_info)
                    data = wise_recv(self.conn)
                    if data is None:
                        sys.exit(1)
                    curr_cmd, msg = chatlib.parse_message(data)
                    if curr_cmd == chatlib.PROTOCOL_TASKS_SERVER['new_task_ok_msg']:
                        self.message_label.text = f"Success! {msg} "
                    elif curr_cmd == chatlib.PROTOCOL_TASKS_SERVER['new_task_failed_msg']:
                        self.message_label.text = f"Failed! {msg} "


class SeeTasksScreen(Screen):
    def __init__(self, conn, name="see_tasks_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()

    def tasks_back_button_press(self, instance):
        """
        Switching to the tasks screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "tasks_screen"
        self.manager.current = "tasks_screen"  # Switch to the tasks_screen

    def move_to_see_specific_task_screen(self):
        """
        Switching to the see specific task screen.
        """
        self.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_specific_task_screen"
        self.manager.current = "see_specific_task_screen"  # Switch to the see_specific_task_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def on_choose_task_button_press(self, instance):
        """
        The function checks if the index that is the text in the task_input widget in the class is valid.
        If it is not valid, an error msg will be presented on the screen.
        Otherwise, the global dictionary screen_flow will be updated with the new task to see,
        and the function will call the move_to_see_specific_task_screen() fucntion,
        in order to move to the see_specific_task screen

        :param instance: the button instance that triggered the event.
        """
        index = self.task_input.text
        if not index.isdigit():
            self.task_message_label.text = "Not valid input! You need to enter a valid index! "
            print("Invalid index")
        else:
            real_index = int(index) - 1
            if 0 <= real_index < len(self.all_tasks_table.row_data):
                # Index is in the valid range
                row_data = self.all_tasks_table.row_data[real_index]
                print("The row that the client chose: ",  row_data)
                screen_flow["specific task to see"] = list(row_data[1:])
                self.move_to_see_specific_task_screen()

            else:
                self.task_message_label.text = "Not valid input! You need to enter a valid index! "
                print("Invalid index")

    def refresh_screen(self, instance):
        """
        Refreshes the screen
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()
        self.on_enter()  # Call the on_enter method to add the widgets to the layout

    def build_tasks_data_frame(self, tasks_msg):
        """
        Builds a MDDataTable based on the data from the json string called tasks_msg
        :param tasks_msg: a json string
        """
        tasks_df = pd.read_json(tasks_msg)
        tasks_df.set_index(pd.Index(range(1, len(tasks_df) + 1)), inplace=True)
        print(tasks_df)

        # Get the column names from the DataFrame
        column_names = [str(name) for name in tasks_df.columns]

        column_data = [("Index", 30)]
        for name in column_names:
            column_data.append((name, 30))

        # Get the values for each row in the DataFrame
        values_list = []
        for i in range(tasks_df.shape[0]):
            row_values = [str(tasks_df.iloc[i][col]) for col in column_names]
            values_list.append(tuple(row_values))

        print(values_list)
        print("Number of values:", len(values_list))

        # Create the MDDataTable widget
        tasks_table = MDDataTable(
            size_hint=(1, 0.6),
            column_data=column_data,
            row_data=[(str(index), *row) for index, row in enumerate(values_list, start=1)],
            rows_num=len(values_list),
            use_pagination=False
        )

        return tasks_table

    def on_enter(self):
        """
        If the previous screen is the tasks_screen or the see_specific_task_screen,
        A request to the server to see the client's tasks calendar will be sent.
        Then, the server's response will be shown on the screen with respect to the server's msg.
        """
        global screen_flow
        # first design
        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Tasks area - See tasks", font_size=self.width * 0.05, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.99}, color=(0, 0, 0, 1)))

        self.refresh_button = MDIconButton(icon=refresh_picture_path, size_hint=(0.05, 0.07),
                                           pos_hint={'center_x': 0.84, 'top': 0.92},
                                           on_press=self.refresh_screen, icon_size="50sp")
        self.add_widget(self.refresh_button)

        # creating a message label
        self.message_label = Label(text="", font_size=self.width * 0.03, size_hint=(1, 0.6), pos_hint={'top': 0.6},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        # here will be the tasks and unfinished tasks dataframe

        # case 1 - there aren't unfinished tasks
        self.all_tasks_case1_layout = BoxLayout(size_hint=(0.5, 0.7), pos_hint={"center_x": 0.5, "center_y": 0.75})
        self.add_widget(self.all_tasks_case1_layout)

        # case 2 - there are unfinished tasks
        self.all_tasks_case2_layout = BoxLayout(size_hint=(0.3, 0.5), pos_hint={"center_x": 0.77, "center_y": 0.75})
        self.add_widget(self.all_tasks_case2_layout)

        self.unfinished_tasks_layout = BoxLayout(size_hint=(0.3, 0.5), pos_hint={"center_x": 0.4, "center_y": 0.75})
        self.add_widget(self.unfinished_tasks_layout)

        if screen_flow["prev"] == "tasks_screen" or screen_flow["prev"] == "see_specific_task_screen":
            print("Asking the server to see my tasks calendar... \n")
            cmd = chatlib.PROTOCOL_TASKS_CLIENT['see_tasks_calendar_msg']
            build_and_send_message(self.conn, cmd, "")
            data = wise_recv(self.conn)
            if data is None:
                return
            curr_cmd, msg = chatlib.parse_message(data)
            if curr_cmd == chatlib.PROTOCOL_TASKS_SERVER['see_tasks_calendar_ok_msg']:
                tasks_msg = msg.split("#")

                if tasks_msg[0] != no_tasks_see_msg:
                    # first design
                    task_layout = BoxLayout(orientation='horizontal',
                                            size_hint=(1, 0.1))  # create the username layout widget
                    task_layout.pos_hint = {'top': 0.4,
                                            'center_x': 0.45}  # position the username_layout just below the welcome_label

                    # Create the label widget
                    self.task_label = Label(text='Enter index: ', font_size=30, size_hint=(0.4, 0.1),
                                             pos_hint={'center_x': 0.17, 'top': 0.33}, color=(0, 0, 1, 1))
                    self.task_input = TextInput(size_hint=(0.5, 0.05), pos_hint={'center_x': 0.5, 'top': 0.3})
                    self.add_widget(self.task_label)
                    self.add_widget(self.task_input)

                    # creating a message label
                    self.task_message_label = Label(text="", font_size=self.width * 0.03, size_hint=(1, 0.6),
                                                    pos_hint={'top': 0.5},
                                                    color=(0, 0, 1, 1))
                    self.add_widget(self.task_message_label)

                    buttons_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                       pos_hint={'center_x': 0.5, 'top': 0.2}, padding=(20, 0, 20, 0))

                    tasks_back_button = MDRaisedButton(text="Tasks", size_hint=(0.2, 0.6), font_size=self.width / 40)
                    tasks_back_button.bind(on_press=self.tasks_back_button_press)
                    tasks_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
                    buttons_layout.add_widget(tasks_back_button)
                    buttons_layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 40,
                                                     on_press=self.exit_app))
                    buttons_layout.add_widget(MDRaisedButton(text="Choose task", size_hint=(0.2, 0.6), font_size=self.width / 40,
                                                     on_press=self.on_choose_task_button_press))
                    self.add_widget(buttons_layout)

                    # show the tasks dataframe or dataframes
                    if len(tasks_msg) == 1:
                        self.all_tasks_table = self.build_tasks_data_frame(tasks_msg[0])
                        self.all_tasks_case1_layout.add_widget(self.all_tasks_table)

                    elif len(tasks_msg) == 2:
                        self.all_tasks_table = self.build_tasks_data_frame(tasks_msg[0])
                        self.all_tasks_case2_layout.add_widget(self.all_tasks_table)

                        self.unfinished_tasks_table = self.build_tasks_data_frame(tasks_msg[1])
                        self.unfinished_tasks_layout.add_widget(self.unfinished_tasks_table)

                        # creating a message labels
                        self.all_tasks_label = Label(text="All the tasks", font_size=self.width * 0.03, size_hint=(1, 0.6),
                                                     pos_hint={"center_x": 0.77, "center_y": 0.45},
                                                     color=(0, 0, 1, 1))
                        self.add_widget(self.all_tasks_label)

                        self.unfinished_tasks_label = Label(text="Unfinished tasks", font_size=self.width * 0.03,
                                                            size_hint=(1, 0.6),
                                                            pos_hint={"center_x": 0.4, "center_y": 0.45},
                                                            color=(0, 0, 1, 1))
                        self.add_widget(self.unfinished_tasks_label)

                else:
                    self.message_label.text = tasks_msg[0]

                    layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                       pos_hint={'center_x': 0.5, 'top': 0.2}, padding=(20, 0, 20, 0))

                    tasks_back_button = MDRaisedButton(text="Tasks", size_hint=(0.2, 0.6), font_size=self.width / 40)
                    tasks_back_button.bind(on_press=self.tasks_back_button_press)
                    tasks_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
                    layout.add_widget(tasks_back_button)
                    layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 40,
                                                     on_press=self.exit_app))

                    self.add_widget(layout)

            else:
                self.message_label.text = msg


class SeeSpecificTaskScreen(Screen):
    def __init__(self, conn, name="see_specific_task_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="See specific Task area", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.99}, color=(0, 0, 0, 1)))

        # creating a message label
        self.specific_task_label = Label(text="", font_size=self.width * 0.5, size_hint=(1, 0.6), pos_hint={'top': 0.65},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.specific_task_label)

        # here will be the hobbies dataframe

        self.box_layout = BoxLayout(size_hint=(0.5, 0.4), pos_hint={"center_x": 0.5, "center_y": 0.63})
        self.add_widget(self.box_layout)

        first_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                 pos_hint={'center_x': 0.5, 'top': 0.4}, padding=(20, 0, 20, 0))

        first_layout.add_widget(MDRaisedButton(text="Edit task", size_hint=(0.2, 0.6), font_size=self.width / 4,
                                       on_press=self.on_edit_task_button_press))
        first_layout.add_widget(MDRaisedButton(text="Delete task", size_hint=(0.2, 0.6), font_size=self.width / 4,
                                       on_press=self.on_delete_task_button_press))
        self.add_widget(first_layout)

        second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                  pos_hint={'center_x': 0.5, 'top': 0.25}, padding=(20, 0, 20, 0))

        tasks_back_button = MDRaisedButton(text="See tasks", size_hint=(0.2, 0.6), font_size=self.width / 4)
        tasks_back_button.bind(on_press=self.see_tasks_back_button_press)
        tasks_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        second_layout.add_widget(tasks_back_button)
        second_layout.add_widget(
            MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(second_layout)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.specific_task_label.text = ''
        self.box_layout.clear_widgets()

    def see_tasks_back_button_press(self, instance):
        """
        Switching to the see tasks screen.
        :param instance: the button instance that triggered the event.
        """
        self.specific_task_label.text = ''
        self.box_layout.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_tasks_screen"
        self.manager.current = "see_tasks_screen"  # Switch to the see_tasks_screen

    def on_delete_task_button_press(self, instance):
        """
        Sends the server a request to delete the task that was chosen in the see tasks screen,
        and shows the server's response on the screen. If the task was deleted successfully,
        the screen will be switched to the delete task screen.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        cmd = chatlib.PROTOCOL_TASKS_CLIENT['delete_task_msg']
        msg_to_server = screen_flow["specific task to see"][0] + "#" + screen_flow["specific task to see"][1] + "#" + screen_flow["specific task to see"][2] + "#" + screen_flow["specific task to see"][3] + "#" + screen_flow["specific task to see"][4]
        build_and_send_message(self.conn, cmd, msg_to_server)

        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_TASKS_SERVER['delete_task_ok_msg']:
            self.specific_task_label.text = f"Success! {msg}"

            self.specific_task_label.text = ''
            self.box_layout.clear_widgets()

            screen_flow["prev"] = screen_flow["current"]
            screen_flow["current"] = "see_tasks_screen"
            self.manager.current = "see_tasks_screen"  # Switch to the see_tasks_screen

        elif curr_cmd == chatlib.PROTOCOL_TASKS_SERVER['delete_task_failed_msg']:
            self.specific_task_label.text = f"Failed! {msg}"

    def on_edit_task_button_press(self, instance):
        """
        Switching to the edit specific task screen.
        :param instance: the button instance that triggered the event.
        """
        self.specific_task_label.text = ''
        self.box_layout.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "edit_specific_task_screen"
        self.manager.current = "edit_specific_task_screen"  # Switch to the edit_specific_task_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def on_enter(self):
        """
        Shows on the screen the specific task the client chose in the see tasks screen.
        """
        global screen_flow
        tasks_first_dict = screen_flow["specific task to see"]
        tasks_dict_right_keys = {"day": tasks_first_dict[0], "month": tasks_first_dict[1], "year": tasks_first_dict[2], "info": tasks_first_dict[3], "did_finish": tasks_first_dict[4]}
        tasks_df = pd.DataFrame([tasks_dict_right_keys])
        tasks_df.set_index(pd.Index(range(1, len(tasks_df) + 1)), inplace=True)
        print(tasks_df)

        # Get the column names from the DataFrame
        column_names = [str(name) for name in tasks_df.columns]
        print(column_names)

        # Get the values for each row in the DataFrame
        values_list = []
        for i in range(tasks_df.shape[0]):
            row_values = [str(tasks_df.iloc[i][col]) for col in column_names]
            values_list.append(tuple(row_values))
        print(values_list)

        # Create the column data for the MDDataTable
        column_data = [(name, 30) for name in column_names]

        # Create the MDDataTable widget
        table = MDDataTable(
            size_hint=(1, 1),
            column_data=column_data,
            row_data=values_list,
            rows_num=len(values_list),
            use_pagination=False
        )
        self.box_layout.add_widget(table)


class EditSpecificTaskScreen(Screen):
    def __init__(self, conn, name="edit_specific_task_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Tasks area - Edit task", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.99}, color=(0, 0, 0, 1)))

        self.box_layout = BoxLayout(size_hint=(0.5, 0.2), pos_hint={"center_x": 0.5, "center_y": 0.7})
        self.add_widget(self.box_layout)

        # here will be the task dataframe
        # the edit inputs --> date, info and did finish input boxes

        # date input box
        self.date_label = Label(text='Pick the date (day/month/year): ', font_size=30, size_hint=(0.4, 0.1),
                                pos_hint={'center_x': 0.2, 'top': 0.57}, color=(0, 0, 1, 1))
        self.date_input = TextInput(size_hint=(0.5, 0.05), pos_hint={'center_x': 0.6, 'top': 0.55})
        self.add_widget(self.date_label)
        self.add_widget(self.date_input)

        # info input box
        self.info_label = Label(text='Info: ', font_size=30, size_hint=(0.4, 0.1),
                                pos_hint={'center_x': 0.33, 'top': 0.49}, color=(0, 0, 1, 1))
        self.info_input = TextInput(size_hint=(0.5, 0.05), pos_hint={'center_x': 0.6, 'top': 0.47})
        self.add_widget(self.info_label)
        self.add_widget(self.info_input)

        # did finish input box
        self.did_finish_label = Label(text='Did finish: ', font_size=30, size_hint=(0.4, 0.1),
                                pos_hint={'center_x': 0.3, 'top': 0.42}, color=(0, 0, 1, 1))
        self.did_finish_input = TextInput(size_hint=(0.5, 0.05), pos_hint={'center_x': 0.6, 'top': 0.4})
        self.add_widget(self.did_finish_label)
        self.add_widget(self.did_finish_input)

        # create the 'edit the task' msg label
        self.edit_the_task_response_label = Label(text="", font_size=self.width * 0.25, size_hint=(1, 0.1), pos_hint={'top': 0.37},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.edit_the_task_response_label)

        # create a horizontal BoxLayout for the buttons
        first_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.1),
                           pos_hint={'center_x': 0.5, 'top': 0.3}, padding=(20, 0, 20, 0))
        first_layout.add_widget(MDRaisedButton(text="Edit the task", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_edit_the_task_button_press))
        self.add_widget(first_layout)

        second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                  pos_hint={'center_x': 0.5, 'top': 0.2}, padding=(20, 0, 20, 0))
        tasks_back_button = MDRaisedButton(text="See specific task", size_hint=(0.2, 0.6), font_size=self.width / 4)
        tasks_back_button.bind(on_press=self.on_see_specific_task_back_button_press)
        tasks_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        second_layout.add_widget(tasks_back_button)
        second_layout.add_widget(
            MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(second_layout)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.edit_the_task_response_label.text = ''
        self.info_input.text = ''
        self.date_input.text = ''
        self.did_finish_input.text = ''
        self.box_layout.clear_widgets()

    def on_see_specific_task_back_button_press(self, instance):
        """
        Switching to the see specific task screen.
        :param instance: the button instance that triggered the event.
        """
        self.edit_the_task_response_label.text = ''
        self.info_input.text = ''
        self.date_input.text = ''
        self.did_finish_input.text = ''
        self.box_layout.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_specific_task_screen"
        self.manager.current = "see_specific_task_screen"  # Switch to the see_specific_task_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def edit_did_finish(self, cmd, whole_task_str, new_did_finish):
        """
        Asks the server to change the did_finish state of the specific task
        :param cmd: the command that will be sent to the server.
        :param whole_task_str: the task that will be changed.
        :param new_did_finish: the new did_finish state of the task, as requested from the client
        """

        msg_to_server = "did_finish" + "#" + new_did_finish + "#" + whole_task_str
        build_and_send_message(self.conn, cmd, msg_to_server)

        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_TASKS_SERVER['edit_task_ok_msg']:
            self.edit_the_task_response_label.text = f"Success! {msg}"
            screen_flow["specific task to see"][4] = new_did_finish
        elif curr_cmd == chatlib.PROTOCOL_TASKS_SERVER['edit_task_failed_msg']:
            self.edit_the_task_response_label.text = f"ERROR! {msg}"

    def edit_date(self, cmd, whole_task_str, new_date):
        """
        Asks the server to change the date of the specific task
        :param cmd: the command that will be sent to the server.
        :param whole_task_str: the task that will be changed.
        :param new_date: the new date of the task, as requested from the client
        """

        if not val_date(new_date):
            self.edit_the_task_response_label.text = "ERROR! The date you entered is invalid! "

        else:
            if not is_date_after_today_add_new_task(new_date):
                self.edit_the_task_response_label.text = "ERROR! You can't enter a day that is below today! "

            else:
                msg_to_server = "date" + "#" + new_date + "#" + whole_task_str
                build_and_send_message(self.conn, cmd, msg_to_server)
                data = wise_recv(self.conn)
                if data is None:
                    sys.exit(1)
                curr_cmd, msg = chatlib.parse_message(data)
                if curr_cmd == chatlib.PROTOCOL_TASKS_SERVER['edit_task_ok_msg']:
                    self.edit_the_task_response_label.text = f"Success! {msg}"

                    day_before = screen_flow["specific task to see"][0]
                    month_before = screen_flow["specific task to see"][1]
                    year_before = screen_flow["specific task to see"][2]

                    print("Before: ", (day_before, month_before, year_before))

                    curr_day = new_date.split("/")[0]
                    curr_month = new_date.split("/")[1]
                    curr_year = new_date.split("/")[2]

                    print("After: ", (curr_day, curr_month, curr_year))

                    screen_flow["specific task to see"][0] = curr_day
                    screen_flow["specific task to see"][1] = curr_month
                    screen_flow["specific task to see"][2] = curr_year

                elif curr_cmd == chatlib.PROTOCOL_TASKS_SERVER['edit_task_failed_msg']:
                    self.edit_the_task_response_label.text = f"ERROR! {msg}"

    def is_date_valid(self, new_date):
        """
        Checking if the new date is valid.
        :param new_date: the new date.
        """
        if not val_date(new_date):
            self.edit_the_task_response_label.text = "ERROR! The date you entered is invalid! "
            return False

        if not is_date_after_today_add_new_task(new_date):
            self.edit_the_task_response_label.text = "ERROR! You can't enter a day that is below today! "
            return False

        return True

    def edit_info(self, cmd, whole_task_str, new_info):
        """
        Asks the server to change the info of the specific task
        :param cmd: the command that will be sent to the server.
        :param whole_task_str: the task that will be changed.
        :param new_info: the new info of the task, as requested from the client
        """
        msg_to_server = "info" + "#" + new_info + "#" + whole_task_str
        build_and_send_message(self.conn, cmd, msg_to_server)
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_TASKS_SERVER['edit_task_ok_msg']:
            self.edit_the_task_response_label.text = f"Success! {msg}"
            screen_flow["specific task to see"][3] = new_info
        elif curr_cmd == chatlib.PROTOCOL_TASKS_SERVER['edit_task_failed_msg']:
            self.edit_the_task_response_label.text = f"ERROR! {msg}"

    def create_whole_task_str(self, whole_task_list):
        """
        Creates the whole task string from the whole task list.
        :param whole_task_list: a list that describes a specific task
        """
        whole_task_str = ""
        for i in range(len(whole_task_list)):
            whole_task_str += whole_task_list[i]
            if i < len(whole_task_list) - 1:
                whole_task_str += "^"
        return whole_task_str

    def on_edit_the_task_button_press(self, instance):
        """
        Sends the server a request to edit the task with the user's inputs.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow

        date = self.date_input.text
        info = self.info_input.text
        did_finish = self.did_finish_input.text

        whole_task = screen_flow["specific task to see"]
        cmd = chatlib.PROTOCOL_TASKS_CLIENT['edit_task_msg']
        # priority : did_finish->date->info

        if date == '' and info == '' and did_finish == '':
            self.edit_the_task_response_label.text = "You have to enter a least one non-empty value! "

        else:
            if did_finish != '':
                if did_finish not in ["0", "0.5", "1"]:
                    self.edit_the_task_response_label.text = "Did finish must be in {0, 0.5, 1}. O is didn't start, 0.5 is in progress, 1 is finished. "

                else:  # change did finish
                    new_did_finish = did_finish
                    curr_whole_task_str = self.create_whole_task_str(screen_flow["specific task to see"])
                    self.edit_did_finish(cmd, curr_whole_task_str, new_did_finish)

                    if date != '':
                        new_date = date
                        if self.is_date_valid(new_date):
                            curr_whole_task_str = self.create_whole_task_str(screen_flow["specific task to see"])
                            self.edit_date(cmd, curr_whole_task_str, new_date)

                            if info != '':
                                new_info = info
                                if '#' in info or "^" in info:
                                    self.edit_the_task_response_label.text = "ERROR! You can't have # or ^ in the tasks' info! "
                                else:
                                    curr_whole_task_str = self.create_whole_task_str(
                                        screen_flow["specific task to see"])
                                    self.edit_info(cmd, curr_whole_task_str, new_info)

                    else:
                        if info != '':
                            new_info = info
                            if '#' in info or "^" in info:
                                self.edit_the_task_response_label.text = "ERROR! You can't have # or ^ in the tasks' info! "
                            else:
                                curr_whole_task_str = self.create_whole_task_str(screen_flow["specific task to see"])
                                self.edit_info(cmd, curr_whole_task_str, new_info)

            else:
                if date != '':
                    new_date = date
                    if self.is_date_valid(new_date):
                        curr_whole_task_str = self.create_whole_task_str(screen_flow["specific task to see"])
                        self.edit_date(cmd, curr_whole_task_str, new_date)

                        if info != '':
                            new_info = info
                            if '#' in info or "^" in info:
                                self.edit_the_task_response_label.text = "ERROR! You can't have # or ^ in the tasks' info! "
                            else:
                                curr_whole_task_str = self.create_whole_task_str(screen_flow["specific task to see"])
                                self.edit_info(cmd, curr_whole_task_str, new_info)

                else:  # info != ''
                    new_info = info
                    if '#' in info or "^" in info:
                        self.edit_the_task_response_label.text = "ERROR! You can't have # or ^ in the tasks' info! "
                    else:
                        curr_whole_task_str = self.create_whole_task_str(screen_flow["specific task to see"])
                        self.edit_info(cmd, curr_whole_task_str, new_info)

    def on_enter(self):
        """
        Shows the client the data about the specific task he chose.
        """
        global screen_flow
        tasks_first_dict = screen_flow["specific task to see"]
        tasks_dict_right_keys = {"day": tasks_first_dict[0], "month": tasks_first_dict[1], "year": tasks_first_dict[2], "info": tasks_first_dict[3], "did_finish": tasks_first_dict[4]}
        tasks_df = pd.DataFrame([tasks_dict_right_keys])
        tasks_df.set_index(pd.Index(range(1, len(tasks_df) + 1)), inplace=True)
        print(tasks_df)

        # Get the column names from the DataFrame
        column_names = [str(name) for name in tasks_df.columns]
        print(column_names)

        # Get the values for each row in the DataFrame
        values_list = []
        for i in range(tasks_df.shape[0]):
            row_values = [str(tasks_df.iloc[i][col]) for col in column_names]
            values_list.append(tuple(row_values))
        print(values_list)

        # Create the column data for the MDDataTable
        column_data = [(name, 30) for name in column_names]

        # Create the MDDataTable widget
        table = MDDataTable(
            size_hint=(1, 1),
            column_data=column_data,
            row_data=values_list,
            rows_num=len(values_list),
            use_pagination=False
        )
        self.box_layout.add_widget(table)


# shared diaries screens

class SharedDiariesScreen(Screen):
    def __init__(self, conn, name="shared_diaries_screen", **kwargs):
        super().__init__(name=name, **kwargs)

        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)
        self.conn = conn

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_main_screen_button_press(self, instance):
        """
        Switching to the main screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "main_screen"
        self.manager.current = "main_screen"  # Switch to the main_screen

    def on_outgoing_requests_button_press(self, instance):
        """
        Switching to the outgoing share diary requests screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "outgoing_share_diary_requests_screen"
        self.manager.current = "outgoing_share_diary_requests_screen"  # Switch to the outgoing_share_diary_request_screen

    def on_ingoing_requests_button_press(self, instance):
        """
        Switching to the ingoing share diary requests screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "ingoing_share_diary_requests_screen"
        self.manager.current = "ingoing_share_diary_requests_screen"  # Switch to the ingoing_share_diary_request_screen

    def on_see_shared_diaries_button_press(self, instance):
        """
        Switching to the see shared diaries screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_shared_diaries_screen"
        self.manager.current = "see_shared_diaries_screen"  # Switch to the see_shared_diaries_screen

    def on_enter(self):
        """
        This function is building the screen widgets and the client's current options.
        """
        # first design
        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # creating a message label
        self.msg_label = Label(text="", font_size=self.width * 0.05, size_hint=(1, 0.6), pos_hint={'top': 0.85},
                               color=(0, 0, 1, 1))
        self.add_widget(self.msg_label)

        # add the label below the image
        self.add_widget(Label(text="Shared Diaries Area", font_size=self.width / 25, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        cmd = chatlib.PROTOCOL_CLIENT['shared_diaries_msg']
        build_and_send_message(self.conn, cmd, "")
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_SERVER['shared_diaries_failed_msg']:
            self.msg_label.text = "Failed to show your options! "
        elif curr_cmd == chatlib.PROTOCOL_SERVER['shared_diaries_ok_msg']:
            if msg != no_friends:
                # add the buttons to the BoxLayout
                # create a horizontal BoxLayout for the buttons
                layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                   pos_hint={'center_x': 0.5, 'top': 0.6}, padding=(20, 0, 20, 0))
                layout.add_widget(MDRaisedButton(text="Outgoing requests", size_hint=(0.2, 0.8), font_size=self.width / 40, on_press=self.on_outgoing_requests_button_press))
                layout.add_widget(MDRaisedButton(text="Ingoing requests", size_hint=(0.2, 0.8), font_size=self.width / 40, on_press=self.on_ingoing_requests_button_press))
                layout.add_widget(MDRaisedButton(text="See shared diaries", size_hint=(0.2, 0.8), font_size=self.width / 40, on_press=self.on_see_shared_diaries_button_press))
                self.add_widget(layout)

                # add another layout
                second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2), pos_hint={'center_x': 0.5, 'top': 0.4}, padding=(20, 0, 20, 0))
                second_layout.add_widget(MDRaisedButton(text="Main screen", size_hint=(0.2, 0.8), font_size=self.width / 40, on_press=self.on_main_screen_button_press))
                second_layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width / 40, on_press=self.exit_app))
                self.add_widget(second_layout)

            else:
                # add the buttons to the BoxLayout
                # create a horizontal BoxLayout for the buttons
                self.msg_label.text = msg
                layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                          pos_hint={'center_x': 0.5, 'top': 0.4}, padding=(20, 0, 20, 0))
                layout.add_widget(MDRaisedButton(text="Main screen", size_hint=(0.2, 0.8), font_size=self.width / 40,
                                                on_press=self.on_main_screen_button_press))
                layout.add_widget(
                    MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width / 40, on_press=self.exit_app))
                self.add_widget(layout)

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()


class OutgoingShareDiaryRequestsScreen(Screen):
    def __init__(self, conn, name="outgoing_share_diary_requests_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Shared diaries area - Outgoing Requests", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.99}, color=(0, 0, 0, 1)))

        # no friends label
        self.no_friends_label = Label(text="", font_size=self.width * 0.5, size_hint=(1, 0.6), pos_hint={'top': 0.75},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.no_friends_label)

        # refresh button
        self.refresh_button = MDIconButton(icon=refresh_picture_path, size_hint=(0.05, 0.07),
                                           pos_hint={'center_x': 0.84, 'top': 0.92},
                                           on_press=self.refresh_screen, icon_size="50sp")
        self.add_widget(self.refresh_button)

        # here will be the friends dataframe

        self.friends_tables_case1_layout = BoxLayout(size_hint=(0.5, 0.5), pos_hint={"center_x": 0.5, "center_y": 0.6})
        self.add_widget(self.friends_tables_case1_layout)

        self.friends_tables_case2_layout = BoxLayout(size_hint=(0.3, 0.5), pos_hint={"center_x": 0.77, "center_y": 0.58})
        self.add_widget(self.friends_tables_case2_layout)

        self.outgoing_requests_layout = BoxLayout(size_hint=(0.3, 0.5), pos_hint={"center_x": 0.4, "center_y": 0.58})
        self.add_widget(self.outgoing_requests_layout)

        friend_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.1))  # create the username layout widget
        friend_layout.pos_hint = {'top': 0.35, 'center_x': 0.45}   # position the username_layout just below the welcome_label

        # friends input box
        self.friends_label = Label(text="Friends' indexes: ", font_size=30, size_hint=(0.4, 0.1),
                                pos_hint={'center_x': 0.25, 'top': 0.33}, color=(0, 0, 1, 1))
        self.friends_input = TextInput(size_hint=(0.5, 0.05), pos_hint={'center_x': 0.6, 'top': 0.31})
        self.add_widget(self.friends_label)
        self.add_widget(self.friends_input)

        self.message_label = Label(
            text="",
            font_size=self.width * 0.2, size_hint=(1, 0.6), pos_hint={'top': 0.53},
            color=(0, 0, 1, 1))
        self.add_widget(self.message_label)  # the response to the client's indexes message.

        self.friends_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(0.7, 0.2),
                                   pos_hint={'center_x': 0.5, 'top': 0.29}, padding=(20, 0, 20, 0))
        choose_friends_button = MDRaisedButton(text="Choose friends", size_hint=(0.2, 0.6), font_size=self.width / 4)
        choose_friends_button.bind(on_press=self.on_choose_friends_button_press)
        self.friends_layout.add_widget(choose_friends_button)
        self.add_widget(self.friends_layout)

        buttons_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.2}, padding=(20, 0, 20, 0))

        tasks_back_button = MDRaisedButton(text="Shared diaries", size_hint=(0.1, 0.35), font_size=self.width / 4)
        tasks_back_button.bind(on_press=self.shared_diaries_back_button_press)
        tasks_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        buttons_layout.add_widget(tasks_back_button)
        buttons_layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.1, 0.35), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(buttons_layout)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.message_label.text = ''
        self.friends_input.text = ''
        # self.friends_label.text = ''
        self.friends_tables_case1_layout.clear_widgets()
        self.friends_tables_case2_layout.clear_widgets()
        self.outgoing_requests_layout.clear_widgets()

    def shared_diaries_back_button_press(self, instance):
        """
        Switching to the shared diaries screen.
        :param instance: the button instance that triggered the event.
        """
        self.message_label.text = ''
        self.friends_input.text = ''
        # self.friends_label.text = ''
        self.friends_tables_case1_layout.clear_widgets()
        self.friends_tables_case2_layout.clear_widgets()
        self.outgoing_requests_layout.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "shared_diaries_screen"
        self.manager.current = "shared_diaries_screen"  # Switch to the tasks_screen

    def move_to_send_share_diary_request_screen(self):
        """
        Switching to send share diary request screen.
        """
        self.message_label.text = ''
        self.friends_input.text = ''
        # self.friends_label.text = ''
        self.friends_tables_case1_layout.clear_widgets()
        self.friends_tables_case2_layout.clear_widgets()
        self.outgoing_requests_layout.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "send_share_diary_request_screen"
        self.manager.current = "send_share_diary_request_screen"  # Switch to the send_share_diary_request_screen

    def exit_app(self, instance):
        """
         Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def on_choose_friends_button_press(self, instance):
        """
        Moves to send share diary screen, based on the client's input - the indexe's of friends he want to share diary with.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow

        friend_indexes = self.friends_input.text
        min_index = 1
        max_index = len(self.friends_table.row_data)
        check, numbers_list = return_indexes(friend_indexes, min_index, max_index)

        if not check:
            self.message_label.text = "ERROR! The indexes are not valid! "

        else:
            real_indexes_list = [int(index) - 1 for index in numbers_list]
            all_clients = []
            for index in real_indexes_list:
                chosen_friend = self.friends_table.row_data[index][1]
                all_clients.append(chosen_friend)
                print("You chose friend:", chosen_friend)
            # check with the server if they are current friends or not.
            screen_flow["Friends to see share diary request to: "] = all_clients
            self.move_to_send_share_diary_request_screen()

    def refresh_screen(self, instance):
        """
        Refreshes the screen
        :param instance: the button instance that triggered the event.
        """
        self.message_label.text = ''
        self.friends_input.text = ''
        # self.friends_label.text = ''
        self.friends_tables_case1_layout.clear_widgets()
        self.friends_tables_case2_layout.clear_widgets()
        self.outgoing_requests_layout.clear_widgets()

        self.on_enter()  # Call the on_enter method to add the widgets to the layout

    def on_enter(self):
        """
        The client shows the client's current outgoing share diary request, if there are any, and the client's list of friends.
        """
        global screen_flow
        if screen_flow["prev"] == "shared_diaries_screen" or screen_flow["prev"] == "send_share_diary_request_screen": # maybe add more
            print("Asking the server to see my outgoing share diary requests... \n")
            cmd = chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['outgoing_share_diary_requests_msg']
            build_and_send_message(self.conn, cmd, "")
            data = wise_recv(self.conn)
            if data is None:
                return
            curr_cmd, msg = chatlib.parse_message(data)
            if curr_cmd == chatlib.PROTOCOL_SHARED_DIARIES_SERVER['outgoing_share_diary_requests_ok_msg']:
                if msg.split("#")[0] == no_outgoing_requests_to_share_diaries:
                    # send new request
                    friends_msg = msg.split("#")[1]
                    # show the friends dataframe
                    friends_df = pd.read_json(friends_msg)
                    friends_df.set_index(pd.Index(range(1, len(friends_df) + 1)), inplace=True)

                    # column_name = [str(name) for name in friends_df.columns][0]
                    column_data = [("Index", 30), ("Friends names", 30)]
                    values_list = [str(friends_df.iloc[i][0]) for i in range(friends_df.shape[0])]

                    final_values_list = []
                    index = 1
                    for i in range(len(values_list)):
                        final_values_list.append((str(index), values_list[i]))
                        index += 1

                    # create the MDDataTable widget
                    self.friends_table = MDDataTable(
                        size_hint=(1, 1),
                        column_data=column_data,
                        row_data=final_values_list,
                        rows_num=len(values_list),
                        use_pagination=False
                    )

                    self.friends_tables_case1_layout.add_widget(self.friends_table)

                else:
                    print(msg)
                    # send new request and see existing requests
                    # friends msg
                    friends_msg = msg.split("#")[1]
                    # show the friends dataframe
                    friends_df = pd.read_json(friends_msg)
                    friends_df.set_index(pd.Index(range(1, len(friends_df) + 1)), inplace=True)

                    # column_name = [str(name) for name in friends_df.columns][0]
                    column_data = [("Index", 30), ("Friends names", 30)]
                    values_list = [str(friends_df.iloc[i][0]) for i in range(friends_df.shape[0])]

                    final_values_list = []
                    index = 1
                    for i in range(len(values_list)):
                        final_values_list.append((str(index), values_list[i]))
                        index += 1

                    # create the MDDataTable widget
                    self.friends_table = MDDataTable(
                        size_hint=(1, 1),
                        column_data=column_data,
                        row_data=final_values_list,
                        rows_num=len(values_list),
                        use_pagination=False
                    )
                    self.friends_tables_case2_layout.add_widget(self.friends_table)

                    # show the existing outgoing requests dataframe
                    outgoing_requests_msg = msg.split("#")[2]
                    outgoing_requests_df = pd.read_json(outgoing_requests_msg)
                    outgoing_requests_df.set_index(pd.Index(range(1, len(outgoing_requests_df) + 1)), inplace=True)
                    print(outgoing_requests_df)

                    # Get the column names from the DataFrame
                    column_names = [str(name) for name in outgoing_requests_df.columns]

                    # Get the values for each row in the DataFrame
                    values_list = []
                    for i in range(outgoing_requests_df.shape[0]):
                        row_values = [str(outgoing_requests_df.iloc[i][col]) for col in column_names]
                        values_list.append(tuple(row_values))

                    print("Number of values:", len(values_list))

                    # Create the column data for the MDDataTable
                    column_data = [(name, 30) for name in column_names]

                    # Create the MDDataTable widget
                    outgoing_requests_table = MDDataTable(
                        size_hint=(1, 1),
                        column_data=column_data,
                        row_data=values_list,
                        rows_num=len(values_list),
                        use_pagination=False
                    )

                    # this table is not clickable
                    self.outgoing_requests_layout.add_widget(outgoing_requests_table)

            else:
                # clearing
                self.friends_layout.clear_widgets()
                self.message_label.text = ''
                self.friends_input.text = ''

                self.remove_widget(self.friends_input)
                self.friends_label.text = ''

                self.friends_tables_case1_layout.clear_widgets()
                self.friends_tables_case2_layout.clear_widgets()
                self.outgoing_requests_layout.clear_widgets()

                self.no_friends_label.text = msg


def is_date_after_today(date_string):
    """
    Checking if the date in the input is strictly after today or not.
    :param date_string: a date input.
    """
    today = datetime.date.today()
    date_format = "%d/%m/%Y"

    try:
        parsed_date = datetime.datetime.strptime(date_string, date_format).date()
        return parsed_date > today
    except ValueError:
        return False


def is_date_after_today_add_new_task(date_string):
    """
    Checking if the date in the input is after today or not.
    :param date_string: a date input.
    """
    today = datetime.date.today()
    date_format = "%d/%m/%Y"

    try:
        parsed_date = datetime.datetime.strptime(date_string, date_format).date()
        return parsed_date >= today
    except ValueError:
        return False


class SendShareDiaryRequestScreen(Screen):
    def __init__(self, conn, name="send_share_diary_request_screen", **kwargs):
        global screen_flow
        super().__init__(name=name, **kwargs)
        self.conn = conn

        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Share diary area - Send share diary request", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.9}, color=(0, 0, 0, 1)))

        # theme, info and time input boxes
        theme_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.1))  # create the username layout widget
        theme_layout.pos_hint = {'top': 0.7, 'center_x': 0.45}   # position the username_layout just below the welcome_label

        # create the theme label widget
        self.theme_label = Label(text="Theme: ", font_size=self.width * 0.3, size=(self.width*0.9, self.height*0.05), size_hint=(0.2, 1), color=(0, 0, 1, 1))
        theme_layout.add_widget(self.theme_label)
        self.theme_label.pos_hint = {'top': 0.7, 'right': 0.15}

        # create the theme input widget
        self.theme_input = TextInput(multiline=False, size_hint=(0.6, 0.5), size=(self.width * 0.6, self.height * 0.05),
                                   font_size=self.width * 0.15)
        theme_layout.add_widget(self.theme_input)
        self.add_widget(theme_layout)  # add the theme_layout to the root widget

        # info input box
        info_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.1))  # create the username layout widget
        info_layout.pos_hint = {'top': 0.6, 'center_x': 0.45}   # position the username_layout just below the welcome_label

        # create the info label widget
        self.info_label = Label(text="Info: ", font_size=self.width * 0.3, size=(self.width*0.9, self.height*0.05), size_hint=(0.2, 1), color=(0, 0, 1, 1))
        info_layout.add_widget(self.info_label)
        self.info_label.pos_hint = {'top': 0.6, 'right': 0.15}

        # create the info input widget
        self.info_input = TextInput(multiline=False, size_hint=(0.6, 0.5), size=(self.width * 0.6, self.height * 0.05),
                                   font_size=self.width * 0.15)
        info_layout.add_widget(self.info_input)
        self.add_widget(info_layout)  # add the info_layout to the root widget

        # time input box
        date_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.1))  # create the username layout widget
        date_layout.pos_hint = {'top': 0.5, 'center_x': 0.45}   # position the username_layout just below the welcome_label

        # create the date label widget
        self.date_label = Label(text="Date: ", font_size=self.width * 0.3, size=(self.width*0.9, self.height*0.05), size_hint=(0.2, 1), color=(0, 0, 1, 1))
        date_layout.add_widget(self.date_label)
        self.date_label.pos_hint = {'top': 0.5, 'right': 0.15}

        # create the date input widget
        self.date_input = TextInput(multiline=False, size_hint=(0.6, 0.5), size=(self.width * 0.6, self.height * 0.05),
                                   font_size=self.width * 0.15)
        date_layout.add_widget(self.date_input)
        self.add_widget(date_layout)  # add the date_layout to the root widget

        # create the message label widget
        self.message_label = Label(text="", font_size=self.width * 0.35, size_hint=(1, 0.1), pos_hint={'top': 0.42},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        # create a horizontal BoxLayout for the buttons
        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.37}, padding=(20, 0, 20, 0))
        layout.add_widget(MDRaisedButton(text="Send share diary request", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_send_share_diary_request_button_press))
        self.add_widget(layout)

        # add another layout
        second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2), pos_hint={'center_x': 0.5, 'top': 0.2}, padding=(20, 0, 20, 0))
        second_layout.add_widget(MDRaisedButton(text="Share diary outgoing requests", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.on_share_diary_outgoing_requests_button_press))
        second_layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(second_layout)

    def on_enter(self):
        """
        Creates the usernames message label widget
        """
        if "Friends to see share diary request to: " in screen_flow.keys():
            usernames_msg = "The usernames: "
            for i in range(len(screen_flow["Friends to see share diary request to: "])):
                usernames_msg += screen_flow["Friends to see share diary request to: "][i]
                if i < len(screen_flow["Friends to see share diary request to: "]) - 1:
                    usernames_msg += ", "

            self.usernames_message_label = Label(text=usernames_msg, font_size=self.width * 0.03, size_hint=(1, 0.1), pos_hint={'top': 0.78},
                                       color=(0, 0, 1, 1))
            self.add_widget(self.usernames_message_label)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_share_diary_outgoing_requests_button_press(self, instance):
        """
        Switching to the share diary outgoing requests screen.
        :param instance: the button instance that triggered the event.
        """
        self.date_input.text = ''
        self.info_input.text = ''
        self.theme_input.text = ''
        self.message_label.text = ''
        self.usernames_message_label.text = ''

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "outgoing_share_diary_requests_screen"
        self.manager.current = "outgoing_share_diary_requests_screen"  # Switch to the register_screen

    def exit_app(self, instance):
        """
         Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def on_send_share_diary_request_button_press(self, instance):
        """
        Asking the server to send a specific share diary request.
        The request will consist theree things:
        list_of_usernames (will be a sublist of usernames_list).
        a theme (of the group that will share their tasks diaries).
        a date range (for sharing the diaries).
        """
        global screen_flow

        max_date = self.date_input.text
        group_info = self.info_input.text
        group_theme = self.theme_input.text
        usernames_list = screen_flow["Friends to see share diary request to: "]
        print((max_date, group_info, group_theme, usernames_list))

        usernames_str = ""
        for i in range(len(usernames_list)):
            usernames_str += usernames_list[i]
            if i < len(usernames_list) - 1:
                usernames_str += "$"  # The usernames will be separated by $

        print(val_date(max_date))

        if not val_date(max_date):
            self.message_label.text = "ERROR! The date you entered is invalid! It needs to be day/month/year"

        else:
            if not is_date_after_today(max_date):
                self.message_label.text = "ERROR! The date you entered is invalid! This is not after today! "
            else:
                if '#' in group_theme:
                    self.message_label.text = "ERROR! # cant be in your desired theme of the group! "
                else:
                    if '#' in group_info:
                        self.message_label.text = "ERROR! # cant be in your desired info of the group! "
                    else:
                        if group_info == '' or group_theme == '' or max_date == '':
                            self.message_label.text = "ERROR! You cant enter empty values here! "
                        else:
                            date_msg = max_date.split("/")[0] + "$" + max_date.split("/")[1] + "$" + max_date.split("/")[2]
                            final_msg = usernames_str + "#" + group_theme + "#" + group_info + "#" + date_msg
                            cmd = chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['new_share_diary_request_msg']
                            build_and_send_message(self.conn, cmd, final_msg)

                            data = wise_recv(self.conn)
                            if data is None:
                                sys.exit(1)

                            curr_cmd, msg = chatlib.parse_message(data)
                            if curr_cmd == chatlib.PROTOCOL_SHARED_DIARIES_SERVER['new_share_diary_request_ok_msg']:
                                self.message_label.text = f"Success! {msg}"
                            elif curr_cmd == chatlib.PROTOCOL_SHARED_DIARIES_SERVER['new_share_diary_request_failed_msg']:
                                self.message_label.text = f"Failed! {msg}"


class IngoingShareDiaryRequestsScreen(Screen):
    def __init__(self, conn, name="ingoing_share_diary_requests_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()

    def share_diary_back_button_press(self, instance):
        """
        Switching to the share diary screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "shared_diaries_screen"
        self.manager.current = "shared_diaries_screen"  # Switch to the shared_diaries_screen

    def move_to_see_specific_ingoing_share_diary_request_screen(self):
        """
        Switching to the see specific ingoing share diary request screen.
        """
        self.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_specific_ingoing_share_diary_request_screen"
        self.manager.current = "see_specific_ingoing_share_diary_request_screen"  # Switch to the see_specific_ingoing_share_diary_request_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def on_choose_specific_ingoing_share_diary_request_button_press(self, instance_table):
        """
        Handling the client's decision to press the button that triggers the choosing specific request text.
        :param instance_table: all the ingoing share diary request table.
        """
        global screen_flow
        index = self.request_input.text
        if not index.isdigit():
            self.request_message_label.text = "Not valid input! You need to enter a valid index! "
            print("Invalid index")
        else:
            real_index = int(index) - 1
            if 0 <= real_index < len(self.ingoing_share_diary_request_table.row_data):
                # Index is in the valid range
                row_data = self.ingoing_share_diary_request_table.row_data[real_index]
                print("The request that the client chose: ",  row_data)
                screen_flow["specific ingoing share diary request to see"] = row_data[1:]
                self.move_to_see_specific_ingoing_share_diary_request_screen()

            else:
                self.request_message_label.text = "Not valid input! You need to enter a valid index! "
                print("Invalid index")

    def refresh_screen(self, instance):
        """
        Refreshes the screen
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()
        self.on_enter()  # Call the on_enter method to add the widgets to the layout

    def on_enter(self):
        global screen_flow

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Share diary area - Ingoing requests", font_size=self.width * 0.05, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.99}, color=(0, 0, 0, 1)))

        # refresh button
        self.refresh_button = MDIconButton(icon=refresh_picture_path, size_hint=(0.05, 0.07),
                                           pos_hint={'center_x': 0.84, 'top': 0.92},
                                           on_press=self.refresh_screen, icon_size="50sp")
        self.add_widget(self.refresh_button)

        # creating a message label
        self.message_label = Label(text="", font_size=self.width * 0.03, size_hint=(1, 0.6), pos_hint={'top': 0.75},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.message_label)

        if screen_flow["prev"] == "shared_diaries_screen" or screen_flow["prev"] == "see_specific_ingoing_share_diary_request_screen":
            print("Asking the server to see my ingoing share diary request... \n")
            cmd = chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['ingoing_share_diary_requests_msg']
            build_and_send_message(self.conn, cmd, "")
            data = wise_recv(self.conn)
            if data is None:
                return
            curr_cmd, msg = chatlib.parse_message(data)
            if curr_cmd == chatlib.PROTOCOL_SHARED_DIARIES_SERVER['ingoing_share_diary_requests_ok_msg']:
                ingoing_share_diary_requests_msg = msg.split("#")[0]

                if ingoing_share_diary_requests_msg != no_ingoing_requests_to_share_diaries:
                    # first - design

                    # request input box
                    self.request_label = Label(text="Request index: ", font_size=30, size_hint=(0.4, 0.1),
                                               pos_hint={'center_x': 0.27, 'top': 0.27}, color=(0, 0, 1, 1))
                    self.request_input = TextInput(size_hint=(0.5, 0.05), pos_hint={'center_x': 0.6, 'top': 0.25})
                    self.add_widget(self.request_label)
                    self.add_widget(self.request_input)

                    # creating a message label
                    self.request_message_label = Label(text="", font_size=self.width * 0.03, size_hint=(1, 0.6),
                                                       pos_hint={'top': 0.55},
                                                       color=(0, 0, 1, 1))
                    self.add_widget(self.request_message_label)

                    # buttons
                    layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                       pos_hint={'center_x': 0.5, 'top': 0.2}, padding=(20, 0, 20, 0))

                    layout.add_widget(MDRaisedButton(text="Choose share diary request", size_hint=(0.2, 0.6),
                                                     font_size=self.width / 40,
                                                     on_press=self.on_choose_specific_ingoing_share_diary_request_button_press))
                    tasks_back_button = MDRaisedButton(text="Share diary", size_hint=(0.2, 0.6),
                                                       font_size=self.width / 40)
                    tasks_back_button.bind(on_press=self.share_diary_back_button_press)
                    tasks_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
                    layout.add_widget(tasks_back_button)
                    layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 40,
                                                     on_press=self.exit_app))
                    self.add_widget(layout)

                    # show the tasks dataframe
                    ingoing_share_diary_requests_df = pd.read_json(ingoing_share_diary_requests_msg)
                    ingoing_share_diary_requests_df.set_index(pd.Index(range(1, len(ingoing_share_diary_requests_df) + 1)), inplace=True)
                    print(ingoing_share_diary_requests_df)

                    # Get the column names from the DataFrame
                    column_names = [str(name) for name in ingoing_share_diary_requests_df.columns]
                    column_data = [("Index", 30)]   # Create the column data for the MDDataTable
                    for name in column_names:
                        column_data.append((name, 30))

                    # Get the values for each row in the DataFrame
                    values_list = []
                    for i in range(ingoing_share_diary_requests_df.shape[0]):
                        row_values = [str(ingoing_share_diary_requests_df.iloc[i][col]) for col in column_names]
                        values_list.append(tuple(row_values))

                    print("Number of values:", len(values_list))

                    # here will be the ingoing share diary requests dataframe

                    self.box_layout = BoxLayout(size_hint=(0.5, 0.7), pos_hint={"center_x": 0.5, "center_y": 0.65})
                    self.add_widget(self.box_layout)

                    # Create the MDDataTable widget
                    self.ingoing_share_diary_request_table = MDDataTable(
                        size_hint=(1, 0.7),
                        column_data=column_data,
                        row_data=[(str(index), *row) for index, row in enumerate(values_list, start=1)],
                        rows_num=len(values_list),
                        use_pagination=False
                    )
                    self.box_layout.add_widget(self.ingoing_share_diary_request_table)

                else:
                    self.message_label.text = ingoing_share_diary_requests_msg

                    layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                       pos_hint={'center_x': 0.5, 'top': 0.2}, padding=(20, 0, 20, 0))

                    tasks_back_button = MDRaisedButton(text="Share diary", size_hint=(0.2, 0.6),
                                                       font_size=self.width / 40)
                    tasks_back_button.bind(on_press=self.share_diary_back_button_press)
                    tasks_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
                    layout.add_widget(tasks_back_button)
                    layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 40,
                                                     on_press=self.exit_app))
                    self.add_widget(layout)

            else:
                self.message_label.text = msg


class SeeSpecificIngoingShareDiaryRequestScreen(Screen):
    def __init__(self, conn, name="see_specific_ingoing_share_diary_request_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # add the label below the image
        self.add_widget(Label(text="Share diary area - See specific ingoing share diary request", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.99}, color=(0, 0, 0, 1)))

        # creating a message label
        self.specific_request_label = Label(text="", font_size=self.width * 0.3, size_hint=(1, 0.6), pos_hint={'top': 0.65, 'center_x': 0.5},
                                   color=(0, 0, 1, 1))
        self.add_widget(self.specific_request_label)

        # here will be the hobbies dataframe

        self.box_layout = BoxLayout(size_hint=(0.5, 0.4), pos_hint={"center_x": 0.5, "center_y": 0.63})
        self.add_widget(self.box_layout)

        first_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                 pos_hint={'center_x': 0.5, 'top': 0.4}, padding=(20, 0, 20, 0))

        first_layout.add_widget(MDRaisedButton(text="Approve request", size_hint=(0.2, 0.6), font_size=self.width / 4,
                                       on_press=self.on_approve_ingoing_share_diary_request_button_press))
        first_layout.add_widget(MDRaisedButton(text="Reject request", size_hint=(0.2, 0.6), font_size=self.width / 4,
                                       on_press=self.on_reject_ingoing_share_diary_request_button_press))
        self.add_widget(first_layout)

        second_layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                  pos_hint={'center_x': 0.5, 'top': 0.25}, padding=(20, 0, 20, 0))

        tasks_back_button = MDRaisedButton(text="Ingoing requests", size_hint=(0.2, 0.6), font_size=self.width / 4)
        tasks_back_button.bind(on_press=self.ingoing_requests_back_button_press)
        tasks_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        second_layout.add_widget(tasks_back_button)
        second_layout.add_widget(
            MDRaisedButton(text="Exit", size_hint=(0.2, 0.6), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(second_layout)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.specific_request_label.text = ''
        self.box_layout.clear_widgets()

    def ingoing_requests_back_button_press(self, instance):
        """
        Switching to the ingoing share diary requests screen.
        :param instance: the button instance that triggered the event.
        """
        self.specific_request_label.text = ''
        self.box_layout.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "ingoing_share_diary_requests_screen"
        self.manager.current = "ingoing_share_diary_requests_screen"  # Switch to the edit_task_screen

    def on_approve_ingoing_share_diary_request_button_press(self, instance):
        """
        Asks the server to approve a specific ingoing request for diary share.
        """
        global screen_flow
        cmd = chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['approve_share_diary_request_msg']
        msg_to_server = screen_flow["specific ingoing share diary request to see"][0] + "#" + screen_flow["specific ingoing share diary request to see"][1] + "#" + screen_flow["specific ingoing share diary request to see"][2] + "#" + screen_flow["specific ingoing share diary request to see"][3] + "#" + screen_flow["specific ingoing share diary request to see"][4] + "#" + screen_flow["specific ingoing share diary request to see"][5]
        build_and_send_message(self.conn, cmd, msg_to_server)

        data = wise_recv(self.conn)
        if data is None:
            return
        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_SHARED_DIARIES_SERVER['approve_share_diary_request_ok_msg']:
            self.specific_request_label.text = f"Success! {msg}"
        elif curr_cmd == chatlib.PROTOCOL_SHARED_DIARIES_SERVER['approve_share_diary_request_failed_msg']:
            self.specific_request_label.text = f"Failed! {msg}"

    def on_reject_ingoing_share_diary_request_button_press(self, instance):
        """
        Asks the server to reject a specific ingoing request for diary share.
        """
        global screen_flow
        cmd = chatlib.PROTOCOL_SHARED_DIARIES_CLIENT["reject_share_diary_request_msg"]
        msg_to_server = screen_flow["specific ingoing share diary request to see"][0] + "#" + screen_flow["specific ingoing share diary request to see"][1] + "#" + screen_flow["specific ingoing share diary request to see"][2] + "#" + screen_flow["specific ingoing share diary request to see"][3] + "#" + screen_flow["specific ingoing share diary request to see"][4] + "#" + screen_flow["specific ingoing share diary request to see"][5]
        build_and_send_message(self.conn, cmd, msg_to_server)

        data = wise_recv(self.conn)
        if data is None:
            return
        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_SHARED_DIARIES_SERVER['reject_share_diary_request_ok_msg']:
            self.specific_request_label.text = f"Success! {msg}"
        elif curr_cmd == chatlib.PROTOCOL_SHARED_DIARIES_SERVER['reject_share_diary_request_failed_msg']:
            self.specific_request_label.text = f"Failed! {msg}"

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def on_enter(self):
        """
        Shows the client the specific ingoing share diary request (on the screen).
        """
        global screen_flow
        share_diary_ingoing_request_first_dict = screen_flow["specific ingoing share diary request to see"]
        share_diary_ingoing_request_dict_right_keys = {"addresser": share_diary_ingoing_request_first_dict[0], "recipients": share_diary_ingoing_request_first_dict[1], "dates_range": share_diary_ingoing_request_first_dict[2], "approvals": share_diary_ingoing_request_first_dict[3], "theme": share_diary_ingoing_request_first_dict[4], "info": share_diary_ingoing_request_first_dict[5]}
        share_diary_ingoing_request_df = pd.DataFrame([share_diary_ingoing_request_dict_right_keys])
        share_diary_ingoing_request_df.set_index(pd.Index(range(1, len(share_diary_ingoing_request_df) + 1)), inplace=True)
        print(share_diary_ingoing_request_df)

        # Get the column names from the DataFrame
        column_names = [str(name) for name in share_diary_ingoing_request_df.columns]
        print(column_names)

        # Get the values for each row in the DataFrame
        values_list = []
        for i in range(share_diary_ingoing_request_df.shape[0]):
            row_values = [str(share_diary_ingoing_request_df.iloc[i][col]) for col in column_names]
            values_list.append(tuple(row_values))
        print(values_list)

        # Create the column data for the MDDataTable
        column_data = [(name, 30) for name in column_names]

        # Create the MDDataTable widget
        share_diary_ingoing_request_table = MDDataTable(
            size_hint=(1, 1),
            column_data=column_data,
            row_data=values_list,
            rows_num=len(values_list),
            use_pagination=False
        )
        self.box_layout.add_widget(share_diary_ingoing_request_table)


class SeeSharedDiariesScreen(Screen):
    def __init__(self, conn, name="see_shared_diaries_screen", **kwargs):
        super().__init__(name=name, **kwargs)

        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)
        self.conn = conn

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def on_main_screen_button_press(self, instance):
        """
        Switching to the main screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "main_screen"
        self.manager.current = "main_screen"  # Switch to the main_screen

    def on_shared_diaries_button_press(self, instance):
        """
        Switching to the shared diaries screen.
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "shared_diaries_screen"
        self.manager.current = "shared_diaries_screen"  # Switch to the see_shared_diaries_screen

    def move_to_see_specific_share_diary_group_screen(self):
        """
        Switching to the see specific share diary group screen.
        """
        self.clear_widgets()
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_specific_share_diary_group_screen"
        self.manager.current = "see_specific_share_diary_group_screen"  # Switch to the see_shared_diaries_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def on_choose_share_diary_group_button_press(self, instance):
        """
        Handles the client's decision to press the button that triggers the choosing specific share diary group text.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        index = self.share_diary_groups_input.text
        if not index.isdigit():
            self.share_diary_groups_message_label.text = "Not valid input! You need to enter a valid index! "
            print("Invalid index")
        else:
            real_index = int(index) - 1
            if 0 <= real_index < len(self.share_diary_groups_table.row_data):
                # Index is in the valid range
                row_data = self.share_diary_groups_table.row_data[real_index]
                print("The request that the client chose: ",  row_data)
                screen_flow["specific share diary group to see"] = row_data[1:]
                self.move_to_see_specific_share_diary_group_screen()

            else:
                self.share_diary_groups_message_label.text = "Not valid input! You need to enter a valid index! "
                print("Invalid index")

    def refresh_screen(self, instance):
        """
        Refreshes the screen
        :param instance: the button instance that triggered the event.
        """
        self.clear_widgets()
        self.on_enter()  # Call the on_enter method to add the widgets to the layout

    def on_enter(self):
        """
        Builds the screen, sends the server a request to see the shared diaries and shows the client its options.
        """
        global screen_flow
        # first design
        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.9}))

        # creating a message label
        self.msg_label = Label(text="", font_size=self.width * 0.035, size_hint=(1, 0.6), pos_hint={'top': 0.7},
                               color=(0, 0, 1, 1))
        self.add_widget(self.msg_label)

        # add the label below the image
        self.add_widget(Label(text="See shared Diaries Area", font_size=self.width / 30, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.95}, color=(0, 0, 0, 1)))

        # refresh button
        self.refresh_button = MDIconButton(icon=refresh_picture_path, size_hint=(0.05, 0.07),
                                           pos_hint={'center_x': 0.84, 'top': 0.92},
                                           on_press=self.refresh_screen, icon_size="50sp")
        self.add_widget(self.refresh_button)

        cmd = chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['see_shared_diaries_groups_msg']
        build_and_send_message(self.conn, cmd, "")
        data = wise_recv(self.conn)
        if data is None:
            sys.exit(1)
        curr_cmd, msg = chatlib.parse_message(data)
        if curr_cmd == chatlib.PROTOCOL_SHARED_DIARIES_SERVER['see_shared_diaries_groups_failed_msg']:
            self.msg_label.text = "Failed to show your options! "
        elif curr_cmd == chatlib.PROTOCOL_SHARED_DIARIES_SERVER['see_shared_diaries_groups_ok_msg']:
            if msg != no_shared_diaries_groups_to_share_diaries:
                # show the share diary groups data frame:
                share_diary_groups_df = pd.read_json(msg)
                share_diary_groups_df.set_index(pd.Index(range(1, len(share_diary_groups_df) + 1)),
                                                          inplace=True)
                print(share_diary_groups_df)

                # Get the column names from the DataFrame
                column_names = [str(name) for name in share_diary_groups_df.columns]
                column_data = [("Index", 30)]  # Create the column data for the MDDataTable
                for name in column_names:
                    column_data.append((name, 30))

                # Get the values for each row in the DataFrame
                values_list = []
                for i in range(share_diary_groups_df.shape[0]):
                    row_values = [str(share_diary_groups_df.iloc[i][col]) for col in column_names]
                    values_list.append(tuple(row_values))

                print("Number of values:", len(values_list))

                self.box_layout = BoxLayout(size_hint=(0.5, 0.7), pos_hint={"center_x": 0.5, "center_y": 0.65})
                self.add_widget(self.box_layout)

                # Create the MDDataTable widget
                self.share_diary_groups_table = MDDataTable(
                    size_hint=(1, 0.7),
                    column_data=column_data,
                    row_data=[(str(index), *row) for index, row in enumerate(values_list, start=1)],
                    rows_num=len(values_list),
                    use_pagination=False
                )
                self.box_layout.add_widget(self.share_diary_groups_table)

                # index input box
                self.share_diary_groups_label = Label(text="Group index: ", font_size=30, size_hint=(0.4, 0.1),
                                           pos_hint={'center_x': 0.27, 'top': 0.27}, color=(0, 0, 1, 1))
                self.share_diary_groups_input = TextInput(size_hint=(0.5, 0.05), pos_hint={'center_x': 0.6, 'top': 0.25})
                self.add_widget(self.share_diary_groups_label)
                self.add_widget(self.share_diary_groups_input)

                self.share_diary_groups_message_label = Label(
                    text="",
                    font_size=self.width * 0.025, size_hint=(1, 0.6), pos_hint={'top': 0.56},
                    color=(0, 0, 1, 1))
                self.add_widget(self.share_diary_groups_message_label)  # the response to the client's indexes message.

                # add the buttons to the BoxLayout
                # create a horizontal BoxLayout for the buttons
                layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                   pos_hint={'center_x': 0.5, 'top': 0.23}, padding=(20, 0, 20, 0))
                layout.add_widget(MDRaisedButton(text="Choose share diary group", size_hint=(0.2, 0.8), font_size=self.width / 40, on_press=self.on_choose_share_diary_group_button_press))
                layout.add_widget(MDRaisedButton(text="Shared diaries", size_hint=(0.2, 0.8), font_size=self.width / 40, on_press=self.on_shared_diaries_button_press))
                layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width / 40, on_press=self.exit_app))
                self.add_widget(layout)

            else:
                # add the buttons to the BoxLayout
                # create a horizontal BoxLayout for the buttons

                self.msg_label.text = msg
                layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                                          pos_hint={'center_x': 0.5, 'top': 0.3}, padding=(20, 0, 20, 0))
                layout.add_widget(MDRaisedButton(text="Shared Diaries", size_hint=(0.2, 0.8), font_size=self.width / 40,
                                                on_press=self.on_shared_diaries_button_press))
                layout.add_widget(
                    MDRaisedButton(text="Exit", size_hint=(0.2, 0.8), font_size=self.width / 40, on_press=self.exit_app))
                self.add_widget(layout)


class SeeSpecificShareDiaryGroupScreen(Screen):
    def __init__(self, conn, name="see_specific_share_diary_group_screen", **kwargs):
        super().__init__(name=name, **kwargs)
        self.conn = conn
        # set the background color to white.
        with self.canvas:
            Color(1, 1, 1, 1)  # set color to white
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect, pos=self.update_rect)

        # add the image at the top
        self.add_widget(Image(source=logo_path, size_hint=(0.25, 0.25), pos_hint={'center_x': 0.15, 'top': 0.95}))

        # add the label below the image
        self.add_widget(Label(text="See shared diaries area - specific group", font_size=self.width * 0.5, size_hint=(1, 0.2),
                              pos_hint={'center_x': 0.5, 'top': 0.99}, color=(0, 0, 0, 1)))

        # refresh button
        self.refresh_button = MDIconButton(icon=refresh_picture_path, size_hint=(0.05, 0.07),
                                           pos_hint={'center_x': 0.84, 'top': 0.92},
                                           on_press=self.refresh_screen, icon_size="50sp")
        self.add_widget(self.refresh_button)

        # here will be the hobbies dataframe

        self.group_data_layout = BoxLayout(size_hint=(0.5, 0.5), pos_hint={"center_x": 0.3, "center_y": 0.5})
        self.add_widget(self.group_data_layout)

        self.group_shared_diary_layout = BoxLayout(size_hint=(0.3, 0.5), pos_hint={"center_x": 0.75, "center_y": 0.5})
        self.add_widget(self.group_shared_diary_layout)

        self.box_layout = BoxLayout(size_hint=(0.5, 0.7), pos_hint={"center_x": 0.5, "center_y": 0.75})
        self.add_widget(self.box_layout)

        self.message_label = Label(
            text="",
            font_size=self.width * 0.2, size_hint=(1, 0.6), pos_hint={'top': 0.53},
            color=(0, 0, 1, 1))
        self.add_widget(self.message_label)  # the response to the client's indexes message.

        layout = BoxLayout(orientation='horizontal', spacing=40, size_hint=(1, 0.2),
                           pos_hint={'center_x': 0.5, 'top': 0.25}, padding=(20, 0, 20, 0))

        see_shared_diaries_back_button = MDRaisedButton(text="See shared diaries", size_hint=(0.1, 0.35), font_size=self.width / 4)
        see_shared_diaries_back_button.bind(on_press=self.see_shared_diaries_back_button_press)
        see_shared_diaries_back_button.bind(on_press=self.clear_inputs_and_outputs)  # clear data
        layout.add_widget(see_shared_diaries_back_button)
        layout.add_widget(MDRaisedButton(text="Exit", size_hint=(0.1, 0.35), font_size=self.width / 4, on_press=self.exit_app))
        self.add_widget(layout)

    def update_rect(self, *args):
        """
        Updates the rect value.
        :param args:
        """
        self.rect.pos = self.pos
        self.rect.size = self.size

    def clear_inputs_and_outputs(self, instance):
        """
        Clears specific data on the screen.
        :param instance: the button instance that triggered the event.
        """
        self.message_label.text = ''
        self.group_data_layout.clear_widgets()
        self.group_shared_diary_layout.clear_widgets()

    def see_shared_diaries_back_button_press(self, instance):
        """
        Switching to the see shared diaries screen.
        :param instance: the button instance that triggered the event.
        """
        self.message_label.text = ''
        self.group_data_layout.clear_widgets()
        self.group_shared_diary_layout.clear_widgets()

        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "see_shared_diaries_screen"
        self.manager.current = "see_shared_diaries_screen"  # Switch to the tasks_screen

    def exit_app(self, instance):
        """
        Exists the app.
        :param instance: the button instance that triggered the event.
        """
        global screen_flow
        screen_flow["prev"] = screen_flow["current"]
        screen_flow["current"] = "exit_app"
        App.get_running_app().stop()

    def refresh_screen(self, instance):
        """
        Refreshes the screen
        :param instance: the button instance that triggered the event.
        """
        self.message_label.text = ''
        self.group_data_layout.clear_widgets()
        self.group_shared_diary_layout.clear_widgets()

        self.on_enter()  # Call the on_enter method to add the widgets to the layout

    def on_enter(self):
        """
        Shows the client the data about the group:
        the basic data, such as addresser (the manager of the group) and the recipients and the dates range of the group,
        and shows the client the shared tasks calendar of the group, which contains in a sorted order all the tasks of the recipients in the group.
        """
        global screen_flow
        if screen_flow["prev"] == "see_shared_diaries_screen":  # maybe add more
            print("Asking the server to see my specific share diary group... \n")
            cmd = chatlib.PROTOCOL_SHARED_DIARIES_CLIENT['see_specific_shared_diaries_group_msg']

            group_info = ""
            print(screen_flow.keys())
            if "specific share diary group to see" in screen_flow.keys():
                group_info = screen_flow["specific share diary group to see"][-1]

            build_and_send_message(self.conn, cmd, group_info)
            data = wise_recv(self.conn)
            if data is None:
                return
            curr_cmd, msg = chatlib.parse_message(data)
            if curr_cmd == chatlib.PROTOCOL_SHARED_DIARIES_SERVER['see_specific_shared_diaries_group_ok_msg']:
                # first part - basic data about the group.
                group_basic_data_msg = msg.split("#")[0]
                # show the dataframe
                group_basic_data_df = pd.read_json(group_basic_data_msg)
                group_basic_data_df.set_index(pd.Index(range(1, len(group_basic_data_df) + 1)), inplace=True)

                # Get the column names from the DataFrame
                column_names = [str(name) for name in group_basic_data_df.columns]

                # Get the values for each row in the DataFrame
                values_list = []
                for i in range(group_basic_data_df.shape[0]):
                    row_values = [str(group_basic_data_df.iloc[i][col]) for col in column_names]
                    values_list.append(tuple(row_values))

                print("Number of values:", len(values_list))

                # Create the column data for the MDDataTable
                column_data = [(name, 30) for name in column_names]

                # Create the MDDataTable widget
                self.basic_group_data_table = MDDataTable(
                    size_hint=(1, 1),
                    column_data=column_data,
                    row_data=values_list,
                    rows_num=len(values_list),
                    use_pagination=False
                )

                self.group_data_layout.add_widget(self.basic_group_data_table)

                # second part - the group's shared diary.
                group_shared_diary_msg = msg.split("#")[1]
                # show the dataframe
                group_shared_diary_df = pd.read_json(group_shared_diary_msg)
                group_shared_diary_df.set_index(pd.Index(range(1, len(group_shared_diary_df) + 1)), inplace=True)

                # Get the column names from the DataFrame
                column_names = [str(name) for name in group_shared_diary_df.columns]

                # Get the values for each row in the DataFrame
                values_list = []
                for i in range(group_shared_diary_df.shape[0]):
                    row_values = [str(group_shared_diary_df.iloc[i][col]) for col in column_names]
                    values_list.append(tuple(row_values))

                print("Number of values:", len(values_list))

                # Create the column data for the MDDataTable
                column_data = [(name, 30) for name in column_names]

                # Create the MDDataTable widget
                self.group_shared_diary_table = MDDataTable(
                    size_hint=(1, 1),
                    column_data=column_data,
                    row_data=values_list,
                    rows_num=len(values_list),
                    use_pagination=False
                )

                self.group_shared_diary_layout.add_widget(self.group_shared_diary_table)

            else:
                self.message_label.text = msg


def ask_for_username(conn):
    """
    Asking the server for the client's username.
    :param conn - a specific client connected to the server.
    """
    cmd = chatlib.PROTOCOL_CLIENT['send_username_msg']
    build_and_send_message(conn, cmd, "")

    data = wise_recv(conn)
    if data is None:
        return

    curr_cmd, msg = chatlib.parse_message(data)
    client_username = ""

    if curr_cmd == chatlib.PROTOCOL_SERVER['send_username_ok_msg']:
        client_username = msg

    return client_username


def val_date(date):
    """
    Checks if the input (date) is in the correct date form (DD/MM/YYYY).
    :param date - a specific date.
    """
    from datetime import datetime
    try:
        date_object = datetime.strptime(date, '%d/%m/%Y')

        min_date = np.datetime64('1678-01-01')
        max_date = np.datetime64('2261-01-01')

        is_in_range = (date_object.date() >= min_date) & (date_object.date() <= max_date)
        print(is_in_range)

        if is_in_range:
            return True

        return False

    except ValueError:
        return False


def return_indexes(s, min_index, max_index):
    """
    Returns True if s is in the form s_1 , s_2 , s_3 ,..., s_n,
    and for all 1<=i<=n, s_i is in [min_index, max_index].

    Returns false otherwise

    :param s - a string.
    :param min_index - an integer.
    :param max_index - an integer.
    """
    pattern = r"^\d+(,\s*\d+)*$"

    if re.match(pattern, s):
        str_numbers_list = re.findall(r"\d+", s)  # finds all the digits /d in the number
        numbers_list = [int(a) for a in str_numbers_list]
        return all(min_index <= index <= max_index for index in numbers_list), numbers_list

    return False, []


def get_key(conn):
    """
    Builds the key for the cypher. It asks the server for its public key while sending the client's public key.
    Then, using the server's public key, it is calculated through the server and client's shared key.

    :param conn - a specific client connected to the server.
    """
    global client_key  # the client_key (=shared key) is a global variable

    client_public_value = csv.client_public_val  # the client public value
    client_secret_prime = csv.p  # the prime
    client_secret_value = csv.client_secret_val  # the client secret value

    client_key = 0

    full_msg = chatlib.PROTOCOL_CLIENT['public_key_msg'] + "|" + str(client_public_value)
    print("[THE CLIENT'S MESSAGE] ", full_msg)  # Debug print
    conn.send(full_msg.encode())  # sending to the server the public key

    try:
        data = conn.recv(10024).decode()

    except:
        print("Server went down!")
        return

    curr_cmd, msg = chatlib.parse_message(data)
    if curr_cmd == chatlib.PROTOCOL_SERVER['public_key_ok_msg']:
        server_public_value = int(msg)
        client_key = pow(server_public_value, client_secret_value, client_secret_prime)

    else:
        print(msg)

    return str(client_key)


def main():
    """
    The main function of the client side.
    """
    global screen_flow  # a global dictionary
    screen_flow = {}

    my_app = MyApp()
    my_app.run()  # running the app


if __name__ == '__main__':
    main()
