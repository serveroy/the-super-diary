import sqlite3
import pandas as pd
from datetime import datetime
import datetime


def create_connection(data_base_file):
    """ Creates a database connection to the SQLite database named by data_base_file
    :param data_base_file: database file
    :return: Connection object or None if there was on exception when trying to connect.
    """
    conn = None
    try:
        conn = sqlite3.connect(data_base_file)
        return conn

    except Exception as e:
        print(e)

    return conn


# creation of tables

def create_table(conn, table_name, columns):
    """
    Creates the table, first the function creates a cursor that can change or edit the table.
    Then the function creates the table if it doesn't exist already, with specific columns.

    :param conn: the connection object to the table.
    :param columns : the columns of the table.
    :param table_name : the name of the table that will be created.
    :return the table
    """

    try:
        cursor = conn.cursor()
        query = f"CREATE TABLE IF NOT EXISTS {table_name}({', '.join(list(columns.values()))})"
        cursor.execute(query)
        conn.commit()

    except Exception as e:
        print(e)


def create_diaries_sharing_requests_table(conn):
    """
    Creates the table, first the function creates a cursor that can change or edit the table.
    Then the function creates the table if it doesn't exist already, with specific columns.

    :param conn: the connection object to the table.
    :return the table
    """
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS diaries_sharing_requests (
                            addresser TEXT,
                            recipients TEXT,
                            dates_range TEXT,
                            approvals TEXT,
                            theme TEXT,
                            info TEXT
                        )''')

        conn.commit()

    except Exception as e:
        print(e)


def create_diaries_sharing_groups_table(conn):
    """
    Creates the table, first the function creates a cursor that can change or edit the table.
    Then the function creates the table if it doesn't exist already, with specific columns.

    :param conn: the connection object to the table.
    :return the table
    """

    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS diaries_sharing_groups (
                            addresser TEXT,
                            recipients TEXT,
                            dates_range TEXT,
                            theme TEXT,
                            info TEXT
                        )''')

        conn.commit()

    except Exception as e:
        print(e)


# tables update (inserting values)

def update_users_table(conn, values_dict):
    """"
    create a table from the create_table_sql statement
    :param conn: Connection object
    :param values_dict: the dict of the values
    :return:
    """

    try:
        cursor = conn.cursor()

        query = "INSERT INTO users VALUES (?, ?, ?, ?)"
        cursor.execute(query, list(values_dict.values()))

        # Commit the changes
        conn.commit()

    except Exception as e:
        print(e)


def update_tasks_table(conn, values_dict):
    """
    updates the tasks table.
    :param conn: Connection object
    :param values_dict: the dict of the values
    :return:
    """

    try:
        cursor = conn.cursor()

        query = "INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)"
        cursor.execute(query, list(values_dict.values()))

        # Commit the changes
        conn.commit()

    except Exception as e:
        print(e)


def update_diaries_sharing_requests_table(conn, values_list):
    """
    updates the diaries sharing requests table.
    :param conn: Connection object
    :param values_list: the lict of the new values
    :return:
    """
    try:
        cursor = conn.cursor()

        query = "INSERT INTO diaries_sharing_requests VALUES (?, ?, ?, ?, ?, ?)"
        cursor.execute(query, values_list)

        # Commit the changes
        conn.commit()

    except Exception as e:
        print(e)


def update_diaries_sharing_groups_table(conn, values_list):
    """
    updates the diaries sharing requests table.
    :param conn: Connection object
    :param values_list: the lict of the new values
    :return:
    """
    try:
        cursor = conn.cursor()

        query = "INSERT INTO diaries_sharing_groups VALUES (?, ?, ?, ?, ?)"
        cursor.execute(query, values_list)

        # Commit the changes
        conn.commit()

    except Exception as e:
        print(e)


# changing rows

def change_specific_row(conn, table_name, old_id, new_id):
    """
    Changing a specific id in a table.
    :param conn: a connection to the database that contains the table.
    :param table_name: the name of the table.
    :param old_id: the old id.
    :param new_id: the new id.
    """
    # id update
    try:
        cursor = conn.cursor()

        query = f"UPDATE {table_name} SET id=? WHERE id=?"
        cursor.execute(query, (str(new_id), str(old_id)))

        # Commit the changes, maybe close the connection?
        conn.commit()

    except Exception as e:
        print(e)


def change_table(conn, table_name, column, old_val, new_val):
    """
    Changing a specific id in a table.
    :param conn: a connection to the database that contains the table.
    :param table_name: the name of the table.
    :param column: the name of the column (in the table)
    :param old_val: the existing value.
    :param new_val: the new value.
    """
    # assumption : the value can't appear twice in the same column.
    # meaning : you can't put name again.
    try:
        cursor = conn.cursor()

        # Update the table with the new data
        query = f"UPDATE {table_name} SET {column}=? WHERE {column}=?"
        if column == "id":
            cursor.execute(query, (str(new_val), str(old_val)))

        else:
            cursor.execute(query, (new_val, old_val))

        # Commit the changes
        conn.commit()

    except Exception as e:
        print(e)


def change_users_row(conn, column, val, known_row):
    """
    Changes the val in the known_row in the users table.
    """
    try:
        cursor = conn.cursor()

        query = f"UPDATE users SET {column} = ? WHERE id = ? AND name = ? AND username = ? and password = ?"
        cursor.execute(query, [val] + known_row)

        # Commit the changes
        conn.commit()

    except Exception as e:
        print(e)


def change_tasks_row(conn, column, val, known_row):
    """
    Changes the val in the known_row in the tasks table.
    """
    try:
        cursor = conn.cursor()

        query = f"UPDATE tasks SET {column} = ? WHERE day = ? AND month = ? AND year = ? AND info = ? AND did_finish = ? AND client_id = ? AND username = ?"
        cursor.execute(query, [val] + known_row)

        # Commit the changes
        conn.commit()

    except Exception as e:
        print(e)


def change_tasks_rows_by_username(conn, column, val, client_username):
    """
    Changes the val in the known_row in the tasks table.
    """
    try:
        cursor = conn.cursor()

        query = f"UPDATE tasks SET {column} = ? WHERE username = ?"
        cursor.execute(query, [val, client_username])

        # Commit the changes
        conn.commit()

    except Exception as e:
        print(e)


def change_approval_situation(conn, info_data, index, new_client_approval):
    """
    Change the approval situation in the specific row in a specific index.
    index - the index in the list of the current approvals to change
    """
    try:
        print(info_data)
        cursor = conn.cursor()
        query = "SELECT approvals FROM diaries_sharing_requests WHERE info = ?"
        cursor.execute(query, (info_data,))

        current_approvals = cursor.fetchall()[0][0]
        approvals_list = current_approvals.split(", ")
        approvals_list[index] = str(new_client_approval)
        new_approvals = ", ".join(approvals_list)
        print(new_approvals)

        # Update the row in the table with the new approvals value
        update_query = "UPDATE diaries_sharing_requests SET approvals = ? WHERE info = ?"
        cursor.execute(update_query, (new_approvals, info_data))
        conn.commit()  # commit the changes
        return new_approvals

    except Exception as e:
        print(e)


def delete_approvals_val(conn, info_data, new_approvals):
    """
    Change the approval situation in the specific row in a specific index.
    """
    try:
        cursor = conn.cursor()
        # Update the row in the table with the new approvals value
        update_query = "UPDATE diaries_sharing_requests SET approvals = ? WHERE info = ?"
        update_values = (new_approvals, info_data)
        cursor.execute(update_query, update_values)
        conn.commit()  # commit the changes

    except Exception as e:
        print(e)


def change_recipients_situation_share_diary_requests(conn, info_data, new_recipients):
    """
    Changes the recipients in the specific row in a specific index in the share diary requests table.
    index - the index in the list of the current approvals to change
    """
    try:
        cursor = conn.cursor()
        # Update the row in the table with the new approvals value
        update_query = "UPDATE diaries_sharing_requests SET recipients = ? WHERE info = ?"
        update_values = (new_recipients, info_data)
        cursor.execute(update_query, update_values)
        conn.commit()  # commit the changes

    except Exception as e:
        print(e)


def change_recipients_situation_share_diary_groups(conn, info_data, new_recipients):
    """
    Changes the recipients in the specific row in a specific index in the share diary groups table.
    index - the index in the list of the current approvals to change
    """
    try:
        cursor = conn.cursor()
        # Update the row in the table with the new approvals value
        update_query = "UPDATE diaries_sharing_groups SET recipients = ? WHERE info = ?"
        update_values = (new_recipients, info_data)
        cursor.execute(update_query, update_values)
        conn.commit()  # commit the changes

    except Exception as e:
        print(e)


def change_diaries_sharing_requests_row(conn, column, val, info_data):
    """
    Changes the val in the known_row in the diaries_sharing_requests table.
    """
    try:
        cursor = conn.cursor()

        query = f"UPDATE diaries_sharing_requests SET {column} = ? WHERE info = ?"
        cursor.execute(query, [val] + info_data)

        # Commit the changes
        conn.commit()

    except Exception as e:
        print(e)


def change_diaries_sharing_groups_row(conn, column, val, info_data):
    """
    Changes the val in the known_row in the diaries_sharing_groups table.
    """
    try:
        cursor = conn.cursor()

        query = f"UPDATE diaries_sharing_requests SET {column} = ? WHERE info = ?"
        cursor.execute(query, [val] + info_data)

        # Commit the changes
        conn.commit()

    except Exception as e:
        print(e)


def change_column_name(conn, table_name, old_column_name, new_column_name):
    """
    Changing a specific id in a table.
    :param conn: a connection to the database that contains the table.
    :param table_name: the name of the table.
    :param old_column_name: the existing column name (in the table)
    :param new_column_name: the new column name.
    """
    try:
        cursor = conn.cursor()

        query = f"ALTER TABLE {table_name} RENAME COLUMN {old_column_name} TO {new_column_name}"
        cursor.execute(query)

        # Commit the changes
        conn.commit()

    except Exception as e:
        print(e)


# search id in tasks and users

def search_id_in_users(conn, username, password):
    try:
        cursor = conn.cursor()

        query = f"SELECT id FROM users WHERE username = ? AND password = ?"
        cursor.execute(query, (username, password))
        result = cursor.fetchone()
        id_found = result[0]

        # Commit the changes
        conn.commit()
        return id_found

    except Exception as e:
        print(e)


def search_id_in_tasks(conn, client_username):
    try:
        cursor = conn.cursor()
        query = f"SELECT client_id FROM tasks WHERE username = ?"
        cursor.execute(query, (client_username,))
        result = cursor.fetchone()
        print(result)
        id_found = result[0]

        # Commit the changes
        conn.commit()
        return id_found

    except Exception as e:
        print(e)


# list of column, list of values

def list_of_columns(cursor, table_name):
    """
    :param cursor:
    :param table_name:
    :return:
    """
    try:
        columns_list = []

        query = "PRAGMA table_info (" + table_name + ")"
        cursor.execute(query)
        columns = cursor.fetchall()

        for column in columns:
            columns_list.append(column[1])

        return columns_list

    except Exception as e:
        print(e)


def list_of_values(cursor, table_name, column):
    """
    :param table_name: The name of the table in the data base
    :param column: The name of the column
    :param cursor: a pointer to the connection
    :return:
    """
    try:
        query = "SELECT " + column + " from " + table_name
        cursor.execute(query)
        rows = cursor.fetchall()

        values_list = []

        for row in rows:
            values_list.append(row[0])

        return values_list

    except Exception as e:
        print(e)


# delete functions

def delete_users_row(conn, specific_id):
    """
    :param conn:
    :param specific_id:
    :return:
    """
    try:
        cursor = conn.cursor()
        # print("HELLO!!!!!")
        query = "DELETE from users Where id = ?"
        cursor.execute(query, (specific_id, ))
        conn.commit()

    except Exception as e:
        print(e)


def delete_tasks_row_using_only_id(conn, specific_id):
    """
    :param conn:
    :param specific_id:
    :return:
    """
    try:
        cursor = conn.cursor()
        query = "DELETE from tasks Where client_id = ?"
        cursor.execute(query, (specific_id, ))
        conn.commit()

    except Exception as e:
        print(e)


def delete_tasks_row_using_whole_row(conn, tasks_row):
    """
    Deletes one row of the tasks table.
    """
    try:
        cursor = conn.cursor()
        query = "DELETE from tasks WHERE day = ? AND month = ? AND year = ? AND info = ? AND did_finish = ? AND client_id = ? AND username = ?" #only once
        cursor.execute(query, tasks_row)
        conn.commit()

    except Exception as e:
        print(e)


def delete_diaries_sharing_requests_row(conn, info_data):
    """
    Deletes a row of the diaries sharing requests table.
    """
    try:
        cursor = conn.cursor()
        query = "DELETE from diaries_sharing_requests WHERE info = ?"
        cursor.execute(query, (info_data,))
        conn.commit()

    except Exception as e:
        print(e)


def delete_diaries_sharing_groups_row(conn, info_data):
    """
    Deletes a row of the diaries sharing groups table.
    """
    try:
        cursor = conn.cursor()
        query = "DELETE FROM diaries_sharing_groups WHERE info = ?"
        cursor.execute(query, (info_data,))
        conn.commit()

    except Exception as e:
        print(e)


# returning part of tables

# users

def return_users_row(conn, client_id):
    """
    Returns a specific row of users
    :param conn: A connection to the database.
    :param client_id: An id of existing client.
    :return:
    """

    try:
        query = f"SELECT * FROM users WHERE id = ?"
        df = pd.read_sql_query(query, conn, params=[client_id])

        # Commit the changes
        conn.commit()
        return df

    except Exception as e:
        print(e)


def return_name_id_by_username(conn, username):
    """
    Returns the name and ID of a user with the given username
    :param conn: A connection to the database.
    :param username: A username of existing client.
    :return: A tuple containing the name and ID of the user, or None if the user doesn't exist.
    """

    try:
        cursor = conn.cursor()
        query = f"SELECT name, id FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        # Retrieve the query result
        row = cursor.fetchone()
        if row is None:
            return None
        else:
            name, client_id = row
            # Commit the changes
            conn.commit()
            return name, client_id

    except Exception as e:
        print(e)


# tasks

def return_part_of_tasks_by_id(conn, client_id):
    """
    Returns a specific part of tasks - not all! Only the tasks of the client with id=client_id
    :param conn: A connection to the database.
    :param client_id: An id of existing client.
    :return:
    """

    try:
        cursor = conn.cursor()
        query = f"SELECT day, month, year, info, did_finish FROM tasks WHERE client_id = ?"
        df = pd.read_sql_query(query, conn, params=[client_id])

        # Commit the changes
        conn.commit()
        return df

    except Exception as e:
        print(e)


def return_unfinished_task_by_id(conn, client_id):
    """
    Returns all the unfinished tasks of the client with id=client_id.
    :param conn: A connection to the database.
    :param client_id: An id of existing client.
    :return:
    """

    try:
        cursor = conn.cursor()
        query = f"SELECT day, month, year, info, did_finish FROM tasks WHERE client_id = ? AND did_finish != ?"
        df = pd.read_sql_query(query, conn, params=[client_id, "1"])

        # Commit the changes
        conn.commit()
        return df

    except Exception as e:
        print(e)


def return_tasks_row(conn, values_list):
    """
    Returns a specific part of tasks
    :param conn: A connection to the database.
    :param values_list: An id of existing client.
    :return:
    """

    try:
        cursor = conn.cursor()
        query = "SELECT * FROM tasks WHERE day = ? AND month = ? AND year = ? AND info = ? AND did_finish = ? AND client_id = ? AND username = ?"
        cursor.execute(query, values_list)

        # Fetch the results and convert to list of tuples
        results = cursor.fetchall()
        if len(results) == 0:
            return None

        results_list = [tuple(row) for row in results]
        conn.commit()    # Commit the changes

        return results_list

    except Exception as e:
        print(e)


def return_parts_of_tasks_groups(conn, usernames_list):
    """
    Returns a specific part of tasks - all the rows user username is in usernames_list
    :param conn: A connection to the database.
    :param usernames_list: A list of usernames
    :return:
    """

    try:
        cursor = conn.cursor()
        query = f"SELECT username, day, month, year, info, did_finish FROM tasks WHERE username IN ({','.join(['?'] * len(usernames_list))})"
        cursor.execute(query, usernames_list)
        rows = cursor.fetchall()
        columns = [column[0] for column in cursor.description]
        df = pd.DataFrame(rows, columns=columns)
        print(df)
        # Commit the changes
        conn.commit()
        return df

    except Exception as e:
        print(e)


# diaries sharing requests

def return_diaries_sharing_requests_row(conn, info_msg):
    """
    Returns a diaries sharing requests row. None if it doesn't exist.
    """
    try:
        query = "SELECT * FROM diaries_sharing_requests WHERE info = ?"
        df = pd.read_sql_query(query, conn, params=[info_msg])

        if df.empty:
            return None
        return df

    except Exception as e:
        print(e)


def return_all_client_outgoing_share_diary_requests(conn, client_username):
    """
    Returns all the requests that the client in input (username = client_username) made to share his diary.
    """
    try:
        query = "SELECT recipients, dates_range, approvals, theme, info FROM diaries_sharing_requests WHERE addresser = ?"
        df = pd.read_sql_query(query, conn, params=[client_username])

        # Commit the changes
        conn.commit()
        return df

    except Exception as e:
        print(e)


def all_client_ingoing_share_diary_requests(conn, client_username):
    """
    Returns all the ingoing requests to the client conn (his username is client_username)
    """

    try:
        query = "SELECT * FROM diaries_sharing_requests WHERE ', ' || recipients || ', ' LIKE '%" + client_username + "%';"
        df = pd.read_sql_query(query, conn)

        # Commit the changes
        conn.commit()
        return df

    except Exception as e:
        print(e)


# diaries sharing groups

def return_diaries_sharing_groups_row(conn, info_msg):
    """
    Returns a diaries sharing groups row. None if it doesn't exist.
    """
    try:
        query = "SELECT * FROM diaries_sharing_groups WHERE info = ?"
        df = pd.read_sql_query(query, conn, params=[info_msg])
        print(df)

        if df.empty:
            return None
        return df

    except Exception as e:
        print(e)


def return_all_share_diary_groups_containing_client(conn, client_username):
    """
    Returns all groups that involve the client (username = client_username)
    """

    try:
        query = f"SELECT * FROM diaries_sharing_groups WHERE addresser = ? OR recipients LIKE ? OR recipients LIKE ? OR recipients LIKE ? OR recipients LIKE ?"
        df = pd.read_sql_query(query, conn, params=[client_username, f'%{client_username}', f'{client_username},%', f'%, {client_username},%', f'%, {client_username}'])
        if df.empty:
            return None
        return df

    except Exception as e:
        print(e)


def return_all_share_diary_groups_client_username_manages(conn, client_username):
    """
    Returns all groups that the client is the addresser there.
    """

    try:
        query = f"SELECT * FROM diaries_sharing_groups WHERE addresser = ?"
        df = pd.read_sql_query(query, conn, params=[client_username])
        if df.empty:
            return None
        return df

    except Exception as e:
        print(e)


# functions for automatic change.

def update_dates_range():
    """
    The function is raising each value in the dates range column in sha share diary requests table,
    and in the share diary group table.
    """
    # Connect to the database
    conn = create_connection('data_base.db')
    cursor = conn.cursor()

    # Update the diaries_sharing_groups table
    cursor.execute('SELECT * FROM diaries_sharing_groups')
    groups = cursor.fetchall()

    for group in groups:
        dates_range = group[2]
        info = group[4]

        dates = dates_range.split(' -> ')
        new_dates = []

        for date in dates:
            date_obj = datetime.datetime.strptime(date, '%d/%m/%Y')
            date_obj += datetime.timedelta(days=1)  # Add one day
            new_date_str = date_obj.strftime('%d/%m/%Y')  # Convert to string
            new_dates.append(new_date_str)

        new_dates_range = ' -> '.join(new_dates)
        query = 'UPDATE diaries_sharing_groups SET dates_range = ? WHERE info = ?'
        cursor.execute(query, (new_dates_range, info))

    # Update the diaries_sharing_requests table
    cursor.execute('SELECT * FROM diaries_sharing_requests')
    requests = cursor.fetchall()

    for request in requests:
        dates_range = request[2]
        info = request[5]
        dates = dates_range.split(' -> ')
        new_dates = []

        for date in dates:
            date_obj = datetime.datetime.strptime(date, '%d/%m/%Y')
            date_obj += datetime.timedelta(days=1)  # Add one day
            new_date_str = date_obj.strftime('%d/%m/%Y')  # Convert to string
            new_dates.append(new_date_str)

        new_dates_range = ' -> '.join(new_dates)
        query = 'UPDATE diaries_sharing_requests SET dates_range = ? WHERE info = ?'
        cursor.execute(query, (new_dates_range, info))

    # Commit the changes
    conn.commit()


def main():
    # Connect to the database (or create it if it doesn't exist)
    data_base_connection = create_connection('data_base.db')
    cursor = data_base_connection.cursor()

    users_columns = {1: "id", 2: "name", 3: "username", 4: "password"}
    create_table(data_base_connection, "users", users_columns)

    tasks_columns = {1: "day", 2: "month", 3: "year",  4: "info", 5: "did_finish", 6: "client_id", 7: "username"}
    create_table(data_base_connection, "tasks", tasks_columns)

    create_diaries_sharing_requests_table(data_base_connection)
    create_diaries_sharing_groups_table(data_base_connection)

    # cursor.execute("DROP TABLE IF EXISTS users")
    # cursor.execute("DROP TABLE IF EXISTS tasks")
    # cursor.execute("DROP TABLE IF EXISTS diaries_sharing_requests")
    # cursor.execute("DROP TABLE IF EXISTS diaries_sharing_groups")

    df = pd.read_sql_query("SELECT * from users", data_base_connection)
    print(df)

    print(list_of_columns(cursor, "users"))
    print(list_of_values(cursor, "users", "id"))
