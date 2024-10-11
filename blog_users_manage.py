import sqlite3
from uuid import uuid4


def create_table():
    """
    Create table if not exists
    """

    connection = sqlite3.connect('blogs.db')
    cursor = connection.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Blogs (
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    text TEXT NOT NULL
    )
    ''')

    connection.commit()
    connection.close()


def add_user(username, password):
    """
    Add user to table
    """

    connection = sqlite3.connect('users.db')
    cursor = connection.cursor()

    uuid = str(uuid4())

    cursor.execute('INSERT INTO Users (id, username, password) VALUES (?, ?, ?)',
                   (uuid, username, password))

    connection.commit()
    connection.close()


def del_user(username):
    """
    Delete user from table
    """

    connection = sqlite3.connect('users.db')
    cursor = connection.cursor()

    cursor.execute('DELETE FROM Users WHERE username = ?', (username,))

    connection.commit()
    connection.close()


def get_id(username):
    """
    Get id from table
    """

    connection = sqlite3.connect('users.db')
    cursor = connection.cursor()

    cursor.execute('SELECT id FROM Users WHERE username = ?',
                   (username,))
    try:
        return cursor.fetchall()[0][0]
    except IndexError:
        pass


def get_user(uuid):
    """
    Get user from table
    """

    connection = sqlite3.connect('users.db')
    cursor = connection.cursor()

    cursor.execute('SELECT username FROM Users WHERE id = ?',
                   (uuid,))

    try:
        return cursor.fetchall()[0][0]
    except IndexError:
        return None


def check_password(username, password):
    """
    check password
    """

    connection = sqlite3.connect('users.db')
    cursor = connection.cursor()

    cursor.execute('SELECT password FROM Users WHERE username = ?',
                   (username,))

    try:
        res = cursor.fetchall()[0]
        if res[0] == password:
            return True
        else:
            return False
    except IndexError:
        return False
