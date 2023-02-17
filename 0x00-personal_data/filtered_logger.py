#!/usr/bin/env python3
"""
Write a function called filter_datum that returns
the log message obfuscated
"""
from typing import List
import re
import logging
import mysql.connector
from os import getenv


PII_FIELDS = ('name', 'email', 'password', 'ssn', 'phone')


class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        method initialized
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        method calling method filter_datum
        """
        msg = logging.Formatter(self.FORMAT).format(record)
        return filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """
    The function should use a regex to replace occurrences
    of certain field values
    """
    for field in fields:
        regex = "(?<={}=)(.*?)(?={})".format(field, separator)
        message = re.sub(regex, redaction, message)
    return message


def get_logger() -> logging.Logger:
    """
    Implement a get_logger function that takes no
    arguments and returns a logging.Logger object
    """
    log = logging.getLogger("user_data")
    log.setLevel(logging.INFO)
    log.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    log.addHandler(stream_handler)
    return log


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Returns a connector to a mysql database
    """
    db_connection = mysql.connector.connection.MySQLConnection(
        user=getenv('PERSONAL_DATA_DB_USERNAME', 'root'),
        password=getenv('PERSONAL_DATA_DB_PASSWORD', ''),
        host=getenv('PERSONAL_DATA_DB_HOST', 'localhost'),
        database=getenv('PERSONAL_DATA_DB_NAME'))

    return db_connection


def main() -> None:
    """
    Implement a main function that takes no
    arguments and returns nothing
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")

    fields = []
    result = []
    for field in cursor.description:
        fields.append(field[0] + "=")

    log = get_logger()

    for row in cursor:
        for i in range(len(fields)):
            result.append(fields[i] + str(row[i]) + ";")
        log.info(" ".join(result))
        result = []

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
