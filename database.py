import os

import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv


load_dotenv()


class DatabaseConnection:
    def __init__(self):
        database_url = os.getenv("DATABASE_URL")

        # Produção:
        # provedores normalmente disponibilizam uma DATABASE_URL.
        if database_url:
            self.conn = psycopg.connect(
                database_url,
                row_factory=dict_row,
            )

        # Desenvolvimento local:
        # utiliza as configurações individuais do .env.
        else:
            self.conn = psycopg.connect(
                host=os.getenv("DB_HOST"),
                port=os.getenv("DB_PORT"),
                dbname=os.getenv("DB_NAME"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                row_factory=dict_row,
            )

    def _converter_sql(self, sql):
        """
        Converte os placeholders antigos do SQLite (?)
        para o formato utilizado pelo psycopg (%s).

        Isso mantém compatibilidade com as consultas
        existentes no app.py.
        """
        return sql.replace("?", "%s")

    def execute(self, sql, parametros=None):
        sql = self._converter_sql(sql)

        cursor = self.conn.cursor()

        if parametros is None:
            cursor.execute(sql)
        else:
            cursor.execute(
                sql,
                parametros
            )

        return cursor

    def cursor(self):
        return DatabaseCursor(
            self.conn
        )

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()


class DatabaseCursor:
    def __init__(self, conn):
        self.cursor_real = conn.cursor()

    def _converter_sql(self, sql):
        return sql.replace("?", "%s")

    def execute(self, sql, parametros=None):
        sql = self._converter_sql(sql)

        if parametros is None:
            self.cursor_real.execute(sql)
        else:
            self.cursor_real.execute(
                sql,
                parametros
            )

        return self

    def fetchone(self):
        return self.cursor_real.fetchone()

    def fetchall(self):
        return self.cursor_real.fetchall()

    @property
    def rowcount(self):
        return self.cursor_real.rowcount

    def close(self):
        self.cursor_real.close()


def get_db_connection():
    return DatabaseConnection()