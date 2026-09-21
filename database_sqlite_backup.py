import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.db"


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def coluna_existe(conn, tabela, coluna):
    colunas = conn.execute(
        f"PRAGMA table_info({tabela})"
    ).fetchall()

    return any(
        item["name"] == coluna
        for item in colunas
    )


def criar_banco():
    conn = get_db_connection()
    cursor = conn.cursor()

    # ==========================================================
    # USUÁRIOS
    # ==========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            foto_casal TEXT,
            data_casamento TEXT,
            plano TEXT DEFAULT 'teste',
            status_pagamento TEXT DEFAULT 'pendente',
            criado_em TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ==========================================================
    # CASAMENTOS
    # ==========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS casamentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            usuario_id INTEGER NOT NULL UNIQUE,

            nome_pessoa_1 TEXT,
            nome_pessoa_2 TEXT,

            data_casamento TEXT,

            local_casamento TEXT,
            cidade TEXT,
            estado TEXT,

            orcamento_planejado REAL DEFAULT 0,

            convidados_estimados INTEGER DEFAULT 0,

            foto_capa TEXT,

            criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
            atualizado_em TEXT DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (usuario_id)
                REFERENCES usuarios(id)
                ON DELETE CASCADE
        )
    """)

    # ==========================================================
    # CATEGORIAS DE FORNECEDORES
    # ==========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS categorias_fornecedor (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            usuario_id INTEGER NOT NULL,

            nome TEXT NOT NULL,

            criado_em TEXT DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (usuario_id)
                REFERENCES usuarios(id)
                ON DELETE CASCADE,

            UNIQUE (usuario_id, nome)
        )
    """)

    # ==========================================================
    # FORNECEDORES
    # ==========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fornecedores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            nome TEXT NOT NULL,
            whatsapp TEXT,
            valor REAL NOT NULL DEFAULT 0,
            valor_pago REAL NOT NULL DEFAULT 0,
            criado_em TEXT DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (usuario_id)
                REFERENCES usuarios(id)
                ON DELETE CASCADE
        )
    """)

    # ==========================================================
    # ADICIONA CATEGORIA_ID EM FORNECEDORES
    # SEM APAGAR DADOS EXISTENTES
    # ==========================================================

    if not coluna_existe(
        conn,
        "fornecedores",
        "categoria_id"
    ):

        cursor.execute("""
            ALTER TABLE fornecedores
            ADD COLUMN categoria_id INTEGER
        """)

    # ==========================================================
    # HISTÓRICO DE PAGAMENTOS
    # ==========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS historico_pagamento (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fornecedor_id INTEGER NOT NULL,
            valor REAL NOT NULL,
            data_pagamento TEXT NOT NULL,
            criado_em TEXT DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (fornecedor_id)
                REFERENCES fornecedores(id)
                ON DELETE CASCADE
        )
    """)

    # ==========================================================
    # TAREFAS
    # ==========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tarefas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            titulo TEXT NOT NULL,
            categoria TEXT,
            concluido INTEGER NOT NULL DEFAULT 0,
            criado_em TEXT DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (usuario_id)
                REFERENCES usuarios(id)
                ON DELETE CASCADE
        )
    """)
# ==========================================================
# PLANEJAMENTO DE PAGAMENTOS
# ==========================================================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pagamentos_planejados (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        fornecedor_id INTEGER NOT NULL,

        descricao TEXT NOT NULL,

        valor REAL NOT NULL DEFAULT 0,

        data_prevista TEXT,

        status TEXT NOT NULL DEFAULT 'Pendente',

        criado_em TEXT DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (fornecedor_id)
            REFERENCES fornecedores(id)
            ON DELETE CASCADE
    )
""")
    # ==========================================================
    # CONVIDADOS
    # ==========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS convidados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            nome TEXT NOT NULL,
            telefone TEXT,
            acompanhantes INTEGER NOT NULL DEFAULT 0,
            status_confirmacao TEXT NOT NULL DEFAULT 'Pendente',
            observacao TEXT,
            criado_em TEXT DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (usuario_id)
                REFERENCES usuarios(id)
                ON DELETE CASCADE
        )
    """)

    conn.commit()
    conn.close()


if __name__ == "__main__":
    criar_banco()
    print("Banco criado/validado com sucesso.")