"""Planner de casamento — aplicação Flask consolidada.

Substitua o app.py do projeto por este arquivo. Mantenha o database.py,
database.db, .env (SECRET_KEY) e os templates existentes, incluindo
templates/onboarding.html. Dependências: Flask e python-dotenv.
As tabelas são as já utilizadas no projeto; este arquivo não recria o banco.
Fluxo: cadastro -> sessão autenticada -> onboarding -> dashboard.
"""

import os
import math
import resend
from datetime import datetime, date
from pathlib import Path
from uuid import uuid4
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from dotenv import load_dotenv

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename

from database import get_db_connection
# ==========================================================
# CONFIGURAÇÕES
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent

# Carrega as variáveis do arquivo .env
load_dotenv(BASE_DIR / ".env")


# ==========================================================
# FLASK
# ==========================================================

app = Flask(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)
app.secret_key = os.getenv("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY não configurada no arquivo .env."
    )
csrf = CSRFProtect(app)
# =========================================================
# SEGURANÇA DA SESSÃO
# =========================================================

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)
# ==========================================================
# RESEND
# ==========================================================

RESEND_API_KEY = os.getenv("RESEND_API_KEY")

if not RESEND_API_KEY:
    raise RuntimeError(
        "RESEND_API_KEY não configurada no arquivo .env."
    )

resend.api_key = RESEND_API_KEY

serializer = URLSafeTimedSerializer (app.secret_key)

UPLOAD_FOLDER = (
    BASE_DIR
    / "static"
    / "uploads"
)

UPLOAD_FOLDER.mkdir(
    parents=True,
    exist_ok=True
)

app.config["UPLOAD_FOLDER"] = str(
    UPLOAD_FOLDER
)
# Limite máximo para uploads: 5 MB
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

EXTENSOES_PERMITIDAS = {
    "png",
    "jpg",
    "jpeg",
    "webp"
}

CATEGORIAS_PADRAO_FORNECEDOR = [
    "Espaço",
    "Buffet",
    "Decoração",
    "Fotografia e Vídeo",
    "Cerimonial",
    "Música / DJ",
    "Vestido / Traje",
    "Beleza",
    "Convites / Papelaria",
    "Bolo / Doces",
    "Lembrancinhas",
    "Transporte",
    "Lua de Mel",
    "Outros",
]

# ==========================================================
# HELPERS
# ==========================================================

def moeda_brl(valor):

    try:
        valor = float(
            valor or 0
        )

    except (
        ValueError,
        TypeError
    ):
        valor = 0

    valor_formatado = (
        f"{valor:,.2f}"
    )

    return (
        valor_formatado
        .replace(",", "X")
        .replace(".", ",")
        .replace("X", ".")
    )

app.jinja_env.filters[
    "moeda_brl"
] = moeda_brl

def converter_valor_brl(valor):

    if valor is None:
        return 0.0

    valor = (
        str(valor)
        .strip()
        .replace("R$", "")
        .replace(" ", "")
    )

    if not valor:
        return 0.0

    if (
        "." in valor
        and
        "," in valor
    ):
        valor = (
            valor
            .replace(".", "")
            .replace(",", ".")
        )

    elif "," in valor:
        valor = (
            valor
            .replace(",", ".")
        )

    numero = float(valor)
    if not math.isfinite(numero):
        raise ValueError("Informe um valor finito.")
    return round(numero, 2)

def arquivo_permitido(nome_arquivo):

    return (
        "."
        in nome_arquivo
        and
        nome_arquivo
        .rsplit(".", 1)[1]
        .lower()
        in EXTENSOES_PERMITIDAS
    )

def usuario_logado():

    return (
        "usuario_id"
        in session
    )

# ==========================================================
# INÍCIO
# ==========================================================

@app.route("/")
def index():

    if usuario_logado():
        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )
@app.route(
    "/redefinir-senha/<token>",
    methods=["GET", "POST"]
)
def redefinir_senha(token):

    # =========================================================
    # 1. VALIDAR O TOKEN
    # =========================================================

    try:
        dados_token = serializer.loads(
            token,
            salt="recuperacao-senha",
            max_age=1800  # 30 minutos
        )

    except SignatureExpired:

        flash(
            "Este link de recuperação expirou. Solicite um novo.",
            "erro"
        )

        return redirect(
            url_for("esqueci_senha")
        )

    except BadSignature:

        flash(
            "Este link de recuperação é inválido.",
            "erro"
        )

        return redirect(
            url_for("esqueci_senha")
        )


    # =========================================================
    # 2. PEGAR OS DADOS SALVOS NO TOKEN
    # =========================================================

    usuario_id = dados_token.get("usuario_id")
    senha_versao_token = dados_token.get("senha_versao")


    if (
        not usuario_id
        or senha_versao_token is None
    ):

        flash(
            "Este link de recuperação é inválido.",
            "erro"
        )

        return redirect(
            url_for("esqueci_senha")
        )


    # =========================================================
    # 3. LOCALIZAR O USUÁRIO
    # =========================================================

    conn = get_db_connection()

    usuario = conn.execute("""
        SELECT
            id,
            email,
            senha_versao
        FROM usuarios
        WHERE id = ?
    """, (
        usuario_id,
    )).fetchone()

    conn.close()


    if not usuario:

        flash(
            "Este link de recuperação é inválido.",
            "erro"
        )

        return redirect(
            url_for("esqueci_senha")
        )


    # =========================================================
    # 4. VERIFICAR SE O TOKEN JÁ FOI UTILIZADO
    # =========================================================

    if (
        usuario["senha_versao"]
        != senha_versao_token
    ):

        flash(
            "Este link de recuperação já foi utilizado ou não é mais válido.",
            "erro"
        )

        return redirect(
            url_for("esqueci_senha")
        )


    # =========================================================
    # 5. EXIBIR A TELA DE NOVA SENHA
    # =========================================================

    if request.method == "GET":

        return render_template(
            "redefinir_senha.html",
            token=token
        )


    # =========================================================
    # 6. RECEBER AS NOVAS SENHAS
    # =========================================================

    nova_senha = request.form.get(
        "nova_senha",
        ""
    )

    confirmar_senha = request.form.get(
        "confirmar_senha",
        ""
    )


    # =========================================================
    # 7. VALIDAR OS CAMPOS
    # =========================================================

    if not nova_senha or not confirmar_senha:

        flash(
            "Preencha os dois campos de senha.",
            "erro"
        )

        return redirect(
            url_for(
                "redefinir_senha",
                token=token
            )
        )


    if len(nova_senha) < 6:

        flash(
            "A nova senha precisa ter pelo menos 6 caracteres.",
            "erro"
        )

        return redirect(
            url_for(
                "redefinir_senha",
                token=token
            )
        )


    if nova_senha != confirmar_senha:

        flash(
            "As senhas informadas não conferem.",
            "erro"
        )

        return redirect(
            url_for(
                "redefinir_senha",
                token=token
            )
        )


    # =========================================================
    # 8. GERAR HASH DA NOVA SENHA
    # =========================================================

    nova_hash = generate_password_hash(
        nova_senha
    )


    # =========================================================
    # 9. ALTERAR A SENHA E INVALIDAR O TOKEN
    # =========================================================

    conn = get_db_connection()

    try:

        conn.execute("""
            UPDATE usuarios
            SET
                senha = ?,
                senha_versao = senha_versao + 1
            WHERE id = ?
        """, (
            nova_hash,
            usuario["id"]
        ))

        conn.commit()

    except Exception as erro:

        conn.rollback()

        print(
            "ERRO AO REDEFINIR SENHA:",
            erro
        )

        flash(
            "Não foi possível redefinir sua senha.",
            "erro"
        )

        return redirect(
            url_for(
                "redefinir_senha",
                token=token
            )
        )

    finally:

        conn.close()


    # =========================================================
    # 10. LIMPAR EVENTUAL SESSÃO EXISTENTE
    # =========================================================

    session.clear()


    # =========================================================
    # 11. REDIRECIONAR PARA LOGIN
    # =========================================================

    flash(
        "Senha redefinida com sucesso! Faça seu login.",
        "sucesso"
    )

    return redirect(
        url_for("login")
    )

@app.route("/esqueci-senha", methods=["GET", "POST"])
@limiter.limit("3 per 10 minutes", methods=["POST"])
def esqueci_senha():

    if request.method == "GET":
        return render_template(
            "esqueci_senha.html"
        )

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    if not email:
        flash(
            "Informe seu e-mail.",
            "erro"
        )

        return redirect(
            url_for("esqueci_senha")
        )

    conn = get_db_connection()

    usuario = conn.execute("""
        SELECT
            id,
            nome,
            email,
            senha_versao
        FROM usuarios
        WHERE LOWER(email) = LOWER(?)
    """, (
        email,
    )).fetchone()

    conn.close()


    # IMPORTANTE:
    # Mesmo que o e-mail não exista,
    # mostramos a mesma mensagem.
    #
    # Isso evita que alguém descubra
    # quais e-mails possuem cadastro.

    if usuario:

        token = serializer.dumps(
    {
        "usuario_id": usuario["id"],
        "senha_versao": usuario["senha_versao"]
    },
    salt="recuperacao-senha"
)

        link_recuperacao = url_for(
            "redefinir_senha",
            token=token,
            _external=True
        )

        try:

            resend.Emails.send({
                "from": "onboarding@resend.dev",
                "to": [usuario["email"]],
                "subject": "Redefinição de senha 💍",
                "html": f"""
                    <div
                        style="
                            font-family: Arial, sans-serif;
                            max-width: 600px;
                            margin: 0 auto;
                            color: #334155;
                        "
                    >

                        <div
                            style="
                                text-align: center;
                                padding: 30px 0;
                            "
                        >
                            <div style="font-size: 42px;">
                                💍
                            </div>

                            <h2
                                style="
                                    margin-bottom: 8px;
                                    color: #1e293b;
                                "
                            >
                                Redefinição de senha
                            </h2>
                        </div>


                        <p>
                            Olá, {usuario["nome"]}!
                        </p>

                        <p>
                            Recebemos uma solicitação para
                            redefinir a senha da sua conta.
                        </p>

                        <p
                            style="
                                text-align: center;
                                margin: 32px 0;
                            "
                        >
                            <a
                                href="{link_recuperacao}"
                                style="
                                    display: inline-block;
                                    background: #f43f5e;
                                    color: white;
                                    text-decoration: none;
                                    padding: 14px 24px;
                                    border-radius: 12px;
                                    font-weight: bold;
                                "
                            >
                                Criar nova senha
                            </a>
                        </p>

                        <p
                            style="
                                font-size: 13px;
                                color: #64748b;
                            "
                        >
                            Este link é válido por 30 minutos.
                        </p>

                        <p
                            style="
                                font-size: 13px;
                                color: #64748b;
                            "
                        >
                            Se você não solicitou a alteração
                            da senha, ignore este e-mail.
                        </p>

                    </div>
                """
            })

        except Exception as erro:

            # Não vamos mostrar detalhes técnicos
            # para o usuário.

            print(
                "ERRO AO ENVIAR RECUPERAÇÃO:",
                erro
            )


    flash(
        "Se existir uma conta cadastrada com este e-mail, enviaremos as instruções para redefinição da senha.",
        "sucesso"
    )

    return redirect(
        url_for("esqueci_senha")
    )

# ==========================================================
# CADASTRO
# ==========================================================

@app.route(
    "/cadastro",
    methods=["GET", "POST"]
)
def cadastro():
    if request.method == "GET":
        if usuario_logado():
            return redirect(
                url_for("dashboard")
            )

        return render_template(
            "cadastro.html"
        )

    nome = request.form.get(
        "nome",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    senha = request.form.get(
        "senha",
        ""
    )

    if (
        not nome
        or not email
        or not senha
    ):
        flash(
            "Preencha todos os campos obrigatórios.",
            "erro"
        )

        return redirect(
            url_for("cadastro")
        )

    if len(senha) < 6:
        flash(
            "A senha precisa ter pelo menos 6 caracteres.",
            "erro"
        )

        return redirect(
            url_for("cadastro")
        )

    conn = get_db_connection()

    try:
        # ==================================================
        # VERIFICA SE O E-MAIL JÁ ESTÁ CADASTRADO
        # ==================================================

        usuario_existente = conn.execute("""
            SELECT id
            FROM usuarios
            WHERE LOWER(email) = LOWER(?)
        """, (
            email,
        )).fetchone()

        if usuario_existente:
            conn.rollback()

            flash(
                "Já existe uma conta com esse e-mail.",
                "erro"
            )

            return redirect(
                url_for("cadastro")
            )

        # ==================================================
        # CRIA O USUÁRIO E RETORNA O ID
        # ==================================================

        senha_hash = generate_password_hash(
            senha
        )

        resultado = conn.execute("""
            INSERT INTO usuarios (
                nome,
                email,
                senha
            )
            VALUES (?, ?, ?)
            RETURNING id
        """, (
            nome,
            email,
            senha_hash
        ))

        usuario_id = resultado.fetchone()["id"]

        # ==================================================
        # CRIA O PERFIL INICIAL DO CASAMENTO
        # ==================================================

        conn.execute("""
            INSERT INTO casamentos (
                usuario_id,
                nome_pessoa_1
            )
            VALUES (?, ?)
        """, (
            usuario_id,
            nome
        ))

        # ==================================================
        # CRIA AS CATEGORIAS PADRÃO
        # ==================================================

        for categoria in CATEGORIAS_PADRAO_FORNECEDOR:
            conn.execute("""
                INSERT INTO categorias_fornecedor (
                    usuario_id,
                    nome
                )
                VALUES (?, ?)
                ON CONFLICT (usuario_id, nome)
                DO NOTHING
            """, (
                usuario_id,
                categoria
            ))

        conn.commit()

    except Exception as erro:
        conn.rollback()

        print(
            "ERRO NO CADASTRO:",
            erro
        )

        flash(
            "Não foi possível criar a conta.",
            "erro"
        )

        return redirect(
            url_for("cadastro")
        )

    finally:
        conn.close()

    # ==================================================
    # LOGIN AUTOMÁTICO APÓS O CADASTRO
    # ==================================================

    session.clear()
    session["usuario_id"] = usuario_id
    session["usuario_nome"] = nome

    return redirect(
        url_for("onboarding")
    )

# ==========================================================
# LOGIN
# ==========================================================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():

    if request.method == "GET":

        if usuario_logado():
            return redirect(
                url_for("dashboard")
            )

        return render_template(
            "login.html"
        )

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    senha = request.form.get(
        "senha",
        ""
    )

    conn = get_db_connection()

    usuario = conn.execute("""
        SELECT
            id,
            nome,
            email,
            senha
        FROM usuarios
        WHERE LOWER(email) = LOWER(?)
    """, (
        email,
    )).fetchone()

    if not usuario:

        conn.close()

        flash(
            "E-mail ou senha inválidos.",
            "erro"
        )

        return redirect(
            url_for("login")
        )

    senha_salva = (
        usuario["senha"]
        or ""
    )

    senha_valida = False

    try:

        senha_valida = check_password_hash(
            senha_salva,
            senha
        )

    except ValueError:

        senha_valida = False

    # Compatibilidade temporária
    # com senhas antigas em texto puro.

    conn.close()

    if not senha_valida:

        flash(
            "E-mail ou senha inválidos.",
            "erro"
        )

        return redirect(
            url_for("login")
        )

    session.clear()

    session["usuario_id"] = (
        usuario["id"]
    )

    session["usuario_nome"] = (
        usuario["nome"]
    )

    return redirect(
        url_for("dashboard")
    )

# ==========================================================
# LOGOUT
# ==========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )

# ==========================================================
# DASHBOARD
# ==========================================================

@app.route("/dashboard")
def dashboard():

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    usuario_id = (
        session["usuario_id"]
    )

    conn = get_db_connection()

    usuario = conn.execute("""
        SELECT *
        FROM usuarios
        WHERE id = ?
    """, (
        usuario_id,
    )).fetchone()

    casamento = conn.execute("""
        SELECT *
        FROM casamentos
        WHERE usuario_id = ?
    """, (
        usuario_id,
    )).fetchone()

    fornecedores = conn.execute("""
        SELECT *
        FROM fornecedores
        WHERE usuario_id = ?
        ORDER BY nome
    """, (
        usuario_id,
    )).fetchall()

    tarefas = conn.execute("""
        SELECT *
        FROM tarefas
        WHERE usuario_id = ?
        ORDER BY
            concluido ASC,
            id DESC
    """, (
        usuario_id,
    )).fetchall()

    convidados = conn.execute("""
        SELECT *
        FROM convidados
        WHERE usuario_id = ?
        ORDER BY nome
    """, (
        usuario_id,
    )).fetchall()

    conn.close()

    # --------------------------------------------------
    # CASAMENTO
    # --------------------------------------------------

    data_casamento = (
        casamento["data_casamento"]
        if casamento
        else None
    )

    # --------------------------------------------------
    # DIAS RESTANTES
    # --------------------------------------------------

    dias_restantes = None

    if data_casamento:

        try:

            data_casamento_obj = datetime.strptime(
                data_casamento,
                "%Y-%m-%d"
            ).date()

            dias_restantes = (
                data_casamento_obj
                -
                date.today()
            ).days

        except ValueError:

            dias_restantes = None

    foto_casal = (
        casamento["foto_capa"]
        if casamento
        else None
    )

    nome_pessoa_1 = (
        casamento["nome_pessoa_1"]
        if casamento
        else usuario["nome"]
    )

    nome_pessoa_2 = (
        casamento["nome_pessoa_2"]
        if casamento
        else ""
    )

    local_casamento = (
        casamento["local_casamento"]
        if casamento
        else ""
    )

    cidade = (
        casamento["cidade"]
        if casamento
        else ""
    )

    estado = (
        casamento["estado"]
        if casamento
        else ""
    )

    orcamento_planejado = (
        float(
            casamento[
                "orcamento_planejado"
            ]
            or 0
        )
        if casamento
        else 0
    )

    convidados_estimados = (
        int(
            casamento[
                "convidados_estimados"
            ]
            or 0
        )
        if casamento
        else 0
    )

    # --------------------------------------------------
    # FINANCEIRO
    # --------------------------------------------------

    orcamento_total = sum(
        float(
            fornecedor["valor"]
            or 0
        )
        for fornecedor
        in fornecedores
    )

    valor_pago = sum(
        float(
            fornecedor["valor_pago"]
            or 0
        )
        for fornecedor
        in fornecedores
    )

    valor_restante = max(
        orcamento_total
        -
        valor_pago,
        0
    )

    saldo_orcamento = (
        orcamento_planejado
        -
        orcamento_total
    )

    # --------------------------------------------------
    # CHECKLIST
    # --------------------------------------------------

    total_tarefas = len(
        tarefas
    )

    tarefas_concluidas = sum(
        1
        for tarefa
        in tarefas
        if tarefa["concluido"]
    )

    percentual_tarefas = (
        round(
            (
                tarefas_concluidas
                /
                total_tarefas
            )
            * 100
        )
        if total_tarefas
        else 0
    )

    # --------------------------------------------------
    # CONVIDADOS
    # --------------------------------------------------

    total_convidados = sum(
        1
        +
        int(
            convidado["acompanhantes"]
            or 0
        )
        for convidado
        in convidados
    )

    convidados_confirmados = sum(
        (
            1
            +
            int(
                convidado["acompanhantes"]
                or 0
            )
        )
        for convidado
        in convidados
        if (
            convidado[
                "status_confirmacao"
            ]
            ==
            "Confirmado"
        )
    )

    convidados_recusados = sum(
        (
            1
            +
            int(
                convidado["acompanhantes"]
                or 0
            )
        )
        for convidado
        in convidados
        if (
            convidado[
                "status_confirmacao"
            ]
            in (
                "Não irá",
                "Recusado"
            )
        )
    )

    convidados_pendentes = (
        total_convidados
        -
        convidados_confirmados
        -
        convidados_recusados
    )

    percentual_confirmados = (
        round(
            (
                convidados_confirmados
                /
                total_convidados
            )
            * 100
        )
        if total_convidados
        else 0
    )

    return render_template(
        "dashboard.html",

        usuario=usuario,

        usuario_nome=session.get(
            "usuario_nome",
            ""
        ),

        casamento=casamento,

        data_casamento=data_casamento,

        dias_restantes=dias_restantes,

        foto_casal=foto_casal,

        nome_pessoa_1=nome_pessoa_1,
        nome_pessoa_2=nome_pessoa_2,

        local_casamento=local_casamento,
        cidade=cidade,
        estado=estado,

        orcamento_planejado=orcamento_planejado,

        convidados_estimados=convidados_estimados,

        fornecedores=fornecedores,
        total_fornecedores=len(fornecedores),
        orcamento_total=orcamento_total,

        valor_pago=valor_pago,

        valor_restante=valor_restante,

        saldo_orcamento=saldo_orcamento,

        tarefas=tarefas,

        total_tarefas=total_tarefas,

        tarefas_concluidas=tarefas_concluidas,

        percentual_tarefas=percentual_tarefas,

        convidados=convidados,

        total_convidados=total_convidados,

        convidados_confirmados=convidados_confirmados,

        convidados_recusados=convidados_recusados,

        convidados_pendentes=convidados_pendentes,

        percentual_confirmados=percentual_confirmados
    )

# ==========================================================
# PERFIL DO CASAMENTO
# ==========================================================

@app.route("/perfil-casamento")
def perfil_casamento():

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    casamento = conn.execute("""
        SELECT *
        FROM casamentos
        WHERE usuario_id = ?
    """, (
        session["usuario_id"],
    )).fetchone()

    conn.close()

    if not casamento:

        flash(
            "Não foi possível localizar o perfil do casamento.",
            "erro"
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "perfil_casamento.html",

        casamento=casamento,

        usuario_nome=session.get(
            "usuario_nome",
            ""
        )
    )

@app.route(
    "/salvar-perfil-casamento",
    methods=["POST"]
)
def salvar_perfil_casamento():

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    nome_pessoa_1 = request.form.get(
        "nome_pessoa_1",
        ""
    ).strip()

    nome_pessoa_2 = request.form.get(
        "nome_pessoa_2",
        ""
    ).strip()

    data_casamento = request.form.get(
        "data_casamento",
        ""
    ).strip()

    local_casamento = request.form.get(
        "local_casamento",
        ""
    ).strip()

    cidade = request.form.get(
        "cidade",
        ""
    ).strip()

    estado = request.form.get(
        "estado",
        ""
    ).strip().upper()

    orcamento = request.form.get(
        "orcamento_planejado",
        "0"
    )

    convidados = request.form.get(
        "convidados_estimados",
        "0"
    )

    try:

        orcamento = converter_valor_brl(
            orcamento
        )

        if orcamento < 0:
            raise ValueError

    except ValueError:

        flash(
            "Informe um orçamento válido.",
            "erro"
        )

        return redirect(
            url_for(
                "perfil_casamento"
            )
        )

    try:

        convidados = int(
            convidados
            or 0
        )

        if convidados < 0:
            convidados = 0

    except ValueError:

        convidados = 0

    if data_casamento:

        try:

            datetime.strptime(
                data_casamento,
                "%Y-%m-%d"
            )

        except ValueError:

            flash(
                "Informe uma data válida.",
                "erro"
            )

            return redirect(
                url_for(
                    "perfil_casamento"
                )
            )

    conn = get_db_connection()

    conn.execute("""
        UPDATE casamentos
        SET
            nome_pessoa_1 = ?,
            nome_pessoa_2 = ?,
            data_casamento = ?,
            local_casamento = ?,
            cidade = ?,
            estado = ?,
            orcamento_planejado = ?,
            convidados_estimados = ?,
            atualizado_em = CURRENT_TIMESTAMP
        WHERE usuario_id = ?
    """, (
        nome_pessoa_1,
        nome_pessoa_2,
        data_casamento or None,
        local_casamento,
        cidade,
        estado,
        orcamento,
        convidados,
        session["usuario_id"]
    ))

    conn.commit()
    conn.close()

    flash(
        "Perfil do casamento atualizado com sucesso!",
        "sucesso"
    )

    return redirect(
        url_for(
            "perfil_casamento"
        )
    )

# ==========================================================
# DATA DO CASAMENTO
# ==========================================================

@app.route(
    "/salvar-data-casamento",
    methods=["POST"]
)
def salvar_data_casamento():

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    data_casamento = request.form.get(
        "data_casamento",
        ""
    ).strip()

    if data_casamento:

        try:

            datetime.strptime(
                data_casamento,
                "%Y-%m-%d"
            )

        except ValueError:

            flash(
                "Informe uma data válida.",
                "erro"
            )

            return redirect(
                url_for("dashboard")
            )

    conn = get_db_connection()

    conn.execute("""
        UPDATE casamentos
        SET
            data_casamento = ?,
            atualizado_em = CURRENT_TIMESTAMP
        WHERE usuario_id = ?
    """, (
        data_casamento or None,
        session["usuario_id"]
    ))

    conn.commit()
    conn.close()

    flash(
        "Data do casamento atualizada!",
        "sucesso"
    )

    return redirect(
        url_for("dashboard")
    )

@app.route(
    "/upload-foto-casal",
    methods=["POST"]
)
def upload_foto_casal():

    if not usuario_logado():

        return redirect(
            url_for("login")
        )

    arquivo = request.files.get(
        "foto_casal"
    )

    if not arquivo or not arquivo.filename:

        flash(
            "Selecione uma imagem.",
            "erro"
        )

        return redirect(
            url_for("dashboard")
        )

    if not arquivo_permitido(
        arquivo.filename
    ):

        flash(
            "Formato de imagem não permitido.",
            "erro"
        )

        return redirect(
            url_for("dashboard")
        )

    nome_original = secure_filename(
        arquivo.filename
    )

    extensao = (
        nome_original
        .rsplit(".", 1)[1]
        .lower()
    )

    nome_arquivo = (
        f"{session['usuario_id']}_"
        f"{uuid4().hex}."
        f"{extensao}"
    )

    caminho = (
        Path(app.config["UPLOAD_FOLDER"])
        /
        nome_arquivo
    )

    arquivo.save(
        caminho
    )

    conn = get_db_connection()

    conn.execute("""
        UPDATE casamentos
        SET foto_capa = ?, atualizado_em = CURRENT_TIMESTAMP
        WHERE usuario_id = ?
    """, (
        nome_arquivo,
        session["usuario_id"]
    ))

    conn.commit()
    conn.close()

    flash(
        "Foto atualizada com sucesso!",
        "sucesso"
    )

    return redirect(
        url_for("dashboard")
    )

@app.route("/checklist")
def checklist():

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    tarefas = conn.execute("""
        SELECT *
        FROM tarefas
        WHERE usuario_id = ?
        ORDER BY
            concluido ASC,
            id DESC
    """, (
        session["usuario_id"],
    )).fetchall()

    conn.close()

    total = len(
        tarefas
    )

    concluidas = sum(
        1
        for tarefa
        in tarefas
        if tarefa["concluido"]
    )

    pendentes = (
        total
        -
        concluidas
    )

    percentual = (
        round(
            (
                concluidas
                /
                total
            )
            * 100
        )
        if total > 0
        else 0
    )

    return render_template(
        "checklist.html",

        tarefas=tarefas,

        total=total,

        concluidas=concluidas,

        pendentes=pendentes,

        percentual=percentual,

        usuario_nome=session.get(
            "usuario_nome",
            ""
        )
    )

@app.route(
    "/add-tarefa",
    methods=["POST"]
)
def add_tarefa():

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    titulo = request.form.get(
        "titulo",
        ""
    ).strip()

    categoria = request.form.get(
        "categoria",
        ""
    ).strip()

    if not titulo:

        flash(
            "Informe o título da tarefa.",
            "erro"
        )

        return redirect(
            url_for("checklist")
        )

    conn = get_db_connection()

    try:

        conn.execute("""
            INSERT INTO tarefas (
                usuario_id,
                titulo,
                categoria,
                concluido
            )
            VALUES (?, ?, ?, 0)
        """, (
            session["usuario_id"],
            titulo,
            categoria
        ))

        conn.commit()

    except Exception as erro:

        conn.rollback()

        print(
            "ERRO AO ADICIONAR TAREFA:",
            erro
        )

        flash(
            "Não foi possível adicionar a tarefa.",
            "erro"
        )

    finally:

        conn.close()

    return redirect(
        url_for("checklist")
    )

@app.route("/toggle-tarefa/<int:id>", methods=["POST"])
def toggle_tarefa(id):
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    tarefa = conn.execute("""
        SELECT *
        FROM tarefas
        WHERE id = ?
          AND usuario_id = ?
    """, (
        id,
        session["usuario_id"]
    )).fetchone()

    if not tarefa:
        conn.close()

        flash("Tarefa não encontrada.", "erro")
        return redirect(url_for("checklist"))

    novo_status = 0 if tarefa["concluido"] == 1 else 1

    conn.execute("""
        UPDATE tarefas
        SET concluido = ?
        WHERE id = ?
          AND usuario_id = ?
    """, (
        novo_status,
        id,
        session["usuario_id"]
    ))

    conn.commit()
    conn.close()

    return redirect(url_for("checklist"))

@app.route("/excluir-tarefa/<int:id>", methods=["POST"])
def excluir_tarefa(id):
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    conn.execute("""
        DELETE FROM tarefas
        WHERE id = ?
          AND usuario_id = ?
    """, (
        id,
        session["usuario_id"]
    ))

    conn.commit()
    conn.close()

    flash("Tarefa excluída.", "sucesso")

    return redirect(url_for("checklist"))

# =========================================================
# CONVIDADOS
# =========================================================

@app.route("/convidados")
def convidados():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    convidados = conn.execute("""
        SELECT *
        FROM convidados
        WHERE usuario_id = ?
        ORDER BY nome ASC
    """, (session["usuario_id"],)).fetchall()

    conn.close()

    # Quantidade de pessoas
    # Cada convidado principal conta como 1
    # + a quantidade de acompanhantes
    total_convidados = sum(
        1 + (convidado["acompanhantes"] or 0)
        for convidado in convidados
    )

    confirmados = sum(
        1 + (convidado["acompanhantes"] or 0)
        for convidado in convidados
        if convidado["status_confirmacao"] == "Confirmado"
    )

    pendentes = sum(
        1 + (convidado["acompanhantes"] or 0)
        for convidado in convidados
        if convidado["status_confirmacao"] == "Pendente"
    )

    nao_irao = sum(
        1 + (convidado["acompanhantes"] or 0)
        for convidado in convidados
        if convidado["status_confirmacao"] == "Não irá"
    )

    return render_template(
        "convidados.html",
        convidados=convidados,
        total_convidados=total_convidados,
        confirmados=confirmados,
        pendentes=pendentes,
        nao_irao=nao_irao
    )

@app.route("/add-convidado", methods=["POST"])
def add_convidado():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    nome = request.form.get("nome", "").strip()
    telefone = request.form.get("telefone", "").strip()
    acompanhantes = request.form.get("acompanhantes", "0")
    status = request.form.get("status_confirmacao", "Pendente")
    observacao = request.form.get("observacao", "").strip()

    if not nome:
        flash("Informe o nome do convidado.", "erro")
        return redirect(url_for("convidados"))

    try:
        acompanhantes = int(acompanhantes)

        if acompanhantes < 0:
            acompanhantes = 0

    except (ValueError, TypeError):
        acompanhantes = 0

    status_validos = [
        "Pendente",
        "Confirmado",
        "Não irá"
    ]

    if status not in status_validos:
        status = "Pendente"

    conn = get_db_connection()

    conn.execute("""
        INSERT INTO convidados (
            usuario_id,
            nome,
            telefone,
            acompanhantes,
            status_confirmacao,
            observacao
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        session["usuario_id"],
        nome,
        telefone,
        acompanhantes,
        status,
        observacao
    ))

    conn.commit()
    conn.close()

    flash("Convidado adicionado com sucesso!", "sucesso")

    return redirect(url_for("convidados"))

@app.route("/update-convidado/<int:id>", methods=["POST"])
def update_convidado(id):
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    nome = request.form.get("nome", "").strip()
    telefone = request.form.get("telefone", "").strip()
    acompanhantes = request.form.get("acompanhantes", "0")
    status = request.form.get("status_confirmacao", "Pendente")
    observacao = request.form.get("observacao", "").strip()

    if not nome:
        flash("O nome do convidado é obrigatório.", "erro")
        return redirect(url_for("convidados"))

    try:
        acompanhantes = int(acompanhantes)

        if acompanhantes < 0:
            acompanhantes = 0

    except (ValueError, TypeError):
        acompanhantes = 0

    status_validos = [
        "Pendente",
        "Confirmado",
        "Não irá"
    ]

    if status not in status_validos:
        status = "Pendente"

    conn = get_db_connection()

    convidado = conn.execute("""
        SELECT id
        FROM convidados
        WHERE id = ?
          AND usuario_id = ?
    """, (
        id,
        session["usuario_id"]
    )).fetchone()

    if not convidado:
        conn.close()

        flash("Convidado não encontrado.", "erro")
        return redirect(url_for("convidados"))

    conn.execute("""
        UPDATE convidados
        SET nome = ?,
            telefone = ?,
            acompanhantes = ?,
            status_confirmacao = ?,
            observacao = ?
        WHERE id = ?
          AND usuario_id = ?
    """, (
        nome,
        telefone,
        acompanhantes,
        status,
        observacao,
        id,
        session["usuario_id"]
    ))

    conn.commit()
    conn.close()

    flash("Convidado atualizado com sucesso!", "sucesso")

    return redirect(url_for("convidados"))

@app.route("/delete-convidado/<int:id>", methods=["POST"])
def delete_convidado(id):
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    conn.execute("""
        DELETE FROM convidados
        WHERE id = ?
          AND usuario_id = ?
    """, (
        id,
        session["usuario_id"]
    ))

    conn.commit()
    conn.close()

    flash("Convidado excluído.", "sucesso")

    return redirect(url_for("convidados"))

@app.route("/fornecedores")
def fornecedores():

    if not usuario_logado():
        return redirect(url_for("login"))

    usuario_id = session["usuario_id"]

    conn = get_db_connection()

    categorias = conn.execute("""
        SELECT
            id,
            nome
        FROM categorias_fornecedor
        WHERE usuario_id = ?
        ORDER BY nome
    """, (
        usuario_id,
    )).fetchall()

    lista_fornecedores = conn.execute("""
        SELECT
            f.id,
            f.nome,
            f.whatsapp,
            f.valor,
            f.valor_pago,
            f.categoria_id,
            c.nome AS categoria_nome
        FROM fornecedores f

        LEFT JOIN categorias_fornecedor c
            ON c.id = f.categoria_id

        WHERE f.usuario_id = ?

        ORDER BY f.nome ASC
    """, (
        usuario_id,
    )).fetchall()
    
    print("=== FORNECEDORES RECEBIDOS PELA ROTA ===")
    print("USUARIO_ID:", usuario_id)

    for fornecedor in lista_fornecedores:
        print(
        fornecedor["id"],
        fornecedor["nome"],
        fornecedor["valor"],
        fornecedor["valor_pago"]
    )
    print("FORNECEDORES DA ROTA:", lista_fornecedores)
    print("========================================")

    total_contratado = sum(
        float(f["valor"] or 0)
        for f in lista_fornecedores
    )

    total_pago = sum(
        float(f["valor_pago"] or 0)
        for f in lista_fornecedores
    )

    total_pendente = (
        total_contratado
        - total_pago
    )

    total_fornecedores = len(
        lista_fornecedores
    )

    conn.close()

    return render_template(
        "fornecedores.html",
        fornecedores=lista_fornecedores,
        categorias=categorias,
        total_contratado=total_contratado,
        total_pago=total_pago,
        total_pendente=total_pendente,
        total_fornecedores=total_fornecedores,
        usuario_nome=session.get(
            "usuario_nome",
            ""
        )
    )

@app.route(
    "/add-fornecedor",
    methods=["POST"]
)
def add_fornecedor():
    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    usuario_id = session["usuario_id"]

    nome = request.form.get(
        "nome",
        ""
    ).strip()

    categoria_id = request.form.get(
        "categoria_id",
        ""
    ).strip()

    whatsapp = request.form.get(
        "whatsapp",
        ""
    ).strip()

    valor = request.form.get(
        "valor",
        "0"
    )

    valor_pago = request.form.get(
        "valor_pago",
        "0"
    )

    # ======================================================
    # VALIDAÇÃO NOME
    # ======================================================

    if not nome:
        flash(
            "Informe o nome do fornecedor.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    # ======================================================
    # VALIDAÇÃO CATEGORIA
    # ======================================================

    if not categoria_id:
        flash(
            "Selecione uma categoria.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    try:
        categoria_id = int(
            categoria_id
        )

    except ValueError:
        flash(
            "Categoria inválida.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    # ======================================================
    # VALIDAÇÃO VALOR CONTRATADO
    # ======================================================

    try:
        valor = converter_valor_brl(
            valor
        )

    except ValueError:
        flash(
            "Informe um valor contratado válido.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    # ======================================================
    # VALIDAÇÃO VALOR PAGO
    # ======================================================

    try:
        valor_pago = converter_valor_brl(
            valor_pago
        )

    except ValueError:
        flash(
            "Informe um valor pago válido.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    if valor < 0:
        flash(
            "O valor contratado não pode ser negativo.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    if valor_pago < 0:
        flash(
            "O valor pago não pode ser negativo.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    if (
        valor > 0
        and valor_pago > valor
    ):
        flash(
            "O valor pago não pode ser maior que o valor contratado.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    conn = get_db_connection()

    try:
        # ==================================================
        # CONFIRMA QUE A CATEGORIA É DO USUÁRIO
        # ==================================================

        categoria = conn.execute("""
            SELECT id
            FROM categorias_fornecedor
            WHERE id = ?
              AND usuario_id = ?
        """, (
            categoria_id,
            usuario_id
        )).fetchone()

        if not categoria:
            flash(
                "A categoria selecionada não foi encontrada.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

        # ==================================================
        # CADASTRA FORNECEDOR
        # ==================================================

        resultado = conn.execute("""
            INSERT INTO fornecedores (
                usuario_id,
                nome,
                categoria_id,
                whatsapp,
                valor,
                valor_pago
            )
            VALUES (?, ?, ?, ?, ?, ?)
            RETURNING id
        """, (
            usuario_id,
            nome,
            categoria_id,
            whatsapp,
            valor,
            valor_pago
        ))

        fornecedor_id = resultado.fetchone()["id"]

        # ==================================================
        # CRIA HISTÓRICO DO PAGAMENTO INICIAL
        # ==================================================

        if valor_pago > 0:
            conn.execute("""
                INSERT INTO historico_pagamento (
                    fornecedor_id,
                    valor,
                    data_pagamento
                )
                VALUES (?, ?, ?)
            """, (
                fornecedor_id,
                valor_pago,
                date.today().isoformat()
            ))

        conn.commit()

    except Exception:
        conn.rollback()

        flash(
            "Não foi possível cadastrar o fornecedor.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    finally:
        conn.close()

    flash(
        "Fornecedor adicionado com sucesso!",
        "sucesso"
    )

    return redirect(
        url_for("fornecedores")
    )

@app.route(
    "/editar-fornecedor/<int:id>",
    methods=["POST"]
)
def editar_fornecedor(id):
    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    nome = request.form.get(
        "nome",
        ""
    ).strip()

    categoria_id = request.form.get(
        "categoria_id",
        ""
    ).strip()

    whatsapp = request.form.get(
        "whatsapp",
        ""
    ).strip()

    valor = request.form.get(
        "valor",
        ""
    ).strip()

    if not nome:
        flash(
            "Informe o nome do fornecedor.",
            "erro"
        )

        return redirect(
            url_for(
                "historico_pagamentos",
                id=id
            )
        )

    try:
        categoria_id = int(
            categoria_id
        )

    except ValueError:
        flash(
            "Selecione uma categoria válida.",
            "erro"
        )

        return redirect(
            url_for(
                "historico_pagamentos",
                id=id
            )
        )

    try:
        valor = converter_valor_brl(
            valor
        )

    except ValueError:
        flash(
            "Informe um valor contratado válido.",
            "erro"
        )

        return redirect(
            url_for(
                "historico_pagamentos",
                id=id
            )
        )

    if valor < 0:
        flash(
            "O valor contratado não pode ser negativo.",
            "erro"
        )

        return redirect(
            url_for(
                "historico_pagamentos",
                id=id
            )
        )

    conn = get_db_connection()

    try:
        # ==================================================
        # BUSCA E BLOQUEIA O FORNECEDOR DURANTE A EDIÇÃO
        # ==================================================

        fornecedor = conn.execute("""
            SELECT
                id,
                valor_pago
            FROM fornecedores
            WHERE id = ?
              AND usuario_id = ?
            FOR UPDATE
        """, (
            id,
            session["usuario_id"]
        )).fetchone()

        if not fornecedor:
            conn.rollback()

            flash(
                "Fornecedor não encontrado.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

        # ==================================================
        # CONFIRMA QUE A CATEGORIA PERTENCE AO USUÁRIO
        # ==================================================

        categoria = conn.execute("""
            SELECT id
            FROM categorias_fornecedor
            WHERE id = ?
              AND usuario_id = ?
        """, (
            categoria_id,
            session["usuario_id"]
        )).fetchone()

        if not categoria:
            conn.rollback()

            flash(
                "Categoria inválida.",
                "erro"
            )

            return redirect(
                url_for(
                    "historico_pagamentos",
                    id=id
                )
            )

        valor_pago = float(
            fornecedor["valor_pago"]
            or 0
        )

        # ==================================================
        # NÃO PERMITE CONTRATADO MENOR QUE O JÁ PAGO
        # ==================================================

        if valor < valor_pago:
            conn.rollback()

            flash(
                "O valor contratado não pode ser menor "
                "que o valor já pago.",
                "erro"
            )

            return redirect(
                url_for(
                    "historico_pagamentos",
                    id=id
                )
            )

        # ==================================================
        # ATUALIZA FORNECEDOR
        # ==================================================

        conn.execute("""
            UPDATE fornecedores
            SET
                nome = ?,
                categoria_id = ?,
                whatsapp = ?,
                valor = ?
            WHERE id = ?
              AND usuario_id = ?
        """, (
            nome,
            categoria_id,
            whatsapp,
            valor,
            id,
            session["usuario_id"]
        ))

        conn.commit()

    except Exception as erro:
        conn.rollback()

        print(
            "ERRO AO EDITAR FORNECEDOR:",
            erro
        )

        flash(
            "Não foi possível editar o fornecedor.",
            "erro"
        )

        return redirect(
            url_for(
                "historico_pagamentos",
                id=id
            )
        )

    finally:
        conn.close()

    flash(
        "Fornecedor atualizado com sucesso!",
        "sucesso"
    )

    return redirect(
        url_for(
            "historico_pagamentos",
            id=id
        )
    )

@app.route(
    "/delete-fornecedor/<int:id>",
    methods=["POST"]
)
def delete_fornecedor(id):
    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    try:
        # ==================================================
        # VALIDA E BLOQUEIA O FORNECEDOR
        # ==================================================

        fornecedor = conn.execute("""
            SELECT
                id,
                nome
            FROM fornecedores
            WHERE id = ?
              AND usuario_id = ?
            FOR UPDATE
        """, (
            id,
            session["usuario_id"]
        )).fetchone()

        if not fornecedor:
            conn.rollback()

            flash(
                "Fornecedor não encontrado.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

        # ==================================================
        # EXCLUI PAGAMENTOS PLANEJADOS
        # ==================================================

        conn.execute("""
            DELETE FROM pagamentos_planejados
            WHERE fornecedor_id = ?
        """, (
            id,
        ))

        # ==================================================
        # EXCLUI HISTÓRICO DE PAGAMENTOS
        # ==================================================

        conn.execute("""
            DELETE FROM historico_pagamento
            WHERE fornecedor_id = ?
        """, (
            id,
        ))

        # ==================================================
        # EXCLUI FORNECEDOR
        # ==================================================

        conn.execute("""
            DELETE FROM fornecedores
            WHERE id = ?
              AND usuario_id = ?
        """, (
            id,
            session["usuario_id"]
        ))

        conn.commit()

    except Exception as erro:
        conn.rollback()

        print(
            "ERRO AO EXCLUIR FORNECEDOR:",
            erro
        )

        flash(
            "Não foi possível excluir o fornecedor.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    finally:
        conn.close()

    flash(
        "Fornecedor excluído com sucesso!",
        "sucesso"
    )

    return redirect(
        url_for("fornecedores")
    )

@app.route(
    "/acrescentar-pagamento/<int:id>",
    methods=["POST"]
)
def acrescentar_pagamento(id):
    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    valor_adicional = request.form.get(
        "valor_adicional",
        ""
    ).strip()

    if not valor_adicional:
        flash(
            "Informe o valor do pagamento.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    try:
        valor_adicional = converter_valor_brl(
            valor_adicional
        )

    except ValueError:
        flash(
            "Digite um valor válido. Ex.: 500,00",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    if valor_adicional <= 0:
        flash(
            "O pagamento precisa ser maior que zero.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    conn = get_db_connection()

    try:
        # ==================================================
        # BUSCA FORNECEDOR
        # ==================================================

        fornecedor = conn.execute("""
            SELECT
                id,
                nome,
                valor,
                valor_pago
            FROM fornecedores
            WHERE id = ?
              AND usuario_id = ?
            FOR UPDATE
        """, (
            id,
            session["usuario_id"]
        )).fetchone()

        if not fornecedor:
            conn.rollback()

            flash(
                "Fornecedor não encontrado.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

        valor_total = float(
            fornecedor["valor"] or 0
        )

        valor_pago_atual = float(
            fornecedor["valor_pago"] or 0
        )

        restante = (
            valor_total
            -
            valor_pago_atual
        )

        novo_valor_pago = (
            valor_pago_atual
            +
            valor_adicional
        )

        # ==================================================
        # IMPEDE PAGAMENTO ACIMA DO VALOR CONTRATADO
        # ==================================================

        if (
            valor_total > 0
            and novo_valor_pago > valor_total
        ):
            conn.rollback()

            flash(
                "O pagamento informado ultrapassa "
                "o valor restante. "
                f"Restante atual: "
                f"R$ {moeda_brl(restante)}.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

        # ==================================================
        # ATUALIZA TOTAL PAGO
        # ==================================================

        conn.execute("""
            UPDATE fornecedores
            SET valor_pago = ?
            WHERE id = ?
              AND usuario_id = ?
        """, (
            novo_valor_pago,
            id,
            session["usuario_id"]
        ))

        # ==================================================
        # REGISTRA NO HISTÓRICO
        # ==================================================

        conn.execute("""
            INSERT INTO historico_pagamento (
                fornecedor_id,
                valor,
                data_pagamento
            )
            VALUES (?, ?, ?)
        """, (
            id,
            valor_adicional,
            date.today().isoformat()
        ))

        conn.commit()

    except Exception as erro:
        conn.rollback()

        print(
            "ERRO AO REGISTRAR PAGAMENTO:",
            erro
        )

        flash(
            "Não foi possível registrar o pagamento.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    finally:
        conn.close()

    flash(
        "Pagamento registrado com sucesso!",
        "sucesso"
    )

    return redirect(
        url_for("fornecedores")
    )

@app.route(
    "/historico-pagamentos/<int:id>"
)
def historico_pagamentos(id):

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    fornecedor = conn.execute("""
        SELECT
            f.id,
            f.nome,
            f.whatsapp,
            f.valor,
            f.valor_pago,
            f.categoria_id,
            c.nome AS categoria_nome
        FROM fornecedores f

        LEFT JOIN categorias_fornecedor c
            ON c.id = f.categoria_id

        WHERE f.id = ?
          AND f.usuario_id = ?
    """, (
        id,
        session["usuario_id"]
    )).fetchone()

    if not fornecedor:

        conn.close()

        flash(
            "Fornecedor não encontrado.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    historico = conn.execute("""
        SELECT
            id,
            valor,
            data_pagamento
        FROM historico_pagamento
        WHERE fornecedor_id = ?
        ORDER BY
            data_pagamento DESC,
            id DESC
    """, (
        id,
    )).fetchall()

    categorias = conn.execute("""
        SELECT
            id,
            nome
        FROM categorias_fornecedor
        WHERE usuario_id = ?
        ORDER BY nome
    """, (
        session["usuario_id"],
    )).fetchall()

    pagamentos_planejados = conn.execute("""
        SELECT id, descricao, valor, data_prevista, status
        FROM pagamentos_planejados WHERE fornecedor_id = ?
        ORDER BY (data_prevista IS NULL OR data_prevista = ''), data_prevista, id
    """, (id,)).fetchall()
    conn.close()

    valor_total = float(
        fornecedor["valor"]
        or 0
    )

    valor_pago = float(
        fornecedor["valor_pago"]
        or 0
    )

    valor_restante = (
        valor_total
        -
        valor_pago
    )

    if valor_total > 0:
        percentual_pago = round(
            (valor_pago / valor_total) * 100
        )
    else:
        percentual_pago = 0

    return render_template(
        "historico_pagamentos.html",

        fornecedor=fornecedor,
        historico=historico,
        pagamentos_planejados=pagamentos_planejados,
        categorias=categorias,

        valor_restante=valor_restante,
        percentual_pago=percentual_pago,

        usuario_nome=session.get(
            "usuario_nome",
            ""
        )
    )

@app.route(
    "/adicionar-pagamento-planejado/<int:id>",
    methods=["POST"]
)
def adicionar_pagamento_planejado(id):

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    descricao = request.form.get(
        "descricao",
        ""
    ).strip()

    valor = request.form.get(
        "valor",
        ""
    ).strip()

    data_prevista = request.form.get(
        "data_prevista",
        ""
    ).strip()

    if not descricao:

        flash(
            "Informe uma descrição para o pagamento.",
            "erro"
        )

        return redirect(
            url_for(
                "historico_pagamentos",
                id=id
            )
        )

    try:

        valor = converter_valor_brl(
            valor
        )

    except ValueError:

        flash(
            "Informe um valor válido.",
            "erro"
        )

        return redirect(
            url_for(
                "historico_pagamentos",
                id=id
            )
        )

    if valor <= 0:

        flash(
            "O valor precisa ser maior que zero.",
            "erro"
        )

        return redirect(
            url_for(
                "historico_pagamentos",
                id=id
            )
        )

    if data_prevista:

        try:

            datetime.strptime(
                data_prevista,
                "%Y-%m-%d"
            )

        except ValueError:

            flash(
                "Informe uma data válida.",
                "erro"
            )

            return redirect(
                url_for(
                    "historico_pagamentos",
                    id=id
                )
            )

    conn = get_db_connection()

    try:

        fornecedor = conn.execute("""
            SELECT id
            FROM fornecedores
            WHERE id = ?
              AND usuario_id = ?
        """, (
            id,
            session["usuario_id"]
        )).fetchone()

        if not fornecedor:

            flash(
                "Fornecedor não encontrado.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

        conn.execute("""
            INSERT INTO pagamentos_planejados (
                fornecedor_id,
                descricao,
                valor,
                data_prevista,
                status
            )
            VALUES (?, ?, ?, ?, 'Pendente')
        """, (
            id,
            descricao,
            valor,
            data_prevista or None
        ))

        conn.commit()

    except Exception as erro:

        conn.rollback()

        print(
            "ERRO AO CRIAR PAGAMENTO PLANEJADO:",
            erro
        )

        flash(
            "Não foi possível criar o pagamento planejado.",
            "erro"
        )

        return redirect(
            url_for(
                "historico_pagamentos",
                id=id
            )
        )

    finally:

        conn.close()

    flash(
        "Pagamento planejado criado com sucesso!",
        "sucesso"
    )

    return redirect(
        url_for(
            "historico_pagamentos",
            id=id
        )
    )

# ==========================================================
# EDITAR PAGAMENTO PLANEJADO
# ==========================================================

@app.route(
    "/editar-pagamento-planejado/<int:id>",
    methods=["POST"]
)
def editar_pagamento_planejado(id):
    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    descricao = request.form.get(
        "descricao",
        ""
    ).strip()

    valor = request.form.get(
        "valor",
        ""
    ).strip()

    data_prevista = request.form.get(
        "data_prevista",
        ""
    ).strip()

    if not descricao:
        flash(
            "Informe uma descrição para o pagamento.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    try:
        valor = converter_valor_brl(
            valor
        )

    except ValueError:
        flash(
            "Informe um valor válido.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    if valor <= 0:
        flash(
            "O valor precisa ser maior que zero.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    if data_prevista:
        try:
            datetime.strptime(
                data_prevista,
                "%Y-%m-%d"
            )

        except ValueError:
            flash(
                "Informe uma data válida.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

    conn = get_db_connection()

    try:
        # ==================================================
        # BUSCA E BLOQUEIA O PAGAMENTO PLANEJADO
        # ==================================================

        pagamento = conn.execute("""
            SELECT
                pp.id,
                pp.fornecedor_id,
                pp.status
            FROM pagamentos_planejados pp

            JOIN fornecedores f
                ON f.id = pp.fornecedor_id

            WHERE pp.id = ?
              AND f.usuario_id = ?

            FOR UPDATE OF pp
        """, (
            id,
            session["usuario_id"]
        )).fetchone()

        if not pagamento:
            conn.rollback()

            flash(
                "Pagamento planejado não encontrado.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

        fornecedor_id = (
            pagamento["fornecedor_id"]
        )

        # ==================================================
        # PAGAMENTO JÁ REALIZADO NÃO PODE SER ALTERADO
        # ==================================================

        if pagamento["status"] == "Pago":
            conn.rollback()

            flash(
                "Um pagamento já registrado como pago "
                "não pode ser editado.",
                "erro"
            )

            return redirect(
                url_for(
                    "historico_pagamentos",
                    id=fornecedor_id
                )
            )

        # ==================================================
        # ATUALIZA PAGAMENTO PLANEJADO
        # ==================================================

        conn.execute("""
            UPDATE pagamentos_planejados
            SET
                descricao = ?,
                valor = ?,
                data_prevista = ?
            WHERE id = ?
        """, (
            descricao,
            valor,
            data_prevista or None,
            id
        ))

        conn.commit()

    except Exception as erro:
        conn.rollback()

        print(
            "ERRO AO EDITAR PAGAMENTO PLANEJADO:",
            erro
        )

        flash(
            "Não foi possível editar o pagamento planejado.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    finally:
        conn.close()

    flash(
        "Pagamento planejado atualizado!",
        "sucesso"
    )

    return redirect(
        url_for(
            "historico_pagamentos",
            id=fornecedor_id
        )
    )
# ==========================================================
# EXCLUIR PAGAMENTO PLANEJADO
# ==========================================================

@app.route(
    "/excluir-pagamento-planejado/<int:id>",
    methods=["POST"]
)
def excluir_pagamento_planejado(id):
    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    try:
        # ==================================================
        # BUSCA E BLOQUEIA O PAGAMENTO PLANEJADO
        # ==================================================

        pagamento = conn.execute("""
            SELECT
                pp.id,
                pp.fornecedor_id,
                pp.status
            FROM pagamentos_planejados pp

            JOIN fornecedores f
                ON f.id = pp.fornecedor_id

            WHERE pp.id = ?
              AND f.usuario_id = ?

            FOR UPDATE OF pp
        """, (
            id,
            session["usuario_id"]
        )).fetchone()

        if not pagamento:
            conn.rollback()

            flash(
                "Pagamento planejado não encontrado.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

        fornecedor_id = (
            pagamento["fornecedor_id"]
        )

        # ==================================================
        # PAGAMENTO JÁ REALIZADO NÃO PODE SER EXCLUÍDO
        # ==================================================

        if pagamento["status"] == "Pago":
            conn.rollback()

            flash(
                "Um pagamento já registrado como pago "
                "não pode ser excluído por aqui.",
                "erro"
            )

            return redirect(
                url_for(
                    "historico_pagamentos",
                    id=fornecedor_id
                )
            )

        # ==================================================
        # EXCLUI PAGAMENTO PLANEJADO
        # ==================================================

        conn.execute("""
            DELETE FROM pagamentos_planejados
            WHERE id = ?
        """, (
            id,
        ))

        conn.commit()

    except Exception as erro:
        conn.rollback()

        print(
            "ERRO AO EXCLUIR PAGAMENTO PLANEJADO:",
            erro
        )

        flash(
            "Não foi possível excluir o pagamento planejado.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    finally:
        conn.close()

    flash(
        "Pagamento planejado excluído.",
        "sucesso"
    )

    return redirect(
        url_for(
            "historico_pagamentos",
            id=fornecedor_id
        )
    )
# ==========================================================
# REGISTRAR PAGAMENTO PLANEJADO COMO PAGO
# ==========================================================

@app.route(
    "/registrar-planejado-como-pago/<int:id>",
    methods=["POST"]
)
def registrar_planejado_como_pago(id):
    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    data_pagamento = request.form.get(
        "data_pagamento",
        ""
    ).strip()

    if not data_pagamento:
        data_pagamento = date.today().isoformat()

    try:
        datetime.strptime(
            data_pagamento,
            "%Y-%m-%d"
        )

    except ValueError:
        flash(
            "Informe uma data de pagamento válida.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    conn = get_db_connection()

    try:
        # ==================================================
        # BUSCA O PAGAMENTO E BLOQUEIA O PLANEJAMENTO
        # E O FORNECEDOR DURANTE A TRANSAÇÃO
        # ==================================================

        pagamento = conn.execute("""
            SELECT
                pp.id,
                pp.fornecedor_id,
                pp.descricao,
                pp.valor,
                pp.status,

                f.nome AS fornecedor_nome,
                f.valor AS valor_contratado,
                f.valor_pago

            FROM pagamentos_planejados pp

            JOIN fornecedores f
                ON f.id = pp.fornecedor_id

            WHERE pp.id = ?
              AND f.usuario_id = ?

            FOR UPDATE OF pp, f
        """, (
            id,
            session["usuario_id"]
        )).fetchone()

        if not pagamento:
            conn.rollback()

            flash(
                "Pagamento planejado não encontrado.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

        fornecedor_id = pagamento["fornecedor_id"]

        # ==================================================
        # IMPEDE DUPLICIDADE
        # ==================================================

        if pagamento["status"] == "Pago":
            conn.rollback()

            flash(
                "Esse pagamento já foi registrado como pago.",
                "erro"
            )

            return redirect(
                url_for(
                    "historico_pagamentos",
                    id=fornecedor_id
                )
            )

        valor_pagamento = float(
            pagamento["valor"] or 0
        )

        valor_contratado = float(
            pagamento["valor_contratado"] or 0
        )

        valor_pago_atual = float(
            pagamento["valor_pago"] or 0
        )

        novo_valor_pago = (
            valor_pago_atual
            +
            valor_pagamento
        )

        # ==================================================
        # NÃO PERMITE PAGAR ACIMA DO CONTRATO
        # ==================================================

        if (
            valor_contratado > 0
            and novo_valor_pago > valor_contratado
        ):
            restante = max(
                valor_contratado - valor_pago_atual,
                0
            )

            conn.rollback()

            flash(
                "Esse pagamento ultrapassa o saldo "
                "restante do fornecedor. "
                f"Saldo atual: R$ {moeda_brl(restante)}.",
                "erro"
            )

            return redirect(
                url_for(
                    "historico_pagamentos",
                    id=fornecedor_id
                )
            )

        # ==================================================
        # 1. ATUALIZA TOTAL PAGO DO FORNECEDOR
        # ==================================================

        conn.execute("""
            UPDATE fornecedores
            SET valor_pago = ?
            WHERE id = ?
              AND usuario_id = ?
        """, (
            novo_valor_pago,
            fornecedor_id,
            session["usuario_id"]
        ))

        # ==================================================
        # 2. REGISTRA NO HISTÓRICO REAL
        # ==================================================

        conn.execute("""
            INSERT INTO historico_pagamento (
                fornecedor_id,
                valor,
                data_pagamento
            )
            VALUES (?, ?, ?)
        """, (
            fornecedor_id,
            valor_pagamento,
            data_pagamento
        ))

        # ==================================================
        # 3. MARCA O PLANEJAMENTO COMO PAGO
        # ==================================================

        conn.execute("""
            UPDATE pagamentos_planejados
            SET status = 'Pago'
            WHERE id = ?
        """, (
            id,
        ))

        conn.commit()

    except Exception as erro:
        conn.rollback()

        print(
            "ERRO AO REGISTRAR PLANEJADO COMO PAGO:",
            erro
        )

        flash(
            "Não foi possível registrar o pagamento.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    finally:
        conn.close()

    flash(
        "Pagamento registrado como pago com sucesso!",
        "sucesso"
    )

    return redirect(
        url_for(
            "historico_pagamentos",
            id=fornecedor_id
        )
    )
# ==========================================================
# CATEGORIAS DE FORNECEDORES
# ==========================================================

@app.route(
    "/adicionar-categoria-fornecedor",
    methods=["POST"]
)
def adicionar_categoria_fornecedor():

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    nome = request.form.get(
        "nome",
        ""
    ).strip()

    if not nome:

        flash(
            "Informe o nome da categoria.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    if len(nome) > 60:

        flash(
            "O nome da categoria deve ter no máximo 60 caracteres.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    conn = get_db_connection()

    try:

        categoria_existente = conn.execute("""
            SELECT id

            FROM categorias_fornecedor

            WHERE usuario_id = ?
              AND LOWER(nome) = LOWER(?)
        """, (
            session["usuario_id"],
            nome
        )).fetchone()

        if categoria_existente:

            flash(
                "Você já possui uma categoria com esse nome.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

        conn.execute("""
            INSERT INTO categorias_fornecedor (
                usuario_id,
                nome
            )

            VALUES (?, ?)
        """, (
            session["usuario_id"],
            nome
        ))

        conn.commit()

    except Exception as erro:

        conn.rollback()

        print(
            "ERRO AO CRIAR CATEGORIA:",
            erro
        )

        flash(
            "Não foi possível criar a categoria.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    finally:
        conn.close()

    flash(
        "Categoria criada com sucesso!",
        "sucesso"
    )

    return redirect(
        url_for("fornecedores")
    )

# ==========================================================
# EDITAR CATEGORIA
# ==========================================================

@app.route(
    "/editar-categoria-fornecedor/<int:id>",
    methods=["POST"]
)
def editar_categoria_fornecedor(id):

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    nome = request.form.get(
        "nome",
        ""
    ).strip()

    if not nome:

        flash(
            "Informe o nome da categoria.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    if len(nome) > 60:

        flash(
            "O nome da categoria deve ter no máximo 60 caracteres.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    conn = get_db_connection()

    try:

        categoria = conn.execute("""
            SELECT id

            FROM categorias_fornecedor

            WHERE id = ?
              AND usuario_id = ?
        """, (
            id,
            session["usuario_id"]
        )).fetchone()

        if not categoria:

            flash(
                "Categoria não encontrada.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

        outra_categoria = conn.execute("""
            SELECT id

            FROM categorias_fornecedor

            WHERE usuario_id = ?
              AND LOWER(nome) = LOWER(?)
              AND id != ?
        """, (
            session["usuario_id"],
            nome,
            id
        )).fetchone()

        if outra_categoria:

            flash(
                "Você já possui outra categoria com esse nome.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

        conn.execute("""
            UPDATE categorias_fornecedor

            SET nome = ?

            WHERE id = ?
              AND usuario_id = ?
        """, (
            nome,
            id,
            session["usuario_id"]
        ))

        conn.commit()

    except Exception as erro:

        conn.rollback()

        print(
            "ERRO AO EDITAR CATEGORIA:",
            erro
        )

        flash(
            "Não foi possível editar a categoria.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    finally:
        conn.close()

    flash(
        "Categoria atualizada com sucesso!",
        "sucesso"
    )

    return redirect(
        url_for("fornecedores")
    )

# ==========================================================
# EXCLUIR CATEGORIA
# ==========================================================

@app.route(
    "/excluir-categoria-fornecedor/<int:id>",
    methods=["POST"]
)
def excluir_categoria_fornecedor(id):
    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    try:
        # ==================================================
        # BUSCA E BLOQUEIA A CATEGORIA
        # ==================================================

        categoria = conn.execute("""
            SELECT
                id,
                nome
            FROM categorias_fornecedor
            WHERE id = ?
              AND usuario_id = ?
            FOR UPDATE
        """, (
            id,
            session["usuario_id"]
        )).fetchone()

        if not categoria:
            conn.rollback()

            flash(
                "Categoria não encontrada.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

        # ==================================================
        # VERIFICA SE EXISTEM FORNECEDORES NA CATEGORIA
        # ==================================================

        total_fornecedores = conn.execute("""
            SELECT COUNT(*) AS total
            FROM fornecedores
            WHERE categoria_id = ?
              AND usuario_id = ?
        """, (
            id,
            session["usuario_id"]
        )).fetchone()["total"]

        if total_fornecedores > 0:
            conn.rollback()

            flash(
                f"A categoria '{categoria['nome']}' "
                f"está sendo utilizada por "
                f"{total_fornecedores} fornecedor"
                f"{'es' if total_fornecedores != 1 else ''}. "
                "Altere a categoria desses fornecedores antes de excluí-la.",
                "erro"
            )

            return redirect(
                url_for("fornecedores")
            )

        # ==================================================
        # EXCLUI A CATEGORIA
        # ==================================================

        conn.execute("""
            DELETE FROM categorias_fornecedor
            WHERE id = ?
              AND usuario_id = ?
        """, (
            id,
            session["usuario_id"]
        ))

        conn.commit()

    except Exception as erro:
        conn.rollback()

        print(
            "ERRO AO EXCLUIR CATEGORIA:",
            erro
        )

        flash(
            "Não foi possível excluir a categoria.",
            "erro"
        )

        return redirect(
            url_for("fornecedores")
        )

    finally:
        conn.close()

    flash(
        "Categoria excluída com sucesso!",
        "sucesso"
    )

    return redirect(
        url_for("fornecedores")
    )

@app.route("/financeiro")
def financeiro():

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    usuario_id = session["usuario_id"]

    conn = get_db_connection()

    # --------------------------------------------------
    # PERFIL / ORÇAMENTO DO CASAMENTO
    # --------------------------------------------------

    casamento = conn.execute("""
        SELECT
            orcamento_planejado
        FROM casamentos
        WHERE usuario_id = ?
    """, (
        usuario_id,
    )).fetchone()

    orcamento_planejado = 0

    if casamento:
        orcamento_planejado = float(
            casamento["orcamento_planejado"]
            or 0
        )

    # --------------------------------------------------
    # TOTAIS DOS FORNECEDORES
    # --------------------------------------------------

    totais = conn.execute("""
        SELECT
            COUNT(*) AS total_fornecedores,
            COALESCE(SUM(valor), 0) AS total_contratado,
            COALESCE(SUM(valor_pago), 0) AS total_pago
        FROM fornecedores
        WHERE usuario_id = ?
    """, (
        usuario_id,
    )).fetchone()

    total_fornecedores = int(
        totais["total_fornecedores"]
        or 0
    )

    total_contratado = float(
        totais["total_contratado"]
        or 0
    )

    total_pago = float(
        totais["total_pago"]
        or 0
    )

    total_a_pagar = max(
        total_contratado - total_pago,
        0
    )

    # --------------------------------------------------
    # SALDO DO ORÇAMENTO
    # --------------------------------------------------

    saldo_orcamento = (
        orcamento_planejado
        -
        total_contratado
    )

    # --------------------------------------------------
    # % DO ORÇAMENTO COMPROMETIDO
    # --------------------------------------------------

    if orcamento_planejado > 0:

        percentual_comprometido = round(
            (
                total_contratado
                /
                orcamento_planejado
            )
            * 100
        )

    else:

        percentual_comprometido = 0

    # --------------------------------------------------
    # % DOS CONTRATOS JÁ PAGOS
    # --------------------------------------------------

    if total_contratado > 0:

        percentual_pago = round(
            (
                total_pago
                /
                total_contratado
            )
            * 100
        )

    else:

        percentual_pago = 0

    # --------------------------------------------------
    # GASTOS POR CATEGORIA
    # --------------------------------------------------

    categorias = conn.execute("""
        SELECT
            COALESCE(
                c.nome,
                'Sem categoria'
            ) AS categoria,

            COUNT(f.id) AS quantidade,

            COALESCE(
                SUM(f.valor),
                0
            ) AS total_contratado,

            COALESCE(
                SUM(f.valor_pago),
                0
            ) AS total_pago

        FROM fornecedores f

        LEFT JOIN categorias_fornecedor c
            ON c.id = f.categoria_id

        WHERE f.usuario_id = ?

        GROUP BY
            c.id,
            c.nome

        ORDER BY
            total_contratado DESC
    """, (
        usuario_id,
    )).fetchall()

    # --------------------------------------------------
    # MAIORES CONTRATOS
    # --------------------------------------------------

    maiores_fornecedores = conn.execute("""
        SELECT
            f.id,
            f.nome,
            f.valor,
            f.valor_pago,

            COALESCE(
                c.nome,
                'Sem categoria'
            ) AS categoria_nome

        FROM fornecedores f

        LEFT JOIN categorias_fornecedor c
            ON c.id = f.categoria_id

        WHERE f.usuario_id = ?

        ORDER BY
            f.valor DESC

        LIMIT 5
    """, (
        usuario_id,
    )).fetchall()

    pagamentos_planejados = conn.execute("""
        SELECT pp.id, pp.fornecedor_id, pp.descricao, pp.valor,
               pp.data_prevista, pp.status, f.nome AS fornecedor_nome
        FROM pagamentos_planejados pp
        JOIN fornecedores f ON f.id = pp.fornecedor_id
        WHERE f.usuario_id = ? AND pp.status = 'Pendente'
        ORDER BY (pp.data_prevista IS NULL OR pp.data_prevista = ''),
                 pp.data_prevista ASC, pp.id ASC
    """, (usuario_id,)).fetchall()
    total_planejado = sum(float(p["valor"] or 0) for p in pagamentos_planejados)
    conn.close()

    return render_template(
        "financeiro.html",

        orcamento_planejado=orcamento_planejado,

        total_fornecedores=total_fornecedores,
        total_contratado=total_contratado,
        total_pago=total_pago,
        total_a_pagar=total_a_pagar,

        saldo_orcamento=saldo_orcamento,

        percentual_comprometido=percentual_comprometido,
        percentual_pago=percentual_pago,

        categorias=categorias,
        pagamentos_planejados=pagamentos_planejados,
        total_planejado=total_planejado,
        maiores_fornecedores=maiores_fornecedores,

        usuario_nome=session.get(
            "usuario_nome",
            ""
        )
    )

@app.route("/onboarding")
def onboarding():

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    casamento = conn.execute("""
        SELECT *
        FROM casamentos
        WHERE usuario_id = ?
    """, (
        session["usuario_id"],
    )).fetchone()

    conn.close()

    if not casamento:
        flash(
            "Não foi possível localizar os dados do casamento.",
            "erro"
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "onboarding.html",
        casamento=casamento,
        usuario_nome=session.get(
            "usuario_nome",
            ""
        )
    )

@app.route(
    "/salvar-onboarding",
    methods=["POST"]
)
def salvar_onboarding():

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    nome_pessoa_2 = request.form.get(
        "nome_pessoa_2",
        ""
    ).strip()

    data_casamento = request.form.get(
        "data_casamento",
        ""
    ).strip()

    local_casamento = request.form.get(
        "local_casamento",
        ""
    ).strip()

    cidade = request.form.get(
        "cidade",
        ""
    ).strip()

    estado = request.form.get(
        "estado",
        ""
    ).strip().upper()

    orcamento = request.form.get(
        "orcamento_planejado",
        ""
    ).strip()

    convidados = request.form.get(
        "convidados_estimados",
        ""
    ).strip()

    # ======================================================
    # VALIDAÇÕES
    # ======================================================

    if not nome_pessoa_2:

        flash(
            "Informe o nome da outra pessoa.",
            "erro"
        )

        return redirect(
            url_for("onboarding")
        )

    if not data_casamento:

        flash(
            "Informe a data do casamento.",
            "erro"
        )

        return redirect(
            url_for("onboarding")
        )

    try:

        datetime.strptime(
            data_casamento,
            "%Y-%m-%d"
        )

    except ValueError:

        flash(
            "Informe uma data válida.",
            "erro"
        )

        return redirect(
            url_for("onboarding")
        )

    try:

        orcamento = (
            converter_valor_brl(orcamento)
            if orcamento
            else 0
        )

    except ValueError:

        flash(
            "Informe um orçamento válido.",
            "erro"
        )

        return redirect(
            url_for("onboarding")
        )

    try:

        convidados = (
            int(convidados)
            if convidados
            else 0
        )

    except ValueError:

        flash(
            "Informe uma quantidade válida de convidados.",
            "erro"
        )

        return redirect(
            url_for("onboarding")
        )

    if orcamento < 0:

        flash(
            "O orçamento não pode ser negativo.",
            "erro"
        )

        return redirect(
            url_for("onboarding")
        )

    if convidados < 0:

        flash(
            "A quantidade de convidados não pode ser negativa.",
            "erro"
        )

        return redirect(
            url_for("onboarding")
        )

    # ======================================================
    # SALVAR
    # ======================================================

    conn = get_db_connection()

    try:
        casamento = conn.execute(
            "SELECT id FROM casamentos WHERE usuario_id = ?",
            (session["usuario_id"],)
        ).fetchone()
        if not casamento:
            flash("Não foi possível localizar o perfil do casamento.", "erro")
            return redirect(url_for("dashboard"))

        conn.execute("""
            UPDATE casamentos
            SET
                nome_pessoa_2 = ?,
                data_casamento = ?,
                local_casamento = ?,
                cidade = ?,
                estado = ?,
                orcamento_planejado = ?,
                convidados_estimados = ?,
                atualizado_em = CURRENT_TIMESTAMP
            WHERE usuario_id = ?
        """, (
            nome_pessoa_2,
            data_casamento,
            local_casamento or None,
            cidade or None,
            estado or None,
            orcamento,
            convidados,
            session["usuario_id"]
        ))

        conn.commit()

    except Exception as erro:

        conn.rollback()

        print(
            "ERRO AO SALVAR ONBOARDING:",
            erro
        )

        flash(
            "Não foi possível salvar as informações.",
            "erro"
        )

        return redirect(
            url_for("onboarding")
        )

    finally:

        conn.close()

    flash(
        "Seu casamento está configurado! 💕",
        "sucesso"
    )

    return redirect(
        url_for("dashboard")
    )

@app.template_filter("data_br")
def data_br(valor):
    """Formata as datas ISO do SQLite para os templates existentes."""
    if not valor:
        return ""
    if isinstance(valor, (datetime, date)):
        return valor.strftime("%d/%m/%Y")
    try:
        return date.fromisoformat(str(valor)[:10]).strftime("%d/%m/%Y")
    except (ValueError, TypeError):
        return str(valor)

@app.context_processor
def contexto_usuario():
    return {"usuario_nome": session.get("usuario_nome", "")}

@app.route("/minha-conta")
def minha_conta():

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    usuario = conn.execute("""
        SELECT
            id,
            nome,
            email
        FROM usuarios
        WHERE id = ?
    """, (
        session["usuario_id"],
    )).fetchone()

    conn.close()

    if not usuario:

        session.clear()

        return redirect(
            url_for("login")
        )

    return render_template(
        "minha_conta.html",
        usuario=usuario
    )

@app.route(
    "/atualizar-conta",
    methods=["POST"]
)
def atualizar_conta():

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    nome = request.form.get(
        "nome",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip().lower()


    if not nome or not email:

        flash(
            "Preencha nome e e-mail.",
            "erro"
        )

        return redirect(
            url_for("minha_conta")
        )


    conn = get_db_connection()

    try:

        email_existente = conn.execute("""
            SELECT id
            FROM usuarios
            WHERE LOWER(email) = LOWER(?)
              AND id != ?
        """, (
            email,
            session["usuario_id"]
        )).fetchone()


        if email_existente:

            flash(
                "Este e-mail já está sendo utilizado por outra conta.",
                "erro"
            )

            return redirect(
                url_for("minha_conta")
            )


        conn.execute("""
            UPDATE usuarios
            SET
                nome = ?,
                email = ?
            WHERE id = ?
        """, (
            nome,
            email,
            session["usuario_id"]
        ))


        conn.commit()

        # Atualiza também o nome armazenado
        # na sessão atual.
        session["usuario_nome"] = nome


    except Exception as erro:

        conn.rollback()

        print(
            "ERRO AO ATUALIZAR CONTA:",
            erro
        )

        flash(
            "Não foi possível atualizar sua conta.",
            "erro"
        )

        return redirect(
            url_for("minha_conta")
        )

    finally:

        conn.close()


    flash(
        "Dados atualizados com sucesso!",
        "sucesso"
    )

    return redirect(
        url_for("minha_conta")
    )


@app.route(
    "/alterar-senha",
    methods=["POST"]
)
def alterar_senha():

    if not usuario_logado():
        return redirect(
            url_for("login")
        )

    senha_atual = request.form.get(
        "senha_atual",
        ""
    )

    nova_senha = request.form.get(
        "nova_senha",
        ""
    )

    confirmar_senha = request.form.get(
        "confirmar_senha",
        ""
    )


    if (
        not senha_atual
        or
        not nova_senha
        or
        not confirmar_senha
    ):

        flash(
            "Preencha todos os campos de senha.",
            "erro"
        )

        return redirect(
            url_for("minha_conta")
        )


    if len(nova_senha) < 6:

        flash(
            "A nova senha precisa ter pelo menos 6 caracteres.",
            "erro"
        )

        return redirect(
            url_for("minha_conta")
        )


    if nova_senha != confirmar_senha:

        flash(
            "A confirmação da nova senha não confere.",
            "erro"
        )

        return redirect(
            url_for("minha_conta")
        )


    conn = get_db_connection()

    try:

        usuario = conn.execute("""
            SELECT senha
            FROM usuarios
            WHERE id = ?
        """, (
            session["usuario_id"],
        )).fetchone()


        if not usuario:

            flash(
                "Usuário não encontrado.",
                "erro"
            )

            return redirect(
                url_for("minha_conta")
            )


        senha_valida = False

        try:

            senha_valida = check_password_hash(
                usuario["senha"],
                senha_atual
            )

        except ValueError:

            senha_valida = False


        if not senha_valida:

            flash(
                "A senha atual está incorreta.",
                "erro"
            )

            return redirect(
                url_for("minha_conta")
            )


        nova_hash = generate_password_hash(
            nova_senha
        )


        conn.execute("""
            UPDATE usuarios
            SET senha = ?
            WHERE id = ?
        """, (
            nova_hash,
            session["usuario_id"]
        ))


        conn.commit()


    except Exception as erro:

        conn.rollback()

        print(
            "ERRO AO ALTERAR SENHA:",
            erro
        )

        flash(
            "Não foi possível alterar sua senha.",
            "erro"
        )

        return redirect(
            url_for("minha_conta")
        )

    finally:

        conn.close()


    flash(
        "Senha alterada com sucesso!",
        "sucesso"
    )

    return redirect(
        url_for("minha_conta")
    )

# Todas as rotas e filtros precisam estar registrados ANTES de iniciar o servidor.
if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1")
