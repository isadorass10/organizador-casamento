from flask import Flask, render_template, request, redirect
import json
import os

app = Flask(__name__)

ARQUIVO = "dados.json"


# -------------------------
# Persistência
# -------------------------
def carregar():
    if not os.path.exists(ARQUIVO):
        return []

    with open(ARQUIVO, "r", encoding="utf-8") as f:
        dados = json.load(f)
        return dados if isinstance(dados, list) else []


def salvar(dados):
    with open(ARQUIVO, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=4)


# -------------------------
# Rotas
# -------------------------
@app.route("/")
def index():
    dados = carregar()

    total_geral = sum(item["total"] for item in dados)
    total_pago = sum(item["pago"] for item in dados)

    progresso = 0
    if total_geral > 0:
        progresso = int((total_pago / total_geral) * 100)

    return render_template(
        "index.html",
        orcamento=dados,
        total_geral=total_geral,
        total_pago=total_pago,
        progresso=progresso
    )


@app.route("/adicionar", methods=["POST"])
def adicionar():
    dados = carregar()

    novo = {
        "id": len(dados),
        "nome": request.form["nome"],
        "total": float(request.form["total"]),
        "pago": float(request.form["pago"])
    }

    dados.append(novo)
    salvar(dados)
    return redirect("/")


@app.route("/editar/<int:item_id>", methods=["POST"])
def editar(item_id):
    dados = carregar()

    for item in dados:
        if item["id"] == item_id:
            item["pago"] = float(request.form["pago"])
            break

    salvar(dados)
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)
