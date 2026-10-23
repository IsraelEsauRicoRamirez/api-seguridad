import os
import hmac
import datetime
from functools import wraps

import jwt
from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ---------- Configuración (viene del archivo .env) ----------
API_KEY = os.environ.get("API_KEY", "cambia-esta-api-key")
JWT_SECRET = os.environ.get("JWT_SECRET", "cambia-este-secreto-muy-largo-123456")
JWT_EXP_MIN = 30

# ---------- 4) RATE LIMITER ----------
# Por defecto: 30 peticiones por minuto por IP. El login es más estricto.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["30 per minute"],
    storage_uri="memory://",
)

# ---------- "Base de datos" de mentiritas (en memoria) ----------
USERS = {
    "admin": {"password": generate_password_hash("admin123"), "role": "admin"},
    "ana": {"password": generate_password_hash("ana123"), "role": "user"},
    "beto": {"password": generate_password_hash("beto123"), "role": "user"},
}

NOTAS = [
    {"id": 1, "owner": "ana", "texto": "Nota privada de Ana"},
    {"id": 2, "owner": "beto", "texto": "Nota privada de Beto"},
    {"id": 3, "owner": "admin", "texto": "Nota del administrador"},
]


# ---------- 1) API KEY ----------
@app.before_request
def revisar_api_key():
    enviada = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(enviada, API_KEY):
        return jsonify(error="API key invalida o faltante"), 401


# ---------- 2) JWT + ROLES ----------
def requiere_jwt(roles=None):
    def decorador(f):
        @wraps(f)
        def envoltura(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify(error="Falta el token JWT (Authorization: Bearer ...)"), 401
            token = auth.split(" ", 1)[1]
            try:
                datos = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            except jwt.ExpiredSignatureError:
                return jsonify(error="Token expirado"), 401
            except jwt.InvalidTokenError:
                return jsonify(error="Token invalido"), 401
            g.usuario = datos["sub"]
            g.rol = datos["role"]
            if roles and g.rol not in roles:
                return jsonify(error="No tienes el rol necesario"), 403
            return f(*args, **kwargs)
        return envoltura
    return decorador


@app.post("/login")
@limiter.limit("5 per minute")  # frena ataques de fuerza bruta
def login():
    datos = request.get_json(silent=True) or {}
    usuario = USERS.get(datos.get("username", ""))
    if not usuario or not check_password_hash(usuario["password"], datos.get("password", "")):
        return jsonify(error="Usuario o contrasena incorrectos"), 401
    token = jwt.encode(
        {
            "sub": datos["username"],
            "role": usuario["role"],
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=JWT_EXP_MIN),
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    return jsonify(token=token, expira_en_minutos=JWT_EXP_MIN)


@app.get("/salud")
def salud():
    return jsonify(estado="ok")


# ---------- 3) BOLA / IDOR ----------
@app.get("/notas")
@requiere_jwt()
def mis_notas():
    if g.rol == "admin":
        return jsonify(NOTAS)
    return jsonify([n for n in NOTAS if n["owner"] == g.usuario])


@app.post("/notas")
@requiere_jwt()
def crear_nota():
    datos = request.get_json(silent=True) or {}
    texto = str(datos.get("texto", "")).strip()
    if not texto:
        return jsonify(error="Falta 'texto'"), 400
    nota = {"id": max(n["id"] for n in NOTAS) + 1, "owner": g.usuario, "texto": texto}
    NOTAS.append(nota)
    return jsonify(nota), 201


@app.get("/notas/<int:nota_id>")
@requiere_jwt()
def ver_nota(nota_id):
    """SEGURO: revisa que la nota sea del usuario (o que sea admin)."""
    nota = next((n for n in NOTAS if n["id"] == nota_id), None)
    if not nota:
        return jsonify(error="No existe"), 404
    if nota["owner"] != g.usuario and g.rol != "admin":
        return jsonify(error="Esa nota no es tuya"), 403
    return jsonify(nota)


@app.get("/inseguro/notas/<int:nota_id>")
@requiere_jwt()
def ver_nota_insegura(nota_id):
    """VULNERABLE (solo para demostrar BOLA/IDOR): NO revisa el dueno."""
    nota = next((n for n in NOTAS if n["id"] == nota_id), None)
    if not nota:
        return jsonify(error="No existe"), 404
    return jsonify(nota)


@app.delete("/notas/<int:nota_id>")
@requiere_jwt()
def borrar_nota(nota_id):
    nota = next((n for n in NOTAS if n["id"] == nota_id), None)
    if not nota:
        return jsonify(error="No existe"), 404
    if nota["owner"] != g.usuario and g.rol != "admin":
        return jsonify(error="Esa nota no es tuya"), 403
    NOTAS.remove(nota)
    return jsonify(mensaje="Borrada")


@app.get("/admin/usuarios")
@requiere_jwt(roles=["admin"])
def listar_usuarios():
    return jsonify([{"username": u, "role": d["role"]} for u, d in USERS.items()])


@app.errorhandler(429)
def demasiadas(e):
    return jsonify(error="Demasiadas peticiones, espera un momento (rate limit)"), 429


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
