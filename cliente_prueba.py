"""Uso:  python cliente_prueba.py http://IP:5000 TU_API_KEY"""
import sys
import requests

if len(sys.argv) != 3:
    sys.exit("Uso: python cliente_prueba.py http://IP:5000 TU_API_KEY")
URL, KEY = sys.argv[1].rstrip("/"), sys.argv[2]
H = {"X-API-Key": KEY}


def mostrar(titulo, r):
    print(f"\n== {titulo}\n   -> {r.status_code} {r.text.strip()}")


def login(u, p):
    return requests.post(f"{URL}/login", json={"username": u, "password": p}, headers=H)


def auth(token):
    return {**H, "Authorization": f"Bearer {token}"}


mostrar("1) Sin API key (debe dar 401)", requests.get(f"{URL}/notas"))
mostrar("2) Con API key pero sin JWT (debe dar 401)", requests.get(f"{URL}/notas", headers=H))

tok_ana = login("ana", "ana123").json()["token"]
tok_admin = login("admin", "admin123").json()["token"]
print("\n== 3) Login de ana y admin: OK (tokens recibidos)")

mostrar("4) Ana ve sus notas (200)", requests.get(f"{URL}/notas", headers=auth(tok_ana)))
mostrar("5) Ana ve SU nota 1 (200)", requests.get(f"{URL}/notas/1", headers=auth(tok_ana)))
mostrar("6) BOLA bloqueado: Ana pide nota 2 de Beto (403)", requests.get(f"{URL}/notas/2", headers=auth(tok_ana)))
mostrar("7) BOLA/IDOR en endpoint VULNERABLE: Ana lee nota 2 (200 = fallo)", requests.get(f"{URL}/inseguro/notas/2", headers=auth(tok_ana)))
mostrar("8) Ana intenta ruta admin (403)", requests.get(f"{URL}/admin/usuarios", headers=auth(tok_ana)))
mostrar("9) Admin entra a ruta admin (200)", requests.get(f"{URL}/admin/usuarios", headers=auth(tok_admin)))

print("\n== 10) Rate limit: 7 logins malos seguidos")
for i in range(1, 8):
    print(f"   intento {i}: {login('ana', 'mala').status_code}")
