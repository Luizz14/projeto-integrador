#!/usr/bin/env python3
"""
Entrega 1 - Criptografia assimétrica (cifragem híbrida AES-256-GCM + RSA-OAEP)

Fluxo:
  1. O destinatário gera um par de chaves RSA-3072 (privada protegida por senha).
  2. O remetente gera uma chave AES-256 aleatória (chave de sessão) e um nonce de 96 bits.
  3. A mensagem é cifrada com AES-GCM (sigilo + integridade via tag de 128 bits).
  4. A chave de sessão é cifrada com a chave PÚBLICA RSA do destinatário usando OAEP (SHA-256).
  5. O pacote (chave cifrada + nonce + texto cifrado) é salvo em JSON.
  6. Só quem tem a chave PRIVADA recupera a chave de sessão e decifra.

Uso:
  python hibrida.py gerar-chaves --dir chaves
  python hibrida.py cifrar   --pub chaves/publica.pem --entrada msg.txt --saida msg.enc.json
  python hibrida.py decifrar --priv chaves/privada.pem --entrada msg.enc.json --saida msg.dec.txt
  python hibrida.py adulterar --entrada msg.enc.json --saida msg.adulterada.json [--campo ciphertext|nonce|chave|aad]
  python hibrida.py demo
"""

import argparse
import base64
import getpass
import json
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSAO = "hibrida-v1"
RSA_BITS = 3072          # NIST SP
AES_BITS = 256
NONCE_BYTES = 12         # 96 bits

OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# chaves
def gerar_par(senha: bytes):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(senha),
    )
    
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    
    return priv_pem, pub_pem


def carregar_publica(pem: bytes):
    return serialization.load_pem_public_key(pem)


def carregar_privada(pem: bytes, senha: bytes):
    return serialization.load_pem_private_key(pem, password=senha)


def fingerprint(pub) -> str:
    der = pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    h = hashes.Hash(hashes.SHA256())
    h.update(der)
    
    return h.finalize().hex()[:32]


# cifra
def cifrar(mensagem: bytes, pub) -> dict:
    chave_sessao = AESGCM.generate_key(bit_length=AES_BITS)
    nonce = os.urandom(NONCE_BYTES)
    fp = fingerprint(pub)
    
    aad = f"{VERSAO}|{fp}".encode()
    ct = AESGCM(chave_sessao).encrypt(nonce, mensagem, aad)
    chave_cifrada = pub.encrypt(chave_sessao, OAEP)
    
    return {
        "versao": VERSAO,
        "alg": "RSA-OAEP-SHA256 + AES-256-GCM",
        "destinatario_fp": fp,
        "chave_cifrada": b64e(chave_cifrada),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ct),
    }


def decifrar(pacote: dict, priv) -> bytes:
    chave_sessao = priv.decrypt(b64d(pacote["chave_cifrada"]), OAEP)
    aad = f"{pacote['versao']}|{pacote['destinatario_fp']}".encode()
    
    return AESGCM(chave_sessao).decrypt(b64d(pacote["nonce"]), b64d(pacote["ciphertext"]), aad)


def adulterar(pacote: dict, campo: str = "ciphertext") -> dict:
    p = dict(pacote)
    
    if campo == "aad":
        p["destinatario_fp"] = "0" * 32
        return p
    
    nome = {"chave": "chave_cifrada"}.get(campo, campo)
    dados = bytearray(b64d(p[nome]))
    dados[len(dados) // 2] ^= 0x01
    p[nome] = b64e(bytes(dados))
    
    return p


# CLI
def ler_senha(prompt: str) -> bytes:
    env = os.environ.get("SENHA_CHAVE")
    
    return (env if env is not None else getpass.getpass(prompt)).encode()


def cmd_gerar(a):
    d = Path(a.dir)
    d.mkdir(parents=True, exist_ok=True)
    
    priv_pem, pub_pem = gerar_par(ler_senha("Senha para proteger a chave privada: "))
    
    (d / "privada.pem").write_bytes(priv_pem)
    os.chmod(d / "privada.pem", 0o600)
    (d / "publica.pem").write_bytes(pub_pem)
    
    print(f"[OK] Par RSA-{RSA_BITS} gerado em {d}/ (privada.pem protegida por senha, publica.pem)")
    print(f"     fingerprint SHA-256 da pública: {fingerprint(carregar_publica(pub_pem))}")


def cmd_cifrar(a):
    pub = carregar_publica(Path(a.pub).read_bytes())
    pacote = cifrar(Path(a.entrada).read_bytes(), pub)
    Path(a.saida).write_text(json.dumps(pacote, indent=2))
    
    print(f"[OK] '{a.entrada}' cifrado -> '{a.saida}'")


def cmd_decifrar(a):
    try:
        priv = carregar_privada(Path(a.priv).read_bytes(), ler_senha("Senha da chave privada: "))
    except (ValueError, TypeError):
        print("[FALHA] Senha da chave privada incorreta.")
        sys.exit(2)
    
    pacote = json.loads(Path(a.entrada).read_text())
    
    try:
        texto = decifrar(pacote, priv)
    except InvalidTag:
        print("[FALHA] Tag GCM inválida: o texto cifrado, o nonce ou os metadados foram ADULTERADOS.")
        sys.exit(1)
    except ValueError:
        print("[FALHA] Não foi possível decifrar a chave de sessão (RSA-OAEP): chave adulterada ou chave privada errada.")
        sys.exit(1)
    Path(a.saida).write_bytes(texto)
    
    print(f"[OK] '{a.entrada}' decifrado -> '{a.saida}'")


def cmd_adulterar(a):
    pacote = json.loads(Path(a.entrada).read_text())
    Path(a.saida).write_text(json.dumps(adulterar(pacote, a.campo), indent=2))
    
    print(f"[!] Campo '{a.campo}' adulterado (1 bit) -> '{a.saida}'")


def cmd_demo(_a):
    senha = b"senha-de-demo"
    print("== DEMO: cifragem híbrida AES-256-GCM + RSA-OAEP ==\n")
    
    priv_pem, pub_pem = gerar_par(senha)
    pub, priv = carregar_publica(pub_pem), carregar_privada(priv_pem, senha)
    msg = "Relatório confidencial: senha do servidor de backup = S3gr3d0!".encode()
    
    print(f"Mensagem original : {msg.decode()}")
    pacote = cifrar(msg, pub)
    
    print(f"Chave AES cifrada : {pacote['chave_cifrada'][:48]}... ({len(b64d(pacote['chave_cifrada']))} bytes)")
    print(f"Texto cifrado     : {pacote['ciphertext'][:48]}...\n")

    print("[1] Decifrar pacote íntegro com a chave correta")
    print(f"    -> SUCESSO: {decifrar(pacote, priv).decode()}\n")

    casos = [
        ("ciphertext", "1 bit do texto cifrado"),
        ("nonce", "1 bit do nonce"),
        ("aad", "metadados autenticados (fingerprint)"),
        ("chave", "1 bit da chave AES cifrada"),
    ]
    
    for i, (campo, desc) in enumerate(casos, start=2):
        print(f"[{i}] Adulterar {desc} e tentar decifrar")
        try:
            decifrar(adulterar(pacote, campo), priv)
            print("    -> ERRO: deveria ter falhado!")
        except InvalidTag:
            print("    -> FALHA ESPERADA: InvalidTag (GCM detectou a alteração)\n")
        except ValueError:
            print("    -> FALHA ESPERADA: ValueError na decifragem RSA-OAEP\n")

    print(f"[{len(casos) + 2}] Decifrar com a chave privada de OUTRA pessoa")
    
    outra = carregar_privada(gerar_par(senha)[0], senha)
    
    try:
        decifrar(pacote, outra)
        print("    -> ERRO: deveria ter falhado!")
    except ValueError:
        print("    -> FALHA ESPERADA: só o dono da chave privada lê a mensagem (sigilo)\n")
    print("== Fim da demo ==")


def main():
    ap = argparse.ArgumentParser(description="Cifragem híbrida AES-256-GCM + RSA-OAEP")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gerar-chaves"); g.add_argument("--dir", default="chaves"); g.set_defaults(f=cmd_gerar)
    c = sub.add_parser("cifrar"); c.add_argument("--pub", required=True); c.add_argument("--entrada", required=True); c.add_argument("--saida", required=True); c.set_defaults(f=cmd_cifrar)
    d = sub.add_parser("decifrar"); d.add_argument("--priv", required=True); d.add_argument("--entrada", required=True); d.add_argument("--saida", required=True); d.set_defaults(f=cmd_decifrar)
    t = sub.add_parser("adulterar"); t.add_argument("--entrada", required=True); t.add_argument("--saida", required=True); t.add_argument("--campo", default="ciphertext", choices=["ciphertext", "nonce", "chave", "aad"]); t.set_defaults(f=cmd_adulterar)
    m = sub.add_parser("demo"); m.set_defaults(f=cmd_demo)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
