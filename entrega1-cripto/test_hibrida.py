import unittest

from cryptography.exceptions import InvalidTag

import hibrida as h

SENHA = b"teste"


class TestHibrida(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        priv_pem, pub_pem = h.gerar_par(SENHA)
        cls.pub = h.carregar_publica(pub_pem)
        cls.priv = h.carregar_privada(priv_pem, SENHA)
        cls.msg = "Mensagem de teste com acentuação: ção".encode()
        cls.pacote = h.cifrar(cls.msg, cls.pub)

    def test_ida_e_volta(self):
        self.assertEqual(h.decifrar(self.pacote, self.priv), self.msg)

    def test_texto_cifrado_nao_contem_original(self):
        self.assertNotIn(self.msg, h.b64d(self.pacote["ciphertext"]))

    def test_nonce_e_chave_novos_a_cada_cifra(self):
        p2 = h.cifrar(self.msg, self.pub)
        self.assertNotEqual(p2["nonce"], self.pacote["nonce"])
        self.assertNotEqual(p2["ciphertext"], self.pacote["ciphertext"])

    def test_adulterar_ciphertext(self):
        with self.assertRaises(InvalidTag):
            h.decifrar(h.adulterar(self.pacote, "ciphertext"), self.priv)

    def test_adulterar_nonce(self):
        with self.assertRaises(InvalidTag):
            h.decifrar(h.adulterar(self.pacote, "nonce"), self.priv)

    def test_adulterar_aad(self):
        with self.assertRaises(InvalidTag):
            h.decifrar(h.adulterar(self.pacote, "aad"), self.priv)

    def test_adulterar_chave_cifrada(self):
        with self.assertRaises(ValueError):
            h.decifrar(h.adulterar(self.pacote, "chave"), self.priv)

    def test_chave_privada_errada(self):
        outra = h.carregar_privada(h.gerar_par(SENHA)[0], SENHA)
        with self.assertRaises(ValueError):
            h.decifrar(self.pacote, outra)

    def test_senha_errada_na_privada(self):
        priv_pem, _ = h.gerar_par(SENHA)
        with self.assertRaises((ValueError, TypeError)):
            h.carregar_privada(priv_pem, b"errada")


if __name__ == "__main__":
    unittest.main(verbosity=2)
