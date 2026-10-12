"""Testes unitários de funcionalidades locais do ZERO Scanner (sem acesso à rede)."""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import zero_scanner as scanner


class ValidacoesTestes(unittest.TestCase):
    def test_alvos_validos(self):
        for alvo in ("127.0.0.1", "192.168.0.10", "localhost", "servidor.local"):
            with self.subTest(alvo=alvo):
                self.assertTrue(scanner.validar_alvo(alvo))

    def test_alvos_invalidos(self):
        for alvo in ("", "-n", "192.168.0.1;id", "999.999.999.999",
                     "host name", "10.0.0.0/24", "2001:db8::1", "$(id)"):
            with self.subTest(alvo=alvo):
                self.assertFalse(scanner.validar_alvo(alvo))

    def test_portas_e_intervalos(self):
        self.assertEqual(scanner.analisar_portas("445,139,8000-8002,445"),
                         [139, 445, 8000, 8001, 8002])

    def test_portas_invalidas(self):
        for entrada in ("", "0", "65536", "445;id", "100-10", "1-5000", "abc"):
            with self.subTest(entrada=entrada):
                with self.assertRaises(ValueError):
                    scanner.analisar_portas(entrada)

    def test_classificacao_ms17_010(self):
        self.assertEqual(
            scanner.situacao_vulnerabilidade("|   State: VULNERABLE\n"),
            "vulneravel"
        )
        self.assertEqual(
            scanner.situacao_vulnerabilidade("|   State: NOT VULNERABLE\n"),
            "nao_vulneravel"
        )
        self.assertEqual(
            scanner.situacao_vulnerabilidade("Nmap done. Not enough information."),
            "inconclusivo"
        )
        self.assertEqual(
            scanner.situacao_vulnerabilidade("Check whether system is VULNERABLE"),
            "inconclusivo"
        )


class FluxoTestes(unittest.TestCase):
    def test_nao_executa_consultas_smb_sem_portas_confirmadas(self):
        instancia = scanner.Scanner("127.0.0.1", salvar=False)
        with (patch.object(instancia, "verificar_ferramentas"),
              patch.object(instancia, "verificar_portas"),
              patch.object(instancia, "identificar_smb") as nmap,
              patch.object(instancia, "listar_compartilhamentos") as smb,
              patch.object(instancia, "verificar_ms17_010") as vuln,
              contextlib.redirect_stdout(io.StringIO())):
            resultado = instancia.executar()
        self.assertEqual(resultado["ms17_010"], "nao_testado")
        nmap.assert_not_called()
        smb.assert_not_called()
        vuln.assert_not_called()

    def test_nmap_sem_resultado_explicito_e_inconclusivo(self):
        instancia = scanner.Scanner("127.0.0.1", salvar=False)
        retorno = subprocess.CompletedProcess(args=["nmap"], returncode=0,
                                             stdout="Nmap scan report", stderr="")
        with (patch.object(scanner.shutil, "which", return_value="/bin/nmap"),
              patch.object(scanner, "executar", return_value=retorno),
              contextlib.redirect_stdout(io.StringIO())):
            instancia.verificar_ms17_010()
        self.assertEqual(instancia.dados["ms17_010"], "inconclusivo")

    def test_relatorios_json_txt_sem_acesso_a_rede(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = Path(pasta) / "relatorios" / "teste.json"
            instancia = scanner.Scanner("127.0.0.1", saida=str(caminho))
            instancia.dados["total_portas_verificadas"] = 2
            instancia.dados["ms17_010"] = "inconclusivo"
            with contextlib.redirect_stdout(io.StringIO()):
                instancia.relatorios()
            self.assertTrue(caminho.is_file())
            self.assertTrue(caminho.with_suffix(".txt").is_file())
            documento = json.loads(caminho.read_text(encoding="utf-8"))
            self.assertEqual(documento["autor"], "Rodrigo Segobia")
            self.assertEqual(documento["resultados"]["ms17_010"], "inconclusivo")

    def test_comando_personalizado_exige_portas(self):
        with (contextlib.redirect_stderr(io.StringIO()),
              self.assertRaises(SystemExit) as erro):
            scanner.main(["127.0.0.1", "-m", "custom", "--no-report"])
        self.assertEqual(erro.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
