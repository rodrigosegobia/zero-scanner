#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZERO Scanner - análise de serviços SMB em redes autorizadas.

Desenvolvimento e manutenção: Rodrigo Segobia
Projeto: https://github.com/rodrigosegobia/zero-scanner
Licença: MIT
"""

import argparse
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

VERSAO = "1.1.0"
REPOSITORIO = "https://github.com/rodrigosegobia/zero-scanner"
PORTAS = {
    "basic": [(139, "tcp", "NetBIOS"), (445, "tcp", "SMB")],
    "full": [
        (139, "tcp", "NetBIOS"), (445, "tcp", "SMB"),
        (137, "udp", "NetBIOS Name Service"),
        (138, "udp", "NetBIOS Datagram"),
        (135, "tcp", "MSRPC"), (389, "tcp", "LDAP"),
        (636, "tcp", "LDAPS"), (88, "tcp", "Kerberos"),
        (464, "tcp", "Kerberos Password"),
        (53, "tcp", "DNS"), (53, "udp", "DNS"),
        (3389, "tcp", "RDP"),
    ],
}
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def validar_alvo(alvo):
    """Aceita IPv4 ou nome DNS, nunca argumentos de shell ou rede inteira."""
    if not alvo or len(alvo) > 253 or alvo.startswith("-"):
        return False
    try:
        return isinstance(ipaddress.ip_address(alvo), ipaddress.IPv4Address)
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.]+", alvo):
        return False
    return HOSTNAME.fullmatch(alvo) is not None


def analisar_portas(texto):
    """Converte 139,445,8000-8002 em portas TCP válidas, sem intervalos enormes."""
    if not texto or not texto.strip():
        raise ValueError("Informe pelo menos uma porta.")
    resultado = set()
    for segmento in texto.split(","):
        parte = segmento.strip()
        if re.fullmatch(r"\d+", parte):
            inicio = fim = int(parte)
        elif re.fullmatch(r"\d+-\d+", parte):
            inicio, fim = map(int, parte.split("-", 1))
        else:
            raise ValueError("Formato inválido de portas: " + parte)
        if not (1 <= inicio <= fim <= 65535):
            raise ValueError("As portas devem estar entre 1 e 65535.")
        if fim - inicio > 4095 or len(resultado) + fim - inicio + 1 > 4096:
            raise ValueError("Limite de 4096 portas por execução.")
        resultado.update(range(inicio, fim + 1))
    return sorted(resultado)


def executar(comando, tempo=30):
    """Executa comandos externos sem shell e com tempo limite."""
    return subprocess.run(
        comando, capture_output=True, text=True, errors="replace",
        timeout=tempo, check=False
    )


def situacao_vulnerabilidade(saida):
    """Retorna vulnerável, não vulnerável ou inconclusivo sem falsos negativos."""
    if re.search(r"(?im)^\s*\|?\s*State:\s*VULNERABLE\b", saida):
        return "vulneravel"
    if re.search(r"(?im)^\s*\|?\s*State:\s*NOT VULNERABLE\b", saida):
        return "nao_vulneravel"
    return "inconclusivo"


def testar_porta(alvo, porta, protocolo, tempo):
    """UDP sem resposta é inconclusivo; não representa uma porta aberta."""
    try:
        if protocolo == "tcp":
            with socket.create_connection((alvo, porta), timeout=tempo):
                return "aberta"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conexao:
            conexao.settimeout(tempo)
            conexao.sendto(b"\x00", (alvo, porta))
            conexao.recvfrom(512)
        return "respondeu"
    except (socket.timeout, OSError):
        return "inconclusiva" if protocolo == "udp" else "fechada_ou_filtrada"


def resolver_enum4linux():
    """Distingue enum4linux clássico de enum4linux-ng."""
    caminho = shutil.which("enum4linux-ng")
    if caminho:
        return [caminho], "-A"
    for local in (
        Path.home() / "enum4linux-ng" / "enum4linux-ng.py",
        Path.home() / "tools" / "enum4linux-ng" / "enum4linux-ng.py",
    ):
        if local.is_file() and shutil.which("python3"):
            return [shutil.which("python3"), str(local)], "-A"
    caminho = shutil.which("enum4linux")
    if caminho:
        return [caminho], "-a"
    return None, None


class Scanner:
    def __init__(self, alvo, modo="basic", portas=None, saida=None,
                 detalhado=False, forcar=False, tempo=3, threads=10,
                 salvar=True):
        if not validar_alvo(alvo):
            raise ValueError("Alvo inválido. Informe um IPv4 ou nome de host válido.")
        if modo not in PORTAS and modo != "custom":
            raise ValueError("Modo de varredura inválido.")
        if modo == "custom" and not portas:
            raise ValueError("O modo personalizado exige a opção -p/--ports.")
        self.alvo = alvo
        self.modo = modo
        self.portas = portas
        self.saida = saida
        self.detalhado = detalhado
        self.forcar = forcar
        self.tempo = tempo
        self.threads = threads
        self.salvar = salvar
        self.dados = {
            "portas_abertas": [],
            "portas_udp_sem_resposta": [],
            "compartilhamentos": [],
            "sistema_operacional": None,
            "ms17_010": "nao_testado",
            "ferramentas_ausentes": [],
            "erros": [],
            "total_portas_verificadas": 0,
        }

    def informar(self, mensagem, tipo="INFO"):
        print(f"[{datetime.now():%H:%M:%S}] [{tipo}] {mensagem}")

    def verificar_ferramentas(self):
        for nome in ("nmap", "smbclient"):
            if shutil.which(nome) is None:
                self.dados["ferramentas_ausentes"].append(nome)
                self.informar(f"{nome} não encontrado. Recursos dependentes serão ignorados.", "AVISO")

    def verificar_portas(self):
        lista = ([(p, "tcp", "Personalizada") for p in self.portas]
                 if self.modo == "custom" else PORTAS[self.modo])
        self.dados["total_portas_verificadas"] = len(lista)
        self.informar(f"Verificando {len(lista)} portas no alvo {self.alvo}...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            tarefas = {
                executor.submit(testar_porta, self.alvo, p, proto, self.tempo): (p, proto, servico)
                for p, proto, servico in lista
            }
            for futuro in as_completed(tarefas):
                porta, protocolo, servico = tarefas[futuro]
                try:
                    status = futuro.result()
                    if status in ("aberta", "respondeu"):
                        self.dados["portas_abertas"].append({
                            "porta": porta, "protocolo": protocolo,
                            "servico": servico, "estado": status,
                        })
                        self.informar(f"{porta}/{protocolo} ({servico}): {status}", "OK")
                    elif status == "inconclusiva":
                        self.dados["portas_udp_sem_resposta"].append(porta)
                        if self.detalhado:
                            self.informar(f"{porta}/udp: sem resposta (inconclusivo)", "AVISO")
                    elif self.detalhado:
                        self.informar(f"{porta}/{protocolo}: sem conexão", "DEBUG")
                except Exception as erro:
                    self.dados["erros"].append(str(erro))
        self.dados["portas_abertas"].sort(key=lambda item: (item["porta"], item["protocolo"]))

    def identificar_smb(self):
        if not shutil.which("nmap"):
            return
        try:
            comando = [
                "nmap", "-Pn", "-p", "139,445", "-sV", "--script",
                "smb-os-discovery,smb-security-mode,smb-protocols", self.alvo,
            ]
            resultado = executar(comando, max(30, self.tempo * 10))
            if resultado.returncode != 0:
                self.informar("Nmap não conseguiu identificar o serviço SMB.", "AVISO")
                return
            for linha in resultado.stdout.splitlines():
                if re.search(r"\bOS:\s*", linha):
                    self.dados["sistema_operacional"] = linha.strip().lstrip("|_ ")
                    break
            if self.detalhado:
                print(resultado.stdout[:2000])
        except (OSError, subprocess.TimeoutExpired) as erro:
            self.dados["erros"].append(f"Nmap SMB: {erro}")
            self.informar(f"Falha na identificação SMB: {erro}", "AVISO")

    def listar_compartilhamentos(self):
        if not shutil.which("smbclient"):
            return
        try:
            resultado = executar(["smbclient", "-g", "-L", f"//{self.alvo}/", "-N"],
                                max(15, self.tempo * 10))
            if resultado.returncode != 0:
                self.informar("Não foi possível listar compartilhamentos anonimamente.", "AVISO")
                return
            for linha in resultado.stdout.splitlines():
                campos = linha.strip().split("|", 2)
                if len(campos) != 3:
                    continue
                tipo, nome, comentario = campos
                if tipo not in ("Disk", "IPC", "Printer") or not nome:
                    continue
                self.dados["compartilhamentos"].append({
                    "nome": nome, "tipo": tipo, "comentario": comentario
                })
            self.informar(
                f"{len(self.dados['compartilhamentos'])} compartilhamento(s) listado(s). "
                "A listagem não comprova permissão de acesso.", "INFO"
            )
        except (OSError, subprocess.TimeoutExpired) as erro:
            self.dados["erros"].append(f"smbclient: {erro}")
            self.informar(f"Falha na listagem: {erro}", "AVISO")

    def verificar_ms17_010(self):
        if not shutil.which("nmap"):
            return
        try:
            resultado = executar(
                ["nmap", "-Pn", "-p", "445", "--script", "smb-vuln-ms17-010", self.alvo],
                max(30, self.tempo * 10),
            )
            if resultado.returncode != 0:
                self.dados["ms17_010"] = "inconclusivo"
            else:
                self.dados["ms17_010"] = situacao_vulnerabilidade(resultado.stdout)
            estado = self.dados["ms17_010"]
            self.informar(f"Verificação MS17-010: {estado.replace('_', ' ')}",
                         "ALERTA" if estado == "vulneravel" else "INFO")
        except (OSError, subprocess.TimeoutExpired) as erro:
            self.dados["ms17_010"] = "inconclusivo"
            self.dados["erros"].append(f"MS17-010: {erro}")
            self.informar("Verificação MS17-010 inconclusiva.", "AVISO")

    def relatorios(self):
        if self.saida:
            arquivo_json = Path(self.saida)
            if arquivo_json.suffix.lower() != ".json":
                arquivo_json = arquivo_json.with_suffix(".json")
        else:
            agora = datetime.now().strftime("%Y%m%d_%H%M%S")
            arquivo_json = Path(f"zero_scan_{self.alvo}_{agora}.json")
        arquivo_txt = arquivo_json.with_suffix(".txt")
        arquivo_json.parent.mkdir(parents=True, exist_ok=True)
        relatorio = {
            "programa": f"ZERO Scanner {VERSAO}",
            "autor": "Rodrigo Segobia",
            "repositorio": REPOSITORIO,
            "alvo": self.alvo,
            "data": datetime.now().isoformat(timespec="seconds"),
            "modo": self.modo,
            "resultados": self.dados,
            "observacao": "Resultados indicativos; inconclusivo não significa seguro.",
        }
        arquivo_json.write_text(json.dumps(relatorio, ensure_ascii=False, indent=2),
                                encoding="utf-8")
        texto = [
            "ZERO SCANNER - RELATÓRIO DE SEGURANÇA",
            f"Autor: Rodrigo Segobia | {REPOSITORIO}",
            f"Alvo: {self.alvo}",
            f"Modo: {self.modo}",
            f"Data: {relatorio['data']}",
            f"Portas verificadas: {self.dados['total_portas_verificadas']}",
            f"Portas com resposta: {len(self.dados['portas_abertas'])}",
            f"Compartilhamentos listados: {len(self.dados['compartilhamentos'])}",
            f"MS17-010: {self.dados['ms17_010']}",
            f"Sistema operacional: {self.dados['sistema_operacional'] or 'não identificado'}",
            "",
            "PORTAS COM RESPOSTA:",
        ]
        texto.extend(
            f"  {item['porta']}/{item['protocolo']} - {item['servico']}"
            for item in self.dados["portas_abertas"]
        )
        texto.append("\nCOMPARTILHAMENTOS LISTADOS (ACESSO NÃO CONFIRMADO):")
        texto.extend(
            f"  {item['nome']} ({item['tipo']}) - {item['comentario']}"
            for item in self.dados["compartilhamentos"]
        )
        texto.extend([
            "\nRECOMENDAÇÕES:",
            "  Revisar permissões SMB, atualizações de segurança e serviços expostos.",
            "  Avaliar assinatura SMB e desativação de SMBv1 quando aplicável.",
            "  Repetir testes inconclusivos com ferramentas e permissões adequadas.",
            "\nO resultado não substitui uma auditoria de segurança completa.",
        ])
        arquivo_txt.write_text("\n".join(texto) + "\n", encoding="utf-8")
        self.informar(f"Relatórios salvos: {arquivo_json} e {arquivo_txt}", "OK")

    def executar(self):
        self.verificar_ferramentas()
        self.verificar_portas()
        smb_aberto = any(item["porta"] in (139, 445) and
                         item["protocolo"] == "tcp"
                         for item in self.dados["portas_abertas"])
        if smb_aberto or self.forcar:
            self.identificar_smb()
            self.listar_compartilhamentos()
            self.verificar_ms17_010()
        else:
            self.informar("SMB não identificado como aberto; verificações SMB ignoradas.", "AVISO")
        self.resumo()
        if self.salvar:
            self.relatorios()
        return self.dados

    def resumo(self):
        self.informar(
            f"Resumo: {len(self.dados['portas_abertas'])}/"
            f"{self.dados['total_portas_verificadas']} portas com resposta; "
            f"{len(self.dados['compartilhamentos'])} compartilhamentos; "
            f"MS17-010: {self.dados['ms17_010']}.", "INFO"
        )
        print("Aviso: portas UDP sem resposta e testes SMB inconclusivos não comprovam segurança.")


def solicitar_alvo():
    while True:
        alvo = input("IP ou nome do host autorizado (Enter para cancelar): ").strip()
        if not alvo:
            return None
        if validar_alvo(alvo):
            return alvo
        print("Alvo inválido. Use IPv4 ou nome de host, sem espaços ou parâmetros.")


def pos_varredura(alvo, dados, tempo=30):
    if not alvo:
        print("Faça uma varredura antes de acessar estas opções.")
        return
    while True:
        print("\nPÓS-VARREDURA")
        print("[1] Enumeração com enum4linux/enum4linux-ng")
        print("[2] Testar listagem anônima dos compartilhamentos encontrados")
        print("[3] Verificações adicionais de vulnerabilidades SMB")
        print("[4] Exibir comandos para análise manual")
        print("[5] Voltar")
        escolha = input("Opção: ").strip()
        if escolha == "5":
            return
        if escolha == "1":
            base, opcao = resolver_enum4linux()
            if not base:
                print("enum4linux ou enum4linux-ng não encontrado.")
                continue
            try:
                retorno = executar(base + [opcao, alvo], max(60, tempo * 10))
                print((retorno.stdout or retorno.stderr)[:10000])
            except (OSError, subprocess.TimeoutExpired) as erro:
                print(f"Falha na enumeração: {erro}")
        elif escolha == "2":
            if not shutil.which("smbclient"):
                print("Instale smbclient para testar acesso anônimo.")
                continue
            compartilhamentos = dados.get("compartilhamentos", [])
            if not compartilhamentos:
                print("Nenhum compartilhamento foi listado.")
            for item in compartilhamentos[:5]:
                nome = item["nome"]
                try:
                    retorno = executar(["smbclient", f"//{alvo}/{nome}", "-N", "-c", "ls"], 15)
                    print(f"{nome}: {'acesso permitido' if retorno.returncode == 0 else 'acesso não confirmado/negado'}")
                except (OSError, subprocess.TimeoutExpired) as erro:
                    print(f"{nome}: falha ({erro})")
        elif escolha == "3":
            if not shutil.which("nmap"):
                print("Instale nmap para verificar vulnerabilidades.")
                continue
            for script in ("smb-vuln-ms17-010", "smb-vuln-ms10-054",
                           "smb-vuln-ms10-061", "smb-vuln-cve-2017-7494"):
                try:
                    retorno = executar(["nmap", "-Pn", "-p", "445", "--script", script, alvo], 90)
                    status = (situacao_vulnerabilidade(retorno.stdout)
                              if retorno.returncode == 0 else "inconclusivo")
                    print(f"{script}: {status}")
                except (OSError, subprocess.TimeoutExpired):
                    print(f"{script}: inconclusivo")
        elif escolha == "4":
            comandos = [
                f"nmap -Pn -sV -p 139,445 {alvo}",
                f"nmap -Pn -p 445 --script smb-protocols {alvo}",
                f"nmap -Pn -p 445 --script smb-vuln-ms17-010 {alvo}",
                f"smbclient -L //{alvo}/ -N",
            ]
            print("\n".join(comandos))
        else:
            print("Opção inválida.")


def modo_interativo(sem_banner=False):
    ultimo_alvo, ultimos_dados = None, {}
    tempo, threads = 3, 10
    while True:
        if not sem_banner:
            print(f"\nZERO Scanner v{VERSAO} | Rodrigo Segobia")
        print("\n[1] Varredura rápida SMB (139 e 445/TCP)")
        print("[2] Varredura avançada ou portas personalizadas")
        print("[3] Ajustar tempo limite e número de threads")
        print("[4] Ferramentas pós-varredura")
        print("[5] Sair")
        escolha = input("Opção: ").strip()
        if escolha == "5":
            print("Obrigado por utilizar o ZERO Scanner. Rodrigo Segobia.")
            return
        if escolha == "3":
            try:
                tempo = int(input("Tempo por porta em segundos (1-30): "))
                threads = int(input("Threads simultâneas (1-50): "))
                if not (1 <= tempo <= 30 and 1 <= threads <= 50):
                    raise ValueError()
            except ValueError:
                print("Valores inválidos; padrões restaurados.")
                tempo, threads = 3, 10
            continue
        if escolha == "4":
            pos_varredura(ultimo_alvo, ultimos_dados)
            continue
        if escolha not in ("1", "2"):
            print("Opção inválida.")
            continue
        alvo = solicitar_alvo()
        if not alvo:
            continue
        modo, portas, forcar = "basic", None, False
        if escolha == "2":
            escolha_modo = input("Modo [1] básico [2] completo [3] personalizado: ").strip()
            if escolha_modo == "2":
                modo = "full"
            elif escolha_modo == "3":
                modo = "custom"
                try:
                    portas = analisar_portas(input("Portas (ex.: 139,445,8000-8005): "))
                except ValueError as erro:
                    print(erro)
                    continue
            elif escolha_modo != "1":
                print("Modo inválido.")
                continue
            forcar = input("Executar testes SMB mesmo sem resposta em 139/445? (s/N): ").strip().lower() == "s"
        resposta = input("Salvar relatório JSON e TXT? (S/n): ").strip().lower()
        salvar = resposta != "n"
        saida = None
        if salvar:
            saida = input("Caminho do JSON (Enter para gerar nome): ").strip() or None
        scanner = Scanner(alvo, modo=modo, portas=portas, saida=saida,
                          detalhado=(escolha == "2"), forcar=forcar,
                          tempo=tempo, threads=threads, salvar=salvar)
        try:
            ultimos_dados = scanner.executar()
            ultimo_alvo = alvo
        except (OSError, ValueError) as erro:
            print(f"Erro na varredura: {erro}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="ZERO Scanner: varredura de portas e análise SMB autorizada."
    )
    parser.add_argument("target", nargs="?", help="IPv4 ou nome DNS do alvo")
    parser.add_argument("-m", "--mode", choices=("basic", "full", "custom"),
                        default="basic", help="Modo: basic, full ou custom")
    parser.add_argument("-p", "--ports", help="Portas TCP para o modo custom")
    parser.add_argument("-o", "--output", help="Caminho de saída do relatório JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Exibir detalhes")
    parser.add_argument("-f", "--force", action="store_true",
                        help="Tentar verificação SMB mesmo sem portas SMB abertas")
    parser.add_argument("-i", "--interactive", action="store_true", help="Abrir menu")
    parser.add_argument("--no-banner", action="store_true", help="Ocultar cabeçalho no menu")
    parser.add_argument("--no-report", action="store_true", help="Não salvar relatórios")
    parser.add_argument("--timeout", type=int, default=3, help="Tempo por porta (1-30 s)")
    parser.add_argument("--threads", type=int, default=10, help="Threads (1-50)")
    args = parser.parse_args(argv)

    if args.interactive or args.target is None:
        modo_interativo(sem_banner=args.no_banner)
        return 0
    if not validar_alvo(args.target):
        parser.error("alvo inválido: informe IPv4 ou nome DNS válido")
    if not (1 <= args.timeout <= 30 and 1 <= args.threads <= 50):
        parser.error("timeout deve estar entre 1 e 30 e threads entre 1 e 50")
    if args.mode != "custom" and args.ports:
        parser.error("-p/--ports só pode ser usado com -m custom")
    if args.mode == "custom" and not args.ports:
        parser.error("o modo custom exige -p/--ports")
    try:
        portas = analisar_portas(args.ports) if args.mode == "custom" else None
        scanner = Scanner(args.target, modo=args.mode, portas=portas,
                          saida=args.output, detalhado=args.verbose,
                          forcar=args.force, tempo=args.timeout,
                          threads=args.threads, salvar=not args.no_report)
        scanner.executar()
    except (ValueError, OSError) as erro:
        parser.error(str(erro))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nOperação interrompida pelo usuário.")
        sys.exit(130)
