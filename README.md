<div align="center">

# 🔍 ZERO Scanner

**Ferramenta de análise de portas e serviços SMB para ambientes autorizados**

**Desenvolvimento e manutenção: Rodrigo Segobia**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![Licença](https://img.shields.io/badge/Licen%C3%A7a-MIT-green)](LICENSE)
[![Plataforma](https://img.shields.io/badge/Plataforma-Linux%20%7C%20WSL-informational)](https://github.com/rodrigosegobia/zero-scanner)
[![Versão](https://img.shields.io/badge/Vers%C3%A3o-1.1.0-blueviolet)](zero_scanner.py)

[Repositório](https://github.com/rodrigosegobia/zero-scanner) · [Problemas e sugestões](https://github.com/rodrigosegobia/zero-scanner/issues)

</div>

## Sobre o projeto

O **ZERO Scanner** é uma ferramenta em Python para **identificar portas e analisar serviços SMB** em sistemas para os quais você tenha autorização de teste. Oferece execução pelo terminal ou menu interativo, consultas opcionais com Nmap e smbclient, exportação de resultados e ferramentas de acompanhamento.

O projeto foi reorganizado para disponibilizar a interface e a documentação em **português brasileiro**, melhorar as validações e evitar que a ausência de uma confirmação seja apresentada como prova de que um sistema está seguro.

> **Atenção:** o ZERO Scanner é uma ferramenta de apoio à análise. Ele não comprova a segurança de um host, não substitui uma avaliação profissional e pode produzir resultados **inconclusivos**, especialmente em verificações UDP e de vulnerabilidades. **Use exclusivamente em sistemas próprios ou com autorização expressa.**

## Funcionalidades implementadas

- **Varredura básica:** verifica **139/TCP** (NetBIOS) e **445/TCP** (SMB).
- **Varredura completa:** verifica **12 combinações de porta/protocolo** relacionadas a SMB, Active Directory e serviços associados (TCP e UDP).
- **Varredura personalizada:** verifica portas **TCP** informadas pelo usuário, inclusive intervalos.
- **Identificação de SMB:** utiliza Nmap, quando disponível, para coletar informações de serviço, protocolos e sistema operacional (se fornecidas pelo alvo).
- **Compartilhamentos SMB:** utiliza smbclient para tentar listar compartilhamentos **sem autenticação**. Encontrar um compartilhamento **não significa ter acesso ao seu conteúdo**.
- **MS17-010 (EternalBlue):** executa o script NSE correspondente do Nmap, quando possível, e registra um resultado **vulnerável**, **não vulnerável** (quando explicitamente informado), **inconclusivo** ou **não testado**.
- **Ferramentas pós-varredura:** enumeração opcional com enum4linux/enum4linux-ng, teste de acesso anônimo a até cinco compartilhamentos listados, verificações NSE adicionais e comandos para inspeção manual.
- **Relatórios:** geração de arquivos **JSON** e **TXT**, ambos com dados da execução e autoria identificada.
- **Configuração:** ajuste de timeout por porta, quantidade de threads, modo detalhado e opção de forçar verificações SMB.

### Limitações importantes

- A varredura de portas TCP usa conexões de socket. **Sem resposta ou conexão recusada não diferencia todos os possíveis estados de firewall/rede.**
- Portas UDP que não respondem são **inconclusivas**, e não necessariamente fechadas ou abertas.
- A listagem de compartilhamentos depende de acesso anônimo permitido pelo servidor.
- A ausência de detecção de MS17-010 **não comprova ausência de vulnerabilidades**. Resultados não explícitos do Nmap são registrados como inconclusivos.
- A identificação do sistema operacional depende da resposta dos scripts NSE; ela pode não estar disponível.
- **Não há exploração automática de falhas, adivinhação de senhas nem ataque de força bruta implementado nesta versão.**
- O modo personalizado aceita portas TCP, não intervalos CIDR, nem listas de múltiplos hosts.

## Requisitos

- **Python 3.8 ou superior**, recomendado em **Linux** ou **WSL**.
- O núcleo de verificação de portas usa somente bibliotecas padrão do Python.
- **Nmap**: recomendado para identificação SMB e verificações de vulnerabilidade.
- **smbclient**: recomendado para enumeração de compartilhamentos.
- **enum4linux** ou **enum4linux-ng**: opcional, para enumeração adicional no menu pós-varredura.

Os utilitários externos devem estar disponíveis no **PATH**. Para enum4linux-ng, também é reconhecido o script em `~/enum4linux-ng/enum4linux-ng.py` ou `~/tools/enum4linux-ng/enum4linux-ng.py`, quando houver `python3` no PATH.

No Ubuntu, Debian ou Kali Linux, por exemplo:

```bash
sudo apt-get update
sudo apt-get install -y python3 nmap smbclient
```

A disponibilidade e os nomes dos pacotes podem variar entre distribuições. Para funções adicionais, instale separadamente enum4linux ou enum4linux-ng conforme a documentação do projeto correspondente.

## Instalação

```bash
git clone https://github.com/rodrigosegobia/zero-scanner.git
cd zero-scanner
python3 zero_scanner.py --help
```

Não é necessário executar `pip install` para o código principal.

## Como usar

### Menu interativo

Execute sem argumentos:

```bash
python3 zero_scanner.py
```

O menu inclui varredura rápida, avançada, configurações de tempo e threads, ferramentas pós-varredura e saída.

### Linha de comando

Para executar contra um host do seu laboratório:

```bash
# Portas SMB principais
python3 zero_scanner.py 192.168.1.100

# Verificação completa e saída detalhada
python3 zero_scanner.py 192.168.1.100 -m full -v

# Portas TCP personalizadas
python3 zero_scanner.py 192.168.1.100 -m custom -p "135,139,445,8000-8005"

# Salvar relatórios em um caminho definido
python3 zero_scanner.py 192.168.1.100 -o relatorios/laboratorio.json

# Não gerar arquivos de relatório
python3 zero_scanner.py 192.168.1.100 --no-report

# Tentar a análise SMB mesmo sem identificar 139/445 abertas
python3 zero_scanner.py 192.168.1.100 -f

# Ajustar concorrência e timeout
python3 zero_scanner.py 192.168.1.100 --threads 5 --timeout 4
```

A opção `-f` **não burla firewalls ou controles de acesso**: apenas permite tentar as consultas SMB adicionais mesmo quando a verificação de portas não obteve resposta positiva.

| Opção | Função |
| --- | --- |
| `target` | IPv4 ou nome de host autorizado |
| `-m, --mode` | `basic`, `full` ou `custom` |
| `-p, --ports` | Portas TCP, obrigatório em `custom` (até 4096 por execução) |
| `-o, --output` | Destino do relatório JSON; o TXT usa o mesmo nome-base |
| `-v, --verbose` | Exibe detalhes da verificação |
| `-f, --force` | Tenta consultas SMB adicionais mesmo sem portas SMB confirmadas |
| `-i, --interactive` | Abre o menu interativo |
| `--no-banner` | Oculta o cabeçalho no menu |
| `--no-report` | Não cria os relatórios JSON e TXT |
| `--timeout` | Tempo por porta, de 1 a 30 segundos (padrão: 3) |
| `--threads` | Threads simultâneas, de 1 a 50 (padrão: 10) |
| `-h, --help` | Exibe todas as opções |

O programa salva, por padrão, os dois relatórios no diretório atual usando nomes como `zero_scan_192.168.1.100_20261012_140000.json` e `.txt`. Com `-o`, o caminho indicado substitui o nome automático.

### Entendendo os resultados

Exemplo **ilustrativo**, não extraído de uma execução real:

```text
[14:00:00] [INFO] Verificando 2 portas no alvo 192.168.1.100...
[14:00:01] [OK] 445/tcp (SMB): aberta
[14:00:02] [INFO] 2 compartilhamento(s) listado(s). A listagem não comprova permissão de acesso.
[14:00:03] [INFO] Verificação MS17-010: inconclusivo
[14:00:03] [INFO] Resumo: 1/2 portas com resposta; 2 compartilhamentos; MS17-010: inconclusivo.
```

Estados usados no campo `ms17_010` do JSON:

| Valor | Interpretação |
| --- | --- |
| `vulneravel` | O script Nmap retornou explicitamente o estado vulnerável |
| `nao_vulneravel` | O script Nmap retornou explicitamente o estado não vulnerável |
| `inconclusivo` | Não houve confirmação válida ou a execução falhou |
| `nao_testado` | A verificação não chegou a ser executada |

É importante distinguir **porta acessível**, **serviço identificado** e **vulnerabilidade confirmada**. São evidências diferentes.

## Estrutura do repositório

```text
zero-scanner/
├── zero_scanner.py       # Aplicação principal
├── tests/
│   └── test_zero_scanner.py  # Testes automatizados sem varreduras reais
├── README.md             # Documentação em português
├── LICENSE               # Licença MIT
└── ZeroScanner.exe       # Binário legado existente no repositório
```

**Observação sobre `ZeroScanner.exe`:** este executável já estava presente no repositório e **não foi recompilado nem auditado nesta atualização**. Portanto, não há garantia de que corresponda à versão atual do código Python. Para utilizar a versão documentada aqui, execute diretamente `zero_scanner.py`. Não considere o executável como uma versão testada ou oficialmente atualizada nesta revisão.

## Testes e contribuições

Para executar os testes locais sem realizar varreduras na rede:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile zero_scanner.py
```

Abra [uma issue](https://github.com/rodrigosegobia/zero-scanner/issues) descrevendo o problema, seu sistema operacional, a versão do Python, o comando utilizado (removendo informações sensíveis) e o resultado esperado.

Contribuições devem preservar o comportamento seguro de execução **sem `shell=True`**, a validação de entradas e a distinção entre falha de detecção e ausência comprovada de uma vulnerabilidade.

## Segurança e uso responsável

O projeto destina-se **somente a testes autorizados**. Garanta permissão explícita antes de analisar ativos de terceiros; respeite a legislação e as políticas de cada ambiente. Nunca publique relatórios com endereços internos, compartilhamentos ou outras informações sensíveis sem autorização.

As informações produzidas são auxiliares e não garantem que um sistema esteja protegido contra ataques. Execute os testes com cuidado, pois consultas de rede podem gerar registros ou afetar serviços com capacidade limitada.

## Autoria e licença

**Desenvolvimento e manutenção desta versão:** [Rodrigo Segobia](https://github.com/rodrigosegobia).

Distribuído sob a licença [MIT](LICENSE). O aviso de copyright anteriormente presente na licença é mantido para preservar a atribuição da versão original; modificações posteriores têm sua autoria indicada na documentação e nos arquivos modificados.

---

<div align="center">

**ZERO Scanner · Rodrigo Segobia**

[GitHub](https://github.com/rodrigosegobia/zero-scanner) · [Issues](https://github.com/rodrigosegobia/zero-scanner/issues)

</div>
