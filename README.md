<p align="center">
  <br>
  <code>
   ██████╗ ███████╗███╗  ██╗████████╗███████╗███████╗██╗███╗  ██╗ ██████╗
   ██╔══██╗██╔════╝████╗ ██║╚══██╔══╝██╔════╝██╔════╝██║████╗ ██║██╔═══██╗
   ██████╔╝█████╗  ██╔██╗██║   ██║   █████╗  █████╗  ██║██╔██╗██║██║   ██║
   ██╔═══╝ ██╔══╝  ██║╚████║   ██║   ██╔══╝  ██╔══╝  ██║██║╚████║██║   ██║
   ██║     ███████╗██║ ╚███║   ██║   ███████╗██║     ██║██║ ╚███║╚██████╔╝
   ╚═╝     ╚══════╝╚═╝  ╚══╝   ╚═╝   ╚══════╝╚═╝     ╚═╝╚═╝  ╚══╝ ╚═════╝
  </code>
  <br><br>
  <strong>Coletor de evidencias forenses pra Linux</strong>
  <br>
  <em>Todo sistema deixa um rastro. Pentefino encontra.</em>
  <br><br>
  <a href="#instalacao"><img src="https://img.shields.io/badge/plataforma-Linux-blue?style=flat-square&logo=linux&logoColor=white" alt="Plataforma"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licenca-GPLv3-green?style=flat-square" alt="Licenca"></a>
  <a href="#"><img src="https://img.shields.io/badge/versao-3.1-orange?style=flat-square" alt="Versao"></a>
  <a href="#"><img src="https://img.shields.io/badge/bash-4.0+-yellow?style=flat-square&logo=gnubash&logoColor=white" alt="Bash"></a>
  <a href="#"><img src="https://img.shields.io/badge/dependencias-zero-brightgreen?style=flat-square" alt="Zero Dependencias"></a>
</p>

---

Fiz o Pentefino porque precisava de uma ferramenta pra coletar evidencias de servidores Linux de forma organizada, sem pagar milhares de dolares em licenca comercial e sem ter que ficar juntando scripts soltos toda vez.

E um script unico com menu interativo. Roda no servidor alvo, coleta tudo que importa em ordem de volatilidade (seguindo a RFC 3227), gera hash SHA256 de cada arquivo pra cadeia de custodia e joga tudo pra um pendrive.

```
$ sudo bash pentefino.sh

  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                               ║
  ║   ██████╗ ███████╗███╗  ██╗████████╗███████╗███████╗██╗███╗  ██╗ ██████╗  ║
  ║   ██╔══██╗██╔════╝████╗ ██║╚══██╔══╝██╔════╝██╔════╝██║████╗ ██║██╔═══██╗ ║
  ║   ██████╔╝█████╗  ██╔██╗██║   ██║   █████╗  █████╗  ██║██╔██╗██║██║   ██║ ║
  ║   ██╔═══╝ ██╔══╝  ██║╚████║   ██║   ██╔══╝  ██╔══╝  ██║██║╚████║██║   ██║ ║
  ║   ██║     ███████╗██║ ╚███║   ██║   ███████╗██║     ██║██║ ╚███║╚██████╔╝ ║
  ║   ╚═╝     ╚══════╝╚═╝  ╚══╝   ╚═╝   ╚══════╝╚═╝     ╚═╝╚═╝  ╚══╝ ╚═════╝  ║
  ║              Linux Forensic Evidence Collector  v3.1              ║
  ╚═══════════════════════════════════════════════════════════════╝

  MENU PRINCIPAL
  ────────────────────────────────────────────────────────

  1) Coleta completa (guiada passo a passo)
  2) Coleta rapida    (tudo automatico, sem imagem de disco)
  3) Verificar ferramentas instaladas
  4) Sobre / ajuda
  0) Sair

  >>> Opcao:
```

---

## Por que eu fiz isso

Ferramentas comerciais tipo EnCase e AXIOM custam $2.500-5.000 por ano. Scripts soltos nao tem padrao, esquecem de coletar coisa importante e nao geram hash pra custodia.

| | Ferramentas comerciais | Scripts soltos | **Pentefino** |
|---|---|---|---|
| Custo | $2.500-5.000/ano | Gratis | **Gratis** |
| Hash pra custodia | Sim | As vezes | **Sim (SHA256)** |
| Dados volateis primeiro | Sim | Raramente | **Sim (RFC 3227)** |
| Menu interativo | Sim | Nao | **Sim** |
| Roda nativo no Linux | Muitas vezes nao | Sim | **Sim** |
| Arquivo unico | Nao | As vezes | **Sim** |
| Recupera deletados | Sim | Raramente | **Sim** |
| Detecta PID oculto | Alguns | Nao | **Sim** |
| Comprime saida | Alguns | Nao | **Automatico (.gz)** |
| Open source | Nao | Sim | **GPLv3** |

---

## O que ele faz

**Coleta**
- 13 fases de coleta em ordem de volatilidade (RAM > processos > rede > ... > disco)
- Dump completo da RAM via [AVML](https://github.com/microsoft/avml)
- Hash SHA256 de cada binario em execucao
- Recupera arquivos deletados que ainda estao abertos
- Copia completa do `/var/log` + journalctl
- Timeline do filesystem (mtime, atime, ctime) comprimida
- Imagem bit-a-bit do disco com dc3dd

**Deteccao**
- Detecta PIDs ocultos (compara `/proc` com `ps`)
- Indicadores de rootkit (LD_PRELOAD, modulos kernel, binarios deletados)
- Auditoria de SUID/SGID, arquivos world-writable, arquivos sem dono
- Identifica processos em Flatpak/Snap/Docker (nao confunde com suspeito)
- Verifica binarios modificados via `dpkg -V`

**Integridade**
- Hash SHA256 de cada arquivo coletado (cadeia de custodia)
- Log com timestamp e tamanho de cada operacao
- Relatorio com contadores de sucesso/parcial/falha
- Ctrl+C salva a coleta parcial com hashes

**Usabilidade**
- Menu interativo com checkboxes pra selecionar fases
- Detecta pendrives montados automaticamente
- Progresso em tempo real com porcentagem
- Comprime automatico arquivos grandes (lsof, maps, timeline)
- Limite de tamanho pra arquivos recuperados (nao lota o pendrive)
- Monitora espaco em disco durante a coleta
- Exporta como `.tar.gz` no final

---

## Como usar

### 1. Instalar dependencias (uma vez)

```bash
git clone https://github.com/Cassrche/pentefino.git
cd pentefino
bash instalar_ferramentas.sh
```

### 2. Copiar pro pendrive

```bash
cp pentefino.sh /mnt/pendrive/
cp bin/avml /mnt/pendrive/    # opcional, pra captura de RAM
```

### 3. Rodar no servidor alvo

```bash
sudo bash /mnt/pendrive/pentefino.sh
```

So isso. O menu guia o resto.

---

## Fases da coleta

Segue a [RFC 3227](https://datatracker.ietf.org/doc/html/rfc3227) - o que morre primeiro, coleta primeiro.

| # | Fase | O que coleta | Tempo |
|---|------|-------------|-------|
| 1 | **Sistema** | Data/hora, hostname, kernel, hardware, particoes, montagens | ~5s |
| 2 | **RAM** | Dump completo da memoria com AVML | ~2min |
| 3 | **Processos** | Arvore de processos, SHA256 de cada binario, file descriptors, maps de memoria, variaveis de ambiente | ~30s |
| 4 | **Rede** | Conexoes ativas (ss + netstat), interfaces, rotas, ARP, DNS, firewall | ~5s |
| 5 | **Usuarios** | Logados, historico de login, wtmp/btmp, passwd, shadow, sudoers, chaves SSH, bash_history | ~10s |
| 6 | **Arquivos** | Arquivos abertos (lsof), recuperacao de deletados, modificados recentes, SUID/SGID, world-writable | ~1min |
| 7 | **Servicos** | Units systemd, habilitados, falhos, timers, crontabs, at jobs | ~10s |
| 8 | **Configuracoes** | Modulos kernel, sysctl, pacotes instalados, Docker, PAM, SSH config | ~10s |
| 9 | **Logs** | Copia completa /var/log, journalctl (boot, auth, kernel), dmesg, audit | ~1min |
| 10 | **Persistencia** | Init scripts, profiles/rc, LD_PRELOAD, binarios suspeitos, deteccao de PID oculto | ~15s |
| 11 | **Hashes** | SHA256 de todos binarios em /usr/bin, /usr/sbin, /bin, /sbin, libs criticas, verificacao dpkg | ~2min |
| 12 | **Timeline** | Timeline do filesystem: modificados (30d), acessados (7d), metadata (30d) em CSV comprimido | ~3min |
| 13 | **Imagem de disco** | Copia bit-a-bit com dc3dd ou dd, SHA256 automatico | varia |

---

## Estrutura da saida

```
forense_servidor01_2026-04-04_16-30-00_UTC/
|
|-- RELATORIO.txt               Resumo da coleta
|-- evidencia_hashes.sha256     SHA256 de cada arquivo (cadeia de custodia)
|-- coleta.log                  Log de execucao com timestamps
|
|-- sistema/                    Info do sistema, hardware, kernel, discos
|-- memoria/                    Dump da RAM + metadados
|-- processos/                  Arvore, hashes de binarios, fd, maps (.gz)
|-- rede/                       Conexoes, interfaces, firewall, ARP
|-- usuarios/                   Contas, logins, SSH keys, historico
|-- filesystem/                 Arquivos abertos (.gz), deletados, SUID
|   +-- recuperados/            Arquivos deletados recuperados
|-- servicos/                   Systemd, cron, at
|-- logs/                       Copia /var/log + journalctl
|   +-- var_log/                Espelho completo do /var/log
|-- artefatos/                  Persistencia, checks de rootkit
|-- hashes/                     SHA256 de binarios do sistema
|-- timeline/                   Timelines do filesystem (.csv.gz)
+-- disco/                      Imagem do disco (opcional)
```

So aparecem as pastas das fases que voce selecionou. Diretorios vazios sao removidos automaticamente.

---

## Cadeia de custodia

O Pentefino gera tres arquivos de integridade:

| Arquivo | Pra que serve |
|---------|---------------|
| `evidencia_hashes.sha256` | Hash SHA256 de cada arquivo coletado |
| `coleta.log` | Log com timestamp de cada operacao e tamanho dos arquivos |
| `RELATORIO.txt` | Resumo legivel com contadores e estrutura |

Pra verificar integridade depois:

```bash
cd forense_servidor01_2026-04-04_16-30-00_UTC/
sha256sum -c evidencia_hashes.sha256
```

Tudo `OK` = nenhum arquivo foi alterado desde a coleta.

---

## Analise pos-coleta

### Memoria (Volatility 3)

```bash
vol3 -f memoria/ram.lime linux.pslist        # processos que estavam rodando
vol3 -f memoria/ram.lime linux.bash          # comandos digitados no bash
vol3 -f memoria/ram.lime linux.netstat       # conexoes de rede da memoria
```

### Disco (Sleuth Kit / Autopsy)

```bash
mmls disco/disco.dd                                  # listar particoes
fls -r -o 2048 disco/disco.dd                        # listar arquivos (+ deletados)
tsk_recover -o 2048 disco/disco.dd /tmp/recuperados/ # recuperar todos deletados
```

### Timeline

```bash
zcat timeline/timeline_mtime_30d.csv.gz | head -50           # olhada rapida
zgrep ",root," timeline/timeline_mtime_30d.csv.gz            # filtrar por usuario
zgrep "T0[2-4]:" timeline/timeline_mtime_30d.csv.gz          # horarios suspeitos (madrugada)
```

### Investigar processos

```bash
grep "HASH=N/A" processos/ps_com_hash.txt                 # processos sem binario correspondente
grep "DELETED" processos/ps_com_hash.txt                   # processos com binario deletado
grep "FLATPAK\|DOCKER" processos/ps_com_hash.txt          # processos em sandbox
```

### Arquivos comprimidos

```bash
zcat filesystem/lsof.txt.gz | less                         # ver sem descomprimir
zgrep "suspeito" filesystem/lsof.txt.gz                    # buscar dentro do comprimido
gunzip processos/proc_maps.txt.gz                          # descomprimir permanente
```

---

## Configuracao

Da pra mudar os limites no topo do script:

```bash
MAX_RECUPERADO_MB=100       # tamanho maximo por arquivo recuperado (MB)
MAX_RECUPERADO_TOTAL_MB=500 # tamanho total maximo de recuperados (MB)
```

---

## Requisitos

- Linux (Debian/Ubuntu/Kali/Parrot ou RHEL/CentOS)
- Bash 4.0+
- Acesso root (sudo)
- Pendrive ou HD externo pro destino

**Ferramentas obrigatorias** (ja vem na maioria das distros):
`ps`, `ss`, `lsof`, `sha256sum`, `find`, `cp`, `gzip`

**Ferramentas opcionais** (instala via `instalar_ferramentas.sh`):
`journalctl`, `systemctl`, `dc3dd`, `netstat`, `hashdeep`, `foremost`, `tshark`

**Pra captura de RAM:**
[AVML](https://github.com/microsoft/avml) (baixado automaticamente pelo instalador)

---

## Problemas comuns

| Problema | Solucao |
|----------|---------|
| "Este script precisa ser executado como root" | `sudo bash pentefino.sh` |
| Captura de RAM falhou | Secure Boot bloqueia /dev/mem. Usa LiME ou desabilita Secure Boot |
| Muitos resultados `(parcial)` | Normal sem root. Sempre roda com `sudo` |
| Arquivos recuperados lotando o pendrive | Ajusta `MAX_RECUPERADO_MB` no script |
| `last`/`lastb` falhou | wtmp/btmp vazio ou corrompido. Os arquivos brutos ainda sao copiados como `.bin` |
| Aviso de espaco durante coleta | Usa pendrive maior. Minimo 16GB, 64GB+ se for capturar RAM + disco |

---

## Roadmap

- [ ] Coleta remota via SSH
- [ ] Relatorio HTML com graficos
- [ ] Integracao com regras YARA
- [ ] Auto-analise do dump de RAM com Volatility 3
- [ ] Saida JSON pra SIEM
- [ ] Suporte multi-idioma (EN/PT)

---

## Contribuindo

Contribuicoes sao bem-vindas. Abre uma issue antes de mandar mudanca grande.

```bash
git clone https://github.com/Cassrche/pentefino.git
cd pentefino
# faz as mudancas no pentefino.sh
bash -n pentefino.sh              # checar sintaxe
sudo bash pentefino.sh            # testar
```

---

## Aviso legal

Pentefino e uma ferramenta de **coleta**, nao de exploracao. Ele le dados de sistemas que voce tem autorizacao pra acessar. Sempre garanta que tem autorizacao legal antes de coletar evidencias de qualquer sistema.

Ferramenta fornecida como esta pra investigacao forense, resposta a incidentes, pesquisa de seguranca e fins educacionais.

---

## Licenca

[GPLv3](LICENSE) - Livre como tem que ser.

---

<p align="center">
  <strong>PENTEFINO</strong> &mdash; Todo sistema deixa um rastro.
  <br>
  <sub>Feito no Brasil</sub>
</p>
