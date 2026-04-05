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
  <strong>Coletor de evidências forenses pra Linux</strong>
  <br>
  <em>Todo sistema deixa um rastro. Pentefino encontra.</em>
  <br><br>
  <a href="#instalação"><img src="https://img.shields.io/badge/plataforma-Linux-blue?style=flat-square&logo=linux&logoColor=white" alt="Plataforma"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licença-GPLv3-green?style=flat-square" alt="Licença"></a>
  <a href="#"><img src="https://img.shields.io/badge/versão-3.1-orange?style=flat-square" alt="Versão"></a>
  <a href="#"><img src="https://img.shields.io/badge/bash-4.0+-yellow?style=flat-square&logo=gnubash&logoColor=white" alt="Bash"></a>
  <a href="#"><img src="https://img.shields.io/badge/dependências-zero-brightgreen?style=flat-square" alt="Zero Dependências"></a>
</p>

---

Fiz o Pentefino porque precisava de uma ferramenta pra coletar evidências de servidores Linux de forma organizada, sem pagar milhares de dólares em licença comercial e sem ter que ficar juntando scripts soltos toda vez.

É um script único com menu interativo. Roda no servidor alvo, coleta tudo que importa em ordem de volatilidade (seguindo a RFC 3227), gera hash SHA256 de cada arquivo pra cadeia de custódia e joga tudo pra um pendrive.

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
  2) Coleta rápida    (tudo automático, sem imagem de disco)
  3) Verificar ferramentas instaladas
  4) Sobre / ajuda
  0) Sair

  >>> Opção:
```

---

## Por que eu fiz isso

Ferramentas comerciais tipo EnCase e AXIOM custam $2.500-5.000 por ano. Scripts soltos não têm padrão, esquecem de coletar coisa importante e não geram hash pra custódia.

| | Ferramentas comerciais | Scripts soltos | **Pentefino** |
|---|---|---|---|
| Custo | $2.500-5.000/ano | Grátis | **Grátis** |
| Hash pra custódia | Sim | Às vezes | **Sim (SHA256)** |
| Dados voláteis primeiro | Sim | Raramente | **Sim (RFC 3227)** |
| Menu interativo | Sim | Não | **Sim** |
| Roda nativo no Linux | Muitas vezes não | Sim | **Sim** |
| Arquivo único | Não | Às vezes | **Sim** |
| Recupera deletados | Sim | Raramente | **Sim** |
| Detecta PID oculto | Alguns | Não | **Sim** |
| Comprime saída | Alguns | Não | **Automático (.gz)** |
| Open source | Não | Sim | **GPLv3** |

---

## O que ele faz

**Coleta**
- 13 fases de coleta em ordem de volatilidade (RAM > processos > rede > ... > disco)
- Dump completo da RAM via [AVML](https://github.com/microsoft/avml)
- Hash SHA256 de cada binário em execução
- Recupera arquivos deletados que ainda estão abertos
- Cópia completa do `/var/log` + journalctl
- Timeline do filesystem (mtime, atime, ctime) comprimida
- Imagem bit-a-bit do disco com dc3dd

**Detecção**
- Detecta PIDs ocultos (compara `/proc` com `ps`)
- Indicadores de rootkit (LD_PRELOAD, módulos kernel, binários deletados)
- Auditoria de SUID/SGID, arquivos world-writable, arquivos sem dono
- Identifica processos em Flatpak/Snap/Docker (não confunde com suspeito)
- Verifica binários modificados via `dpkg -V`

**Integridade**
- Hash SHA256 de cada arquivo coletado (cadeia de custódia)
- Log com timestamp e tamanho de cada operação
- Relatório com contadores de sucesso/parcial/falha
- Ctrl+C salva a coleta parcial com hashes

**Usabilidade**
- Menu interativo com checkboxes pra selecionar fases
- Detecta pendrives montados automaticamente
- Progresso em tempo real com porcentagem
- Comprime automático arquivos grandes (lsof, maps, timeline)
- Limite de tamanho pra arquivos recuperados (não lota o pendrive)
- Monitora espaço em disco durante a coleta
- Exporta como `.tar.gz` no final

---

## Como usar

### 1. Instalar dependências (uma vez)

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

Só isso. O menu guia o resto.

---

## Fases da coleta

Segue a [RFC 3227](https://datatracker.ietf.org/doc/html/rfc3227) - o que morre primeiro, coleta primeiro.

| # | Fase | O que coleta | Tempo |
|---|------|-------------|-------|
| 1 | **Sistema** | Data/hora, hostname, kernel, hardware, partições, montagens | ~5s |
| 2 | **RAM** | Dump completo da memória com AVML | ~2min |
| 3 | **Processos** | Árvore de processos, SHA256 de cada binário, file descriptors, maps de memória, variáveis de ambiente | ~30s |
| 4 | **Rede** | Conexões ativas (ss + netstat), interfaces, rotas, ARP, DNS, firewall | ~5s |
| 5 | **Usuários** | Logados, histórico de login, wtmp/btmp, passwd, shadow, sudoers, chaves SSH, bash_history | ~10s |
| 6 | **Arquivos** | Arquivos abertos (lsof), recuperação de deletados, modificados recentes, SUID/SGID, world-writable | ~1min |
| 7 | **Serviços** | Units systemd, habilitados, falhos, timers, crontabs, at jobs | ~10s |
| 8 | **Configurações** | Módulos kernel, sysctl, pacotes instalados, Docker, PAM, SSH config | ~10s |
| 9 | **Logs** | Cópia completa /var/log, journalctl (boot, auth, kernel), dmesg, audit | ~1min |
| 10 | **Persistência** | Init scripts, profiles/rc, LD_PRELOAD, binários suspeitos, detecção de PID oculto | ~15s |
| 11 | **Hashes** | SHA256 de todos binários em /usr/bin, /usr/sbin, /bin, /sbin, libs críticas, verificação dpkg | ~2min |
| 12 | **Timeline** | Timeline do filesystem: modificados (30d), acessados (7d), metadata (30d) em CSV comprimido | ~3min |
| 13 | **Imagem de disco** | Cópia bit-a-bit com dc3dd ou dd, SHA256 automático | varia |

---

## Estrutura da saída

```
forense_servidor01_2026-04-04_16-30-00_UTC/
|
|-- RELATORIO.txt               Resumo da coleta
|-- evidencia_hashes.sha256     SHA256 de cada arquivo (cadeia de custódia)
|-- coleta.log                  Log de execução com timestamps
|
|-- sistema/                    Info do sistema, hardware, kernel, discos
|-- memoria/                    Dump da RAM + metadados
|-- processos/                  Árvore, hashes de binários, fd, maps (.gz)
|-- rede/                       Conexões, interfaces, firewall, ARP
|-- usuarios/                   Contas, logins, SSH keys, histórico
|-- filesystem/                 Arquivos abertos (.gz), deletados, SUID
|   +-- recuperados/            Arquivos deletados recuperados
|-- servicos/                   Systemd, cron, at
|-- logs/                       Cópia /var/log + journalctl
|   +-- var_log/                Espelho completo do /var/log
|-- artefatos/                  Persistência, checks de rootkit
|-- hashes/                     SHA256 de binários do sistema
|-- timeline/                   Timelines do filesystem (.csv.gz)
+-- disco/                      Imagem do disco (opcional)
```

Só aparecem as pastas das fases que você selecionou. Diretórios vazios são removidos automaticamente.

---

## Cadeia de custódia

O Pentefino gera três arquivos de integridade:

| Arquivo | Pra que serve |
|---------|---------------|
| `evidencia_hashes.sha256` | Hash SHA256 de cada arquivo coletado |
| `coleta.log` | Log com timestamp de cada operação e tamanho dos arquivos |
| `RELATORIO.txt` | Resumo legível com contadores e estrutura |

Pra verificar integridade depois:

```bash
cd forense_servidor01_2026-04-04_16-30-00_UTC/
sha256sum -c evidencia_hashes.sha256
```

Tudo `OK` = nenhum arquivo foi alterado desde a coleta.

---

## Análise pós-coleta

### Memória (Volatility 3)

```bash
vol3 -f memoria/ram.lime linux.pslist        # processos que estavam rodando
vol3 -f memoria/ram.lime linux.bash          # comandos digitados no bash
vol3 -f memoria/ram.lime linux.netstat       # conexões de rede da memória
```

### Disco (Sleuth Kit / Autopsy)

```bash
mmls disco/disco.dd                                  # listar partições
fls -r -o 2048 disco/disco.dd                        # listar arquivos (+ deletados)
tsk_recover -o 2048 disco/disco.dd /tmp/recuperados/ # recuperar todos deletados
```

### Timeline

```bash
zcat timeline/timeline_mtime_30d.csv.gz | head -50           # olhada rápida
zgrep ",root," timeline/timeline_mtime_30d.csv.gz            # filtrar por usuário
zgrep "T0[2-4]:" timeline/timeline_mtime_30d.csv.gz          # horários suspeitos (madrugada)
```

### Investigar processos

```bash
grep "HASH=N/A" processos/ps_com_hash.txt                 # processos sem binário correspondente
grep "DELETED" processos/ps_com_hash.txt                   # processos com binário deletado
grep "FLATPAK\|DOCKER" processos/ps_com_hash.txt          # processos em sandbox
```

### Arquivos comprimidos

```bash
zcat filesystem/lsof.txt.gz | less                         # ver sem descomprimir
zgrep "suspeito" filesystem/lsof.txt.gz                    # buscar dentro do comprimido
gunzip processos/proc_maps.txt.gz                          # descomprimir permanente
```

---

## Configuração

Dá pra mudar os limites no topo do script:

```bash
MAX_RECUPERADO_MB=100       # tamanho máximo por arquivo recuperado (MB)
MAX_RECUPERADO_TOTAL_MB=500 # tamanho total máximo de recuperados (MB)
```

---

## Requisitos

- Linux (Debian/Ubuntu/Kali/Parrot ou RHEL/CentOS)
- Bash 4.0+
- Acesso root (sudo)
- Pendrive ou HD externo pro destino

**Ferramentas obrigatórias** (já vem na maioria das distros):
`ps`, `ss`, `lsof`, `sha256sum`, `find`, `cp`, `gzip`

**Ferramentas opcionais** (instala via `instalar_ferramentas.sh`):
`journalctl`, `systemctl`, `dc3dd`, `netstat`, `hashdeep`, `foremost`, `tshark`

**Pra captura de RAM:**
[AVML](https://github.com/microsoft/avml) (baixado automaticamente pelo instalador)

---

## Problemas comuns

| Problema | Solução |
|----------|---------|
| "Este script precisa ser executado como root" | `sudo bash pentefino.sh` |
| Captura de RAM falhou | Secure Boot bloqueia /dev/mem. Usa LiME ou desabilita Secure Boot |
| Muitos resultados `(parcial)` | Normal sem root. Sempre roda com `sudo` |
| Arquivos recuperados lotando o pendrive | Ajusta `MAX_RECUPERADO_MB` no script |
| `last`/`lastb` falhou | wtmp/btmp vazio ou corrompido. Os arquivos brutos ainda são copiados como `.bin` |
| Aviso de espaço durante coleta | Usa pendrive maior. Mínimo 16GB, 64GB+ se for capturar RAM + disco |

---

## Roadmap

- [ ] Coleta remota via SSH
- [ ] Relatório HTML com gráficos
- [ ] Integração com regras YARA
- [ ] Auto-análise do dump de RAM com Volatility 3
- [ ] Saída JSON pra SIEM
- [ ] Suporte multi-idioma (EN/PT)

---

## Contribuindo

Contribuições são bem-vindas. Abre uma issue antes de mandar mudança grande.

```bash
git clone https://github.com/Cassrche/pentefino.git
cd pentefino
# faz as mudanças no pentefino.sh
bash -n pentefino.sh              # checar sintaxe
sudo bash pentefino.sh            # testar
```

---

## Aviso legal

Pentefino é uma ferramenta de **coleta**, não de exploração. Ele lê dados de sistemas que você tem autorização pra acessar. Sempre garanta que tem autorização legal antes de coletar evidências de qualquer sistema.

Ferramenta fornecida como está pra investigação forense, resposta a incidentes, pesquisa de segurança e fins educacionais.

---

## Licença

[GPLv3](LICENSE) - Livre como tem que ser.

---

<p align="center">
  <strong>PENTEFINO</strong> &mdash; Todo sistema deixa um rastro.
  <br>
  <sub>Feito no Brasil</sub>
</p>
