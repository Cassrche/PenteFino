#!/bin/bash
# ============================================================================
#
#   PENTEFINO - Linux Forensic Evidence Collector
#   v3.1 | github.com/SEU_USER/pentefino
#
#   Uso: sudo bash pentefino.sh
#
# ============================================================================

# ======================= CORES E SIMBOLOS =======================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

TICK="${GREEN}[+]${NC}"
CROSS="${RED}[-]${NC}"
WARN="${YELLOW}[!]${NC}"
INFO="${CYAN}[*]${NC}"
ARROW="${MAGENTA}>>>${NC}"

# ======================= VARIAVEIS GLOBAIS =======================

VERSAO="3.1"
MAX_RECUPERADO_MB=100       # Limite por arquivo recuperado (MB)
MAX_RECUPERADO_TOTAL_MB=500 # Limite total de recuperados (MB)
HOSTNAME_ALVO=$(hostname)
DATA_INICIO=""
TIMESTAMP_INICIO=""
CASO_DIR=""
LOG=""
DESTINO=""
DISCO_ALVO=""
AVML_PATH=""
FASES_SELECIONADAS=()
TOTAL_ETAPAS=0
ETAPA_ATUAL=0
CONTAGEM_OK=0
CONTAGEM_WARN=0
CONTAGEM_ERRO=0
COLETA_INTERROMPIDA=0

# ======================= TRAP CTRL+C =======================

cleanup() {
    # Desabilitar trap para evitar multiplas execucoes
    trap - SIGINT SIGTERM
    COLETA_INTERROMPIDA=1
    echo ""
    echo ""
    echo -e "  ${RED}${BOLD}COLETA INTERROMPIDA PELO USUARIO (Ctrl+C)${NC}"
    echo ""

    if [ -n "$CASO_DIR" ] && [ -d "$CASO_DIR" ]; then
        echo -e "  ${INFO} Salvando estado parcial..."
        echo "[$(date -u +%H:%M:%S)] INTERROMPIDO: Ctrl+C pelo usuario" >> "$LOG" 2>/dev/null

        # Limpar arquivos vazios da coleta parcial
        find "$CASO_DIR" -type f -empty -not -name "coleta.log" -delete 2>/dev/null
        find "$CASO_DIR" -mindepth 1 -type d -empty -delete 2>/dev/null

        # Gerar hashes do que ja foi coletado
        find "$CASO_DIR" -type f \
            -not -name "evidencia_hashes.sha256" \
            -not -name "coleta.log" \
            -exec sha256sum {} \; > "$CASO_DIR/evidencia_hashes.sha256" 2>/dev/null

        echo -e "  ${WARN} Coleta parcial salva em: ${CYAN}$CASO_DIR${NC}"
        echo -e "  ${WARN} Verifique o log: $CASO_DIR/coleta.log"
    fi
    echo ""
    exit 130
}

trap cleanup SIGINT SIGTERM

# ======================= FUNCOES UTILITARIAS =======================

limpar_tela() { clear; }

pausar() {
    echo ""
    echo -ne "  ${DIM}Pressione ENTER para continuar...${NC}"
    read -r
}

log_ok() {
    CONTAGEM_OK=$((CONTAGEM_OK + 1))
    echo -e "  ${TICK} $1"
    [ -n "$LOG" ] && echo "[$(date -u +%H:%M:%S)] OK: $1" >> "$LOG"
}

log_info() {
    echo -e "  ${INFO} $1"
    [ -n "$LOG" ] && echo "[$(date -u +%H:%M:%S)] INFO: $1" >> "$LOG"
}

log_warn() {
    CONTAGEM_WARN=$((CONTAGEM_WARN + 1))
    echo -e "  ${WARN} $1"
    [ -n "$LOG" ] && echo "[$(date -u +%H:%M:%S)] WARN: $1" >> "$LOG"
}

log_erro() {
    CONTAGEM_ERRO=$((CONTAGEM_ERRO + 1))
    echo -e "  ${CROSS} $1"
    [ -n "$LOG" ] && echo "[$(date -u +%H:%M:%S)] ERRO: $1" >> "$LOG"
}

executar() {
    local descricao="$1"
    local arquivo_saida="$2"
    shift 2
    local cmd="$*"

    ETAPA_ATUAL=$((ETAPA_ATUAL + 1))
    local pct=0
    [ "$TOTAL_ETAPAS" -gt 0 ] && pct=$((ETAPA_ATUAL * 100 / TOTAL_ETAPAS))

    # Barra de progresso inline (sobrescreve a linha)
    printf "\r  ${INFO} ${DIM}[%3d%%]${NC} %-50s" "$pct" "$descricao"

    if eval "$cmd" > "$arquivo_saida" 2>/dev/null; then
        # Verificar se gerou arquivo vazio
        if [ -s "$arquivo_saida" ]; then
            printf "\r  ${TICK} ${DIM}[%3d%%]${NC} %-50s\n" "$pct" "$descricao"
            CONTAGEM_OK=$((CONTAGEM_OK + 1))
            [ -n "$LOG" ] && echo "[$(date -u +%H:%M:%S)] OK: $descricao ($(du -h "$arquivo_saida" | cut -f1))" >> "$LOG"
        else
            # Arquivo vazio = sem dados, remover
            rm -f "$arquivo_saida"
            printf "\r  ${DIM}  [%3d%%] %-50s (vazio, ignorado)${NC}\n" "$pct" "$descricao"
            [ -n "$LOG" ] && echo "[$(date -u +%H:%M:%S)] SKIP: $descricao (sem dados)" >> "$LOG"
        fi
    else
        if [ -s "$arquivo_saida" ]; then
            printf "\r  ${WARN} ${DIM}[%3d%%]${NC} %-50s ${DIM}(parcial)${NC}\n" "$pct" "$descricao"
            CONTAGEM_WARN=$((CONTAGEM_WARN + 1))
            [ -n "$LOG" ] && echo "[$(date -u +%H:%M:%S)] WARN: $descricao (parcial, $(du -h "$arquivo_saida" | cut -f1))" >> "$LOG"
        else
            rm -f "$arquivo_saida"
            printf "\r  ${CROSS} ${DIM}[%3d%%]${NC} %-50s ${DIM}(falhou)${NC}\n" "$pct" "$descricao"
            CONTAGEM_ERRO=$((CONTAGEM_ERRO + 1))
            [ -n "$LOG" ] && echo "[$(date -u +%H:%M:%S)] ERRO: $descricao (falhou)" >> "$LOG"
        fi
    fi
}

# Executa e comprime saida grande (>5MB) automaticamente
executar_gz() {
    local descricao="$1"
    local arquivo_saida="$2"
    shift 2
    local cmd="$*"

    ETAPA_ATUAL=$((ETAPA_ATUAL + 1))
    local pct=0
    [ "$TOTAL_ETAPAS" -gt 0 ] && pct=$((ETAPA_ATUAL * 100 / TOTAL_ETAPAS))

    printf "\r  ${INFO} ${DIM}[%3d%%]${NC} %-50s" "$pct" "$descricao"

    if eval "$cmd" 2>/dev/null | gzip > "${arquivo_saida}.gz"; then
        local size=$(du -h "${arquivo_saida}.gz" | cut -f1)
        printf "\r  ${TICK} ${DIM}[%3d%%]${NC} %-50s ${DIM}(${size} gz)${NC}\n" "$pct" "$descricao"
        CONTAGEM_OK=$((CONTAGEM_OK + 1))
        [ -n "$LOG" ] && echo "[$(date -u +%H:%M:%S)] OK: $descricao ($size comprimido)" >> "$LOG"
    else
        rm -f "${arquivo_saida}.gz"
        printf "\r  ${CROSS} ${DIM}[%3d%%]${NC} %-50s ${DIM}(falhou)${NC}\n" "$pct" "$descricao"
        CONTAGEM_ERRO=$((CONTAGEM_ERRO + 1))
        [ -n "$LOG" ] && echo "[$(date -u +%H:%M:%S)] ERRO: $descricao (falhou)" >> "$LOG"
    fi
}

formatar_duracao() {
    local segundos=$1
    local horas=$((segundos / 3600))
    local minutos=$(( (segundos % 3600) / 60 ))
    local segs=$((segundos % 60))
    if [ "$horas" -gt 0 ]; then
        printf "%dh %dm %ds" "$horas" "$minutos" "$segs"
    elif [ "$minutos" -gt 0 ]; then
        printf "%dm %ds" "$minutos" "$segs"
    else
        printf "%ds" "$segs"
    fi
}

linha() {
    echo -e "  ${CYAN}$(printf '%.0s─' {1..56})${NC}"
}

# Verificar espaco livre no destino (retorna MB livres)
espaco_livre_mb() {
    df -BM "$CASO_DIR" 2>/dev/null | tail -1 | awk '{print $4}' | tr -d 'M'
}

# Aviso se espaco critico (<500MB)
verificar_espaco() {
    local livre=$(espaco_livre_mb)
    if [ -n "$livre" ] && [ "$livre" -lt 500 ]; then
        log_warn "ESPACO CRITICO: apenas ${livre}MB livres no destino!"
        echo "[$(date -u +%H:%M:%S)] WARN: Espaco critico - ${livre}MB livres" >> "$LOG"
    fi
}

# ======================= BANNER =======================

banner() {
    limpar_tela
    echo ""
    echo -e "  ${CYAN}${BOLD}"
    echo "  ╔═══════════════════════════════════════════════════════════════╗"
    echo "  ║                                                               ║"
    echo "  ║   ██████╗ ███████╗███╗  ██╗████████╗███████╗███████╗██╗███╗  ██╗ ██████╗  ║"
    echo "  ║   ██╔══██╗██╔════╝████╗ ██║╚══██╔══╝██╔════╝██╔════╝██║████╗ ██║██╔═══██╗ ║"
    echo "  ║   ██████╔╝█████╗  ██╔██╗██║   ██║   █████╗  █████╗  ██║██╔██╗██║██║   ██║ ║"
    echo "  ║   ██╔═══╝ ██╔══╝  ██║╚████║   ██║   ██╔══╝  ██╔══╝  ██║██║╚████║██║   ██║ ║"
    echo "  ║   ██║     ███████╗██║ ╚███║   ██║   ███████╗██║     ██║██║ ╚███║╚██████╔╝ ║"
    echo "  ║   ╚═╝     ╚══════╝╚═╝  ╚══╝   ╚═╝   ╚══════╝╚═╝     ╚═╝╚═╝  ╚══╝ ╚═════╝  ║"
    echo "  ║              Linux Forensic Evidence Collector  v${VERSAO}              ║"
    echo "  ║                                                               ║"
    echo "  ╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${DIM}$(date -u '+%Y-%m-%d %H:%M:%S UTC')${NC}"
    echo -e "  ${DIM}Host: ${HOSTNAME_ALVO} | User: $(whoami) | Kernel: $(uname -r)${NC}"
    echo ""
}

# ======================= VERIFICACAO DE ROOT =======================

verificar_root() {
    if [ "$(id -u)" -ne 0 ]; then
        banner
        echo -e "  ${CROSS} ${RED}Este script precisa ser executado como root.${NC}"
        echo ""
        echo -e "  Use: ${BOLD}sudo bash $0${NC}"
        echo ""
        exit 1
    fi
}

# ======================= VERIFICAR FERRAMENTAS =======================

verificar_ferramentas() {
    local obrig_ok=0
    local obrig_total=0
    local opt_ok=0

    echo -e "\n  ${BOLD}Ferramentas obrigatorias:${NC}\n"

    local obrig_tools=("ss" "ps" "lsof" "sha256sum" "find" "cp" "gzip")
    local obrig_desc=("Conexoes de rede" "Processos" "Arquivos abertos" "Hashes" "Busca no filesystem" "Copia de logs" "Compressao")

    for i in "${!obrig_tools[@]}"; do
        obrig_total=$((obrig_total + 1))
        if command -v "${obrig_tools[$i]}" &>/dev/null; then
            echo -e "    ${TICK} ${obrig_tools[$i]} — ${obrig_desc[$i]}"
            obrig_ok=$((obrig_ok + 1))
        else
            echo -e "    ${CROSS} ${obrig_tools[$i]} — ${obrig_desc[$i]} ${RED}FALTANDO${NC}"
        fi
    done

    echo ""
    echo -e "  ${BOLD}Ferramentas opcionais:${NC}\n"

    local opt_tools=("journalctl" "systemctl" "dc3dd" "netstat" "hashdeep" "foremost")
    local opt_desc=("Logs systemd" "Servicos" "Imaging forense" "Conexoes legacy" "Hashes recursivos" "Carving de arquivos")

    for i in "${!opt_tools[@]}"; do
        if command -v "${opt_tools[$i]}" &>/dev/null; then
            echo -e "    ${TICK} ${opt_tools[$i]} — ${opt_desc[$i]}"
            opt_ok=$((opt_ok + 1))
        else
            echo -e "    ${DIM}    ${opt_tools[$i]} — ${opt_desc[$i]} (nao instalado)${NC}"
        fi
    done

    echo ""
    echo -e "  ${BOLD}Captura de memoria:${NC}\n"
    AVML_PATH=$(find /home /root /opt /usr/local -name "avml" -type f -perm -111 2>/dev/null | head -1)
    if [ -n "$AVML_PATH" ]; then
        echo -e "    ${TICK} AVML encontrado: $AVML_PATH"
    else
        echo -e "    ${WARN} AVML nao encontrado (dump de RAM desabilitado)"
        echo -e "    ${DIM}    github.com/microsoft/avml/releases${NC}"
    fi

    echo ""
    echo -e "  Obrigatorias: ${GREEN}${obrig_ok}/${obrig_total}${NC} | Opcionais: ${opt_ok}/${#opt_tools[@]}"

    if [ "$obrig_ok" -lt "$obrig_total" ]; then
        echo -e "\n  ${RED}AVISO: Ferramentas obrigatorias faltando. Coleta pode falhar.${NC}"
    fi
}

# ======================= MENU: CONFIGURAR DESTINO =======================

menu_destino() {
    while true; do
        banner
        echo -e "  ${BOLD}PASSO 1/4 — DESTINO DA EVIDENCIA${NC}"
        linha
        echo ""

        # Listar dispositivos externos montados
        echo -e "  ${BOLD}Dispositivos externos detectados:${NC}\n"
        local encontrou=0
        local idx=0
        local mount_points=()

        while IFS= read -r line; do
            local mnt=$(echo "$line" | awk '{print $3}')
            local dev=$(echo "$line" | awk '{print $1}')
            local fs=$(echo "$line" | awk '{print $5}')
            local free=$(df -h "$mnt" 2>/dev/null | tail -1 | awk '{print $4}')
            local total=$(df -h "$mnt" 2>/dev/null | tail -1 | awk '{print $2}')
            idx=$((idx + 1))
            mount_points+=("$mnt")
            echo -e "    ${GREEN}${idx})${NC} $mnt ${DIM}($dev, $fs, ${free} livres de ${total})${NC}"
            encontrou=1
        done < <(mount | grep -E '/mnt/|/media/|/run/media/' | grep -v 'tmpfs')

        if [ "$encontrou" -eq 0 ]; then
            echo -e "    ${DIM}Nenhum dispositivo externo montado.${NC}"
        fi

        echo ""
        echo -e "  ${DIM}Digite o numero do dispositivo, um caminho, ou 'v' para voltar${NC}"
        echo ""
        echo -ne "  ${ARROW} Destino: "
        read -r input

        [ "$input" = "v" ] || [ "$input" = "V" ] && return 1
        [ -z "$input" ] && { echo -e "\n  ${CROSS} Vazio"; sleep 1; continue; }

        # Se digitou um numero, usar o mount point correspondente
        if [[ "$input" =~ ^[0-9]+$ ]] && [ "$input" -ge 1 ] && [ "$input" -le "$idx" ] 2>/dev/null; then
            input="${mount_points[$((input - 1))]}"
        fi

        # Verificar/criar diretorio
        if [ ! -d "$input" ]; then
            echo -ne "\n  Diretorio nao existe. Criar? (s/N) "
            read -r criar
            if [[ "$criar" =~ ^[Ss]$ ]]; then
                mkdir -p "$input" 2>/dev/null || { echo -e "  ${CROSS} Falha ao criar"; sleep 1; continue; }
                echo -e "  ${TICK} Criado"
            else
                continue
            fi
        fi

        # Verificar permissao de escrita
        if [ ! -w "$input" ]; then
            echo -e "\n  ${CROSS} Sem permissao de escrita em $input"
            sleep 1
            continue
        fi

        # Verificar espaco
        local espaco_livre=$(df -BG "$input" | tail -1 | awk '{print $4}' | tr -d 'G')
        local ram_total=$(free -g | awk '/Mem:/{print $2}')

        echo ""
        echo -e "  Espaco livre: ${BOLD}${espaco_livre}GB${NC} | RAM: ${BOLD}${ram_total}GB${NC}"

        if [ "$espaco_livre" -lt "$((ram_total + 2))" ]; then
            echo -e "  ${WARN} ${YELLOW}Espaco pode ser insuficiente para dump de RAM${NC}"
            echo -ne "  Continuar? (s/N) "
            read -r conf
            [[ ! "$conf" =~ ^[Ss]$ ]] && continue
        fi

        DESTINO="$input"
        return 0
    done
}

# ======================= MENU: SELECIONAR FASES =======================

menu_fases() {
    local fase_estado=(1 1 1 1 1 1 1 1 1 1 1 1 0)
    local fase_nomes=(
        "Informacoes do sistema"
        "Memoria RAM (AVML)"
        "Processos em execucao"
        "Conexoes de rede"
        "Usuarios e autenticacao"
        "Arquivos abertos/deletados"
        "Servicos e tarefas agendadas"
        "Configuracoes do sistema"
        "Logs completos"
        "Artefatos de persistencia"
        "Hashes de binarios"
        "Timeline do filesystem"
        "Imagem de disco (DEMORADO)"
    )
    local fase_tempo=(
        "~5s" "~2min" "~30s" "~5s" "~10s" "~1min"
        "~10s" "~10s" "~1min" "~15s" "~2min" "~3min" "VARIA"
    )

    # Se AVML nao encontrado, desabilitar fase 2
    if [ -z "$AVML_PATH" ]; then
        fase_estado[1]=0
    fi

    while true; do
        banner
        echo -e "  ${BOLD}PASSO 2/4 — SELECIONAR FASES DA COLETA${NC}"
        linha
        echo ""

        for i in "${!fase_nomes[@]}"; do
            local num=$((i + 1))
            local tempo="${fase_tempo[$i]}"
            if [ "${fase_estado[$i]}" -eq 1 ]; then
                printf "  ${GREEN} [X]${NC} %2d. %-38s ${DIM}%s${NC}\n" "$num" "${fase_nomes[$i]}" "$tempo"
            else
                if [ "$i" -eq 1 ] && [ -z "$AVML_PATH" ]; then
                    printf "  ${RED} [-]${NC} %2d. %-38s ${DIM}(AVML nao instalado)${NC}\n" "$num" "${fase_nomes[$i]}"
                else
                    printf "  ${DIM} [ ] %2d. %-38s %s${NC}\n" "$num" "${fase_nomes[$i]}" "$tempo"
                fi
            fi
        done

        echo ""
        linha
        echo -e "  ${DIM}[numero] toggle  [a] todas  [c] continuar  [v] voltar${NC}"
        echo ""
        echo -ne "  ${ARROW} Opcao: "
        read -r opt

        case "$opt" in
            [0-9]|[0-9][0-9])
                local idx=$((opt - 1))
                if [ "$idx" -ge 0 ] && [ "$idx" -lt "${#fase_nomes[@]}" ]; then
                    # Impedir ativar RAM sem AVML
                    if [ "$idx" -eq 1 ] && [ -z "$AVML_PATH" ] && [ "${fase_estado[1]}" -eq 0 ]; then
                        echo -e "\n  ${CROSS} AVML nao instalado. Instale primeiro."
                        sleep 1
                        continue
                    fi

                    if [ "${fase_estado[$idx]}" -eq 1 ]; then
                        fase_estado[$idx]=0
                    else
                        fase_estado[$idx]=1
                        if [ "$idx" -eq 12 ] && [ "${fase_estado[12]}" -eq 1 ]; then
                            echo ""
                            echo -e "  ${BOLD}Dispositivos de bloco:${NC}"
                            lsblk -d -o NAME,SIZE,TYPE,MODEL 2>/dev/null | while read -r line; do
                                echo -e "    $line"
                            done
                            echo ""
                            echo -ne "  ${ARROW} Dispositivo (ex: /dev/sda): "
                            read -r DISCO_ALVO
                            if ! [ -b "$DISCO_ALVO" ] 2>/dev/null; then
                                echo -e "  ${CROSS} Dispositivo invalido"
                                fase_estado[12]=0
                                DISCO_ALVO=""
                                sleep 1
                            fi
                        fi
                    fi
                fi
                ;;
            a|A)
                local todos=1
                for e in "${fase_estado[@]}"; do [ "$e" -eq 0 ] && todos=0; done
                local novo=$( [ "$todos" -eq 1 ] && echo 0 || echo 1 )
                for i in "${!fase_estado[@]}"; do
                    # Nao ativar RAM se sem AVML
                    if [ "$i" -eq 1 ] && [ -z "$AVML_PATH" ]; then
                        fase_estado[$i]=0
                    else
                        fase_estado[$i]=$novo
                    fi
                done
                ;;
            c|C)
                FASES_SELECIONADAS=()
                for i in "${!fase_estado[@]}"; do
                    [ "${fase_estado[$i]}" -eq 1 ] && FASES_SELECIONADAS+=($((i + 1)))
                done
                if [ ${#FASES_SELECIONADAS[@]} -eq 0 ]; then
                    echo -e "\n  ${CROSS} Selecione pelo menos uma fase"
                    sleep 1
                    continue
                fi
                return 0
                ;;
            v|V) return 1 ;;
        esac
    done
}

# ======================= MENU: CONFIRMACAO =======================

menu_confirmacao() {
    banner
    echo -e "  ${BOLD}PASSO 3/4 — CONFIRMAR COLETA${NC}"
    linha
    echo ""

    local fase_nomes=(
        "Informacoes do sistema" "Memoria RAM" "Processos"
        "Rede" "Usuarios" "Arquivos abertos/deletados"
        "Servicos e crons" "Configuracoes" "Logs"
        "Persistencia/rootkit" "Hashes de binarios" "Timeline"
        "Imagem de disco"
    )

    echo -e "  ${WHITE}Servidor:${NC}     $HOSTNAME_ALVO"
    echo -e "  ${WHITE}Destino:${NC}      $DESTINO"
    echo -e "  ${WHITE}AVML:${NC}         ${AVML_PATH:-${RED}Nao encontrado${NC}}"
    [ -n "$DISCO_ALVO" ] && echo -e "  ${WHITE}Disco alvo:${NC}   $DISCO_ALVO"
    echo ""
    echo -e "  ${WHITE}Fases (${#FASES_SELECIONADAS[@]}):${NC}"

    for f in "${FASES_SELECIONADAS[@]}"; do
        echo -e "    ${GREEN}✓${NC} ${f}. ${fase_nomes[$((f-1))]}"
    done

    echo ""
    linha
    echo ""
    echo -e "  ${YELLOW}ATENCAO: Nao interrompa o processo. Use Ctrl+C apenas${NC}"
    echo -e "  ${YELLOW}se necessario (a coleta parcial sera salva).${NC}"
    echo ""
    echo -ne "  ${ARROW} Iniciar coleta? (s/N) "
    read -r conf

    [[ "$conf" =~ ^[Ss]$ ]] && return 0 || return 1
}

# ======================= SETUP DO CASO =======================

setup_caso() {
    DATA_INICIO=$(date -u +"%Y-%m-%d_%H-%M-%S_UTC")
    TIMESTAMP_INICIO=$(date +%s)
    CASO_DIR="${DESTINO}/forense_${HOSTNAME_ALVO}_${DATA_INICIO}"
    LOG="${CASO_DIR}/coleta.log"

    # Criar apenas pastas das fases selecionadas
    mkdir -p "$CASO_DIR"

    local fase_dirs=(sistema memoria processos rede usuarios filesystem servicos sistema logs artefatos hashes timeline disco)
    for f in "${FASES_SELECIONADAS[@]}"; do
        mkdir -p "$CASO_DIR/${fase_dirs[$((f-1))]}"
    done

    touch "$LOG"
    {
        echo "============================================"
        echo "  Coleta Forense - Log de Execucao"
        echo "============================================"
        echo "Inicio:  $DATA_INICIO"
        echo "Host:    $HOSTNAME_ALVO"
        echo "Kernel:  $(uname -r)"
        echo "User:    $(whoami)"
        echo "Fases:   ${FASES_SELECIONADAS[*]}"
        echo "Destino: $CASO_DIR"
        echo "============================================"
        echo ""
    } >> "$LOG"
}

# ======================= CONTAGEM DE ETAPAS =======================

contar_etapas() {
    TOTAL_ETAPAS=0
    for f in "${FASES_SELECIONADAS[@]}"; do
        case $f in
            1)  TOTAL_ETAPAS=$((TOTAL_ETAPAS + 11)) ;;
            2)  TOTAL_ETAPAS=$((TOTAL_ETAPAS + 4)) ;;
            3)  TOTAL_ETAPAS=$((TOTAL_ETAPAS + 8)) ;;
            4)  TOTAL_ETAPAS=$((TOTAL_ETAPAS + 10)) ;;
            5)  TOTAL_ETAPAS=$((TOTAL_ETAPAS + 10)) ;;
            6)  TOTAL_ETAPAS=$((TOTAL_ETAPAS + 9)) ;;
            7)  TOTAL_ETAPAS=$((TOTAL_ETAPAS + 6)) ;;
            8)  TOTAL_ETAPAS=$((TOTAL_ETAPAS + 10)) ;;
            9)  TOTAL_ETAPAS=$((TOTAL_ETAPAS + 6)) ;;
            10) TOTAL_ETAPAS=$((TOTAL_ETAPAS + 5)) ;;
            11) TOTAL_ETAPAS=$((TOTAL_ETAPAS + 5)) ;;
            12) TOTAL_ETAPAS=$((TOTAL_ETAPAS + 3)) ;;
            13) TOTAL_ETAPAS=$((TOTAL_ETAPAS + 1)) ;;
        esac
    done
}

# ============================================================
#  FASES DE COLETA
# ============================================================

fase_sistema() {
    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ FASE 1/12: INFORMACOES DO SISTEMA ━━━${NC}"
    echo ""

    executar "Data/hora UTC" "$CASO_DIR/sistema/data_utc.txt" "date -u"
    executar "Data/hora local" "$CASO_DIR/sistema/data_local.txt" "date"
    executar "Timezone" "$CASO_DIR/sistema/timezone.txt" "timedatectl 2>/dev/null || cat /etc/timezone"
    executar "Hostname" "$CASO_DIR/sistema/hostname.txt" "hostname -f 2>/dev/null; hostname"
    executar "Uptime" "$CASO_DIR/sistema/uptime.txt" "uptime"
    executar "Kernel e OS" "$CASO_DIR/sistema/uname.txt" "uname -a"
    executar "Release" "$CASO_DIR/sistema/release.txt" "cat /etc/*release 2>/dev/null; cat /etc/issue 2>/dev/null"
    executar "Hardware (CPU, RAM, discos)" "$CASO_DIR/sistema/hardware.txt" "lscpu; echo '---'; free -h; echo '---'; lsblk -f"
    executar "Tabela de particoes" "$CASO_DIR/sistema/discos.txt" "fdisk -l 2>/dev/null; echo '---'; blkid; echo '---'; df -hT"
    executar "Montagens e fstab" "$CASO_DIR/sistema/montagens.txt" "mount; echo '---'; cat /etc/fstab"
    executar "Variaveis de ambiente" "$CASO_DIR/sistema/env.txt" "env"
}

fase_memoria() {
    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ FASE 2/12: CAPTURA DE MEMORIA RAM ━━━${NC}"
    echo ""

    local ram_total_mb=$(free -m | awk '/Mem:/{print $2}')
    local ram_total=$(( (ram_total_mb + 512) / 1024 ))
    [ "$ram_total" -eq 0 ] && ram_total=1
    log_info "RAM total: ${ram_total_mb}MB (~${ram_total}GB)"

    ETAPA_ATUAL=$((ETAPA_ATUAL + 1))
    if [ -n "$AVML_PATH" ] && [ -f "$AVML_PATH" ]; then
        log_info "Capturando RAM com AVML... (${ram_total}GB, pode demorar)"

        if "$AVML_PATH" "$CASO_DIR/memoria/ram.lime" 2>>"$LOG"; then
            local tamanho=$(du -sh "$CASO_DIR/memoria/ram.lime" | cut -f1)
            log_ok "Memoria capturada: $tamanho"

            ETAPA_ATUAL=$((ETAPA_ATUAL + 1))
            sha256sum "$CASO_DIR/memoria/ram.lime" > "$CASO_DIR/memoria/ram.lime.sha256"
            log_ok "Hash SHA256 da memoria gerado"
        else
            log_erro "Falha na captura com AVML"
            ETAPA_ATUAL=$((ETAPA_ATUAL + 1))
            if [ -f /proc/kcore ]; then
                log_info "Fallback: /proc/kcore..."
                dd if=/proc/kcore of="$CASO_DIR/memoria/kcore.dd" bs=1M count=$((ram_total * 1024)) 2>/dev/null
                log_warn "kcore capturado (dump parcial)"
            fi
        fi
    else
        log_warn "AVML nao disponivel, pulando captura de RAM"
        ETAPA_ATUAL=$((ETAPA_ATUAL + 1))
    fi

    executar "Meminfo" "$CASO_DIR/memoria/meminfo.txt" "cat /proc/meminfo"
    executar "Swaps" "$CASO_DIR/memoria/swaps.txt" "cat /proc/swaps"
}

fase_processos() {
    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ FASE 3/12: PROCESSOS EM EXECUCAO ━━━${NC}"
    echo ""

    executar "Arvore de processos (ps auxwwf)" "$CASO_DIR/processos/ps_tree.txt" "ps auxwwf"

    executar "Processos detalhado" "$CASO_DIR/processos/ps_detalhado.txt" \
        "ps -eo pid,ppid,uid,user,gid,group,stat,nice,pri,pcpu,pmem,vsz,rss,stime,etimes,tty,args --sort=-pcpu"

    executar "Processos + hash SHA256 do binario" "$CASO_DIR/processos/ps_com_hash.txt" \
        'for pid in /proc/[0-9]*; do
            p=$(basename "$pid"); exe=$(readlink -f "$pid/exe" 2>/dev/null)
            cmdline=$(tr "\0" " " < "$pid/cmdline" 2>/dev/null)
            # Detectar container/flatpak/snap
            container=""
            if [ -f "$pid/cgroup" ]; then
                grep -q "flatpak" "$pid/cgroup" 2>/dev/null && container="FLATPAK"
                grep -q "snap" "$pid/cgroup" 2>/dev/null && container="SNAP"
                grep -q "docker" "$pid/cgroup" 2>/dev/null && container="DOCKER"
            fi
            if [ -n "$exe" ] && [ -f "$exe" ]; then
                hash=$(sha256sum "$exe" 2>/dev/null | cut -d" " -f1)
            elif [ -n "$container" ]; then
                hash="N/A ($container)"
            elif echo "$exe" | grep -q "(deleted)" 2>/dev/null; then
                hash="N/A (DELETED)"
            else
                hash="N/A"
            fi
            echo "PID=$p | EXE=$exe | HASH=$hash | CMD=$cmdline"
        done'

    executar "Links /proc/*/exe" "$CASO_DIR/processos/proc_exe.txt" "ls -la /proc/[0-9]*/exe 2>/dev/null"
    executar "Working dirs /proc/*/cwd" "$CASO_DIR/processos/proc_cwd.txt" "ls -la /proc/[0-9]*/cwd 2>/dev/null"

    # Estes geram arquivos grandes -> comprimir
    executar_gz "File descriptors abertos" "$CASO_DIR/processos/proc_fd.txt" \
        'for pid in /proc/[0-9]*; do p=$(basename "$pid"); echo "=== PID $p ==="; ls -la "$pid/fd" 2>/dev/null; done'

    executar_gz "Maps de memoria" "$CASO_DIR/processos/proc_maps.txt" \
        'for pid in /proc/[0-9]*; do p=$(basename "$pid"); echo "=== PID $p ==="; cat "$pid/maps" 2>/dev/null; done'

    executar_gz "Environ dos processos" "$CASO_DIR/processos/proc_environ.txt" \
        'for pid in /proc/[0-9]*; do p=$(basename "$pid"); echo "=== PID $p ==="; tr "\0" "\n" < "$pid/environ" 2>/dev/null; echo ""; done'
}

fase_rede() {
    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ FASE 4/12: CONEXOES DE REDE ━━━${NC}"
    echo ""

    executar "Conexoes ativas (ss -tulnpa)" "$CASO_DIR/rede/ss_conexoes.txt" "ss -tulnpa"
    executar "Todas as conexoes (ss -anpeo)" "$CASO_DIR/rede/ss_todas.txt" "ss -anpeo"
    executar "Netstat" "$CASO_DIR/rede/netstat.txt" "netstat -tulnpa 2>/dev/null"
    executar "Interfaces de rede" "$CASO_DIR/rede/interfaces.txt" "ip -d addr; echo '---'; ifconfig -a 2>/dev/null"
    executar "Tabela de rotas" "$CASO_DIR/rede/rotas.txt" "ip route; echo '---'; ip -6 route"
    executar "Tabela ARP" "$CASO_DIR/rede/arp.txt" "ip neigh; echo '---'; arp -a 2>/dev/null"
    executar "DNS e /etc/hosts" "$CASO_DIR/rede/dns.txt" "cat /etc/resolv.conf; echo '---'; cat /etc/hosts"
    executar "Firewall iptables" "$CASO_DIR/rede/iptables.txt" "iptables -L -n -v --line-numbers 2>/dev/null; echo '=== NAT ==='; iptables -t nat -L -n -v 2>/dev/null"
    executar "Firewall nftables" "$CASO_DIR/rede/nftables.txt" "nft list ruleset 2>/dev/null"
    executar "Estatisticas de rede" "$CASO_DIR/rede/netstats.txt" "ss -s; echo '---'; cat /proc/net/dev"
}

fase_usuarios() {
    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ FASE 5/12: USUARIOS E AUTENTICACAO ━━━${NC}"
    echo ""

    executar "Usuarios logados (w + who)" "$CASO_DIR/usuarios/logados.txt" "w; echo '---'; who -a"
    executar "Ultimos 100 logins" "$CASO_DIR/usuarios/last.txt" "last -100 -f /var/log/wtmp 2>/dev/null || last -100"
    executar "Ultimos 100 logins falhos" "$CASO_DIR/usuarios/lastb.txt" "lastb -100 -f /var/log/btmp 2>/dev/null || echo 'btmp vazio ou inacessivel'"
    executar "Ultimo login por usuario" "$CASO_DIR/usuarios/lastlog.txt" "lastlog 2>/dev/null || echo 'lastlog indisponivel'"
    # Copiar wtmp/btmp brutos para analise posterior
    executar "wtmp/btmp (brutos)" "$CASO_DIR/usuarios/login_dbs.txt" \
        "cp /var/log/wtmp $CASO_DIR/usuarios/wtmp.bin 2>/dev/null; cp /var/log/btmp $CASO_DIR/usuarios/btmp.bin 2>/dev/null; echo 'wtmp:'; ls -la /var/log/wtmp 2>/dev/null; echo 'btmp:'; ls -la /var/log/btmp 2>/dev/null"
    executar "/etc/passwd" "$CASO_DIR/usuarios/passwd.txt" "cat /etc/passwd"
    executar "/etc/shadow (hashes de senha)" "$CASO_DIR/usuarios/shadow.txt" "cat /etc/shadow"
    executar "/etc/group" "$CASO_DIR/usuarios/group.txt" "cat /etc/group"
    executar "/etc/sudoers" "$CASO_DIR/usuarios/sudoers.txt" "cat /etc/sudoers 2>/dev/null; echo '---'; cat /etc/sudoers.d/* 2>/dev/null"

    executar "SSH keys + bash_history (todos)" "$CASO_DIR/usuarios/ssh_e_historico.txt" \
        'for dir in /home/* /root; do
            [ ! -d "$dir" ] && continue
            user=$(basename "$dir")
            echo "========== USUARIO: $user =========="
            echo "--- SSH KEYS ---"
            for f in authorized_keys known_hosts id_rsa id_rsa.pub id_ed25519 id_ed25519.pub; do
                [ -f "$dir/.ssh/$f" ] && echo "=== $f ===" && cat "$dir/.ssh/$f" 2>/dev/null
            done
            echo "--- HISTORICO ---"
            for hist in .bash_history .zsh_history .python_history .mysql_history; do
                [ -f "$dir/$hist" ] && echo "=== $hist ===" && cat "$dir/$hist"
            done
            echo ""
        done'
}

fase_arquivos() {
    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ FASE 6/12: ARQUIVOS ABERTOS / DELETADOS ━━━${NC}"
    echo ""

    # lsof gera saida enorme (40MB+), comprimir
    executar_gz "Arquivos abertos (lsof)" "$CASO_DIR/filesystem/lsof.txt" "lsof -n -P 2>/dev/null"
    executar "Deletados ainda abertos" "$CASO_DIR/filesystem/deletados_abertos.txt" "lsof +L1 2>/dev/null"

    # Recuperar conteudo de deletados (com limite de tamanho)
    ETAPA_ATUAL=$((ETAPA_ATUAL + 1))
    local pct=0
    [ "$TOTAL_ETAPAS" -gt 0 ] && pct=$((ETAPA_ATUAL * 100 / TOTAL_ETAPAS))
    mkdir -p "$CASO_DIR/filesystem/recuperados"
    local recuperados=0
    local pulados=0
    local total_recuperado_bytes=0
    local max_por_arquivo=$((MAX_RECUPERADO_MB * 1048576))
    local max_total=$((MAX_RECUPERADO_TOTAL_MB * 1048576))

    lsof +L1 2>/dev/null | awk 'NR>1 && /deleted/ {print $2, $4, $7, $9}' | while read -r pid fd size arquivo; do
        # Checar limite total
        if [ "$total_recuperado_bytes" -ge "$max_total" ]; then
            pulados=$((pulados + 1))
            continue
        fi

        fd_num=$(echo "$fd" | tr -dc '0-9')
        if [ -n "$fd_num" ] && [ -f "/proc/$pid/fd/$fd_num" ]; then
            # Checar tamanho do arquivo
            file_size=$(stat -c%s "/proc/$pid/fd/$fd_num" 2>/dev/null || echo 0)
            if [ "$file_size" -gt "$max_por_arquivo" ]; then
                # Arquivo grande demais: so registrar metadata
                echo "PULADO (${file_size} bytes): pid=${pid} fd=${fd_num} arquivo=${arquivo}" \
                    >> "$CASO_DIR/filesystem/recuperados/_GRANDES_PULADOS.txt"
                pulados=$((pulados + 1))
                continue
            fi

            nome_seguro=$(echo "${arquivo}" | tr '/' '_')
            cp "/proc/$pid/fd/$fd_num" "$CASO_DIR/filesystem/recuperados/pid${pid}_fd${fd_num}_${nome_seguro}" 2>/dev/null
            recuperados=$((recuperados + 1))
            total_recuperado_bytes=$((total_recuperado_bytes + file_size))
        fi
    done
    printf "\r  ${TICK} ${DIM}[%3d%%]${NC} %-50s\n" "$pct" "Recuperacao de arquivos deletados"
    [ -n "$LOG" ] && echo "[$(date -u +%H:%M:%S)] OK: Arquivos deletados recuperados" >> "$LOG"
    CONTAGEM_OK=$((CONTAGEM_OK + 1))

    executar "Modificados ultimas 24h" "$CASO_DIR/filesystem/modificados_24h.txt" \
        "find / -xdev -mtime -1 -type f -printf '%T+ %p\n' 2>/dev/null | sort -r | head -500"

    executar "Modificados ultimos 7 dias" "$CASO_DIR/filesystem/modificados_7d.txt" \
        "find / -xdev -mtime -7 -type f -printf '%T+ %p\n' 2>/dev/null | sort -r | head -2000"

    executar "Arquivos SUID / SGID" "$CASO_DIR/filesystem/suid_sgid.txt" \
        "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -ls 2>/dev/null"

    executar "Arquivos world-writable" "$CASO_DIR/filesystem/world_writable.txt" \
        "find / -xdev -perm -0002 -type f -ls 2>/dev/null"

    executar "Arquivos sem dono" "$CASO_DIR/filesystem/sem_dono.txt" \
        "find / -xdev \\( -nouser -o -nogroup \\) 2>/dev/null | head -500"

    executar "Arquivos em /tmp /var/tmp /dev/shm" "$CASO_DIR/filesystem/tmp_files.txt" \
        "find /tmp /var/tmp /dev/shm -type f -ls 2>/dev/null"
}

fase_servicos() {
    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ FASE 7/12: SERVICOS E TAREFAS AGENDADAS ━━━${NC}"
    echo ""

    executar "Servicos systemd (todos)" "$CASO_DIR/servicos/systemd_units.txt" "systemctl list-units --all --no-pager 2>/dev/null"
    executar "Unit files habilitados" "$CASO_DIR/servicos/systemd_enabled.txt" "systemctl list-unit-files --no-pager 2>/dev/null"
    executar "Servicos com falha" "$CASO_DIR/servicos/systemd_failed.txt" "systemctl --failed --no-pager 2>/dev/null"
    executar "Timers systemd" "$CASO_DIR/servicos/systemd_timers.txt" "systemctl list-timers --all --no-pager 2>/dev/null"

    executar "Crontabs (todos os usuarios)" "$CASO_DIR/servicos/crontabs.txt" \
        'echo "=== /etc/crontab ==="; cat /etc/crontab 2>/dev/null
        echo ""; echo "=== /etc/cron.d/ ==="; cat /etc/cron.d/* 2>/dev/null
        echo ""; echo "=== cron.daily ==="; ls -la /etc/cron.daily/ 2>/dev/null
        echo ""; echo "=== cron.hourly ==="; ls -la /etc/cron.hourly/ 2>/dev/null
        echo ""; echo "=== Crontabs por usuario ===";
        for user in $(cut -d: -f1 /etc/passwd); do
            cron=$(crontab -l -u "$user" 2>/dev/null)
            if [ -n "$cron" ]; then echo "--- $user ---"; echo "$cron"; fi
        done'

    executar "At jobs" "$CASO_DIR/servicos/at_jobs.txt" "atq 2>/dev/null; echo '---'; ls -la /var/spool/at/ 2>/dev/null"
}

fase_configuracoes() {
    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ FASE 8/12: CONFIGURACOES DO SISTEMA ━━━${NC}"
    echo ""

    executar "Modulos do kernel (lsmod)" "$CASO_DIR/sistema/modulos_kernel.txt" "lsmod; echo '---'; cat /proc/modules"
    executar "Parametros sysctl" "$CASO_DIR/sistema/sysctl.txt" "sysctl -a 2>/dev/null"
    executar "Repositorios de pacotes" "$CASO_DIR/sistema/repos.txt" "cat /etc/apt/sources.list 2>/dev/null; cat /etc/apt/sources.list.d/* 2>/dev/null; cat /etc/yum.repos.d/* 2>/dev/null"
    executar "Pacotes instalados (dpkg)" "$CASO_DIR/sistema/pacotes_dpkg.txt" "dpkg -l 2>/dev/null"
    executar "Pacotes instalados (rpm)" "$CASO_DIR/sistema/pacotes_rpm.txt" "rpm -qa --last 2>/dev/null"
    executar "SELinux / AppArmor" "$CASO_DIR/sistema/mac_status.txt" "getenforce 2>/dev/null; aa-status 2>/dev/null; sestatus 2>/dev/null"
    executar "Docker containers e imagens" "$CASO_DIR/sistema/docker.txt" "docker ps -a 2>/dev/null; echo '---'; docker images 2>/dev/null; echo '---'; docker network ls 2>/dev/null"
    executar "PAM config" "$CASO_DIR/sistema/pam.txt" "cat /etc/pam.d/* 2>/dev/null"
    executar "SSH config (sshd + client)" "$CASO_DIR/sistema/sshd_config.txt" "cat /etc/ssh/sshd_config 2>/dev/null; echo '---'; cat /etc/ssh/ssh_config 2>/dev/null"
    executar "TCP Wrappers (allow/deny)" "$CASO_DIR/sistema/tcp_wrappers.txt" "cat /etc/hosts.allow 2>/dev/null; echo '---'; cat /etc/hosts.deny 2>/dev/null"
}

fase_logs() {
    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ FASE 9/12: LOGS DO SISTEMA ━━━${NC}"
    echo ""

    ETAPA_ATUAL=$((ETAPA_ATUAL + 1))
    local pct=0
    [ "$TOTAL_ETAPAS" -gt 0 ] && pct=$((ETAPA_ATUAL * 100 / TOTAL_ETAPAS))
    printf "\r  ${INFO} ${DIM}[%3d%%]${NC} %-50s" "$pct" "Copiando /var/log/ completo..."
    cp -a /var/log "$CASO_DIR/logs/var_log" 2>/dev/null
    local log_size=$(du -sh "$CASO_DIR/logs/var_log" 2>/dev/null | cut -f1)
    printf "\r  ${TICK} ${DIM}[%3d%%]${NC} %-50s ${DIM}(${log_size})${NC}\n" "$pct" "Copia de /var/log/"
    CONTAGEM_OK=$((CONTAGEM_OK + 1))
    [ -n "$LOG" ] && echo "[$(date -u +%H:%M:%S)] OK: /var/log copiado ($log_size)" >> "$LOG"

    executar "Journalctl (ultimo boot, 50k linhas)" "$CASO_DIR/logs/journal_boot.txt" "journalctl -b --no-pager -n 50000 2>/dev/null"
    executar "Journal SSH + sudo" "$CASO_DIR/logs/journal_auth.txt" "journalctl _COMM=sshd --no-pager -n 10000 2>/dev/null; echo '---'; journalctl _COMM=sudo --no-pager -n 5000 2>/dev/null"
    executar "Journal kernel" "$CASO_DIR/logs/journal_kernel.txt" "journalctl -k --no-pager -n 10000 2>/dev/null"
    executar "Dmesg" "$CASO_DIR/logs/dmesg.txt" "dmesg -T 2>/dev/null || dmesg"
    executar "Audit log + aureport" "$CASO_DIR/logs/audit.txt" "cat /var/log/audit/audit.log 2>/dev/null; echo '---'; aureport --summary 2>/dev/null"
}

fase_persistencia() {
    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ FASE 10/12: ARTEFATOS DE PERSISTENCIA ━━━${NC}"
    echo ""

    executar "Init scripts (rc*.d)" "$CASO_DIR/artefatos/init_scripts.txt" "ls -la /etc/init.d/ 2>/dev/null; echo '---'; ls -la /etc/rc*.d/ 2>/dev/null"

    executar "Profile/RC files (todos users)" "$CASO_DIR/artefatos/profiles.txt" \
        'echo "=== /etc/profile ==="; cat /etc/profile 2>/dev/null
        echo "=== /etc/profile.d/ ==="; cat /etc/profile.d/* 2>/dev/null
        echo "=== /etc/bash.bashrc ==="; cat /etc/bash.bashrc 2>/dev/null
        for dir in /home/* /root; do
            [ ! -d "$dir" ] && continue
            user=$(basename "$dir")
            for rc in .bashrc .bash_profile .profile .zshrc; do
                [ -f "$dir/$rc" ] && echo "=== $user/$rc ===" && cat "$dir/$rc"
            done
        done'

    executar "LD_PRELOAD / preload" "$CASO_DIR/artefatos/preload.txt" "cat /etc/ld.so.preload 2>/dev/null; echo '---'; echo \$LD_PRELOAD"

    executar "Executaveis em locais suspeitos" "$CASO_DIR/artefatos/binarios_suspeitos.txt" \
        "find /tmp /var/tmp /dev/shm /run -type f -executable -ls 2>/dev/null"

    executar "Deteccao de PIDs ocultos + modulos" "$CASO_DIR/artefatos/rootkit_check.txt" \
        'echo "=== PIDs ocultos (em /proc mas nao em ps) ==="
        ps_pids=$(ps -eo pid --no-headers | tr -d " " | sort -n)
        proc_pids=$(ls -d /proc/[0-9]* 2>/dev/null | xargs -I{} basename {} | sort -n)
        hidden=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids"))
        if [ -n "$hidden" ]; then
            echo "ALERTA - PIDs ocultos encontrados:"
            echo "$hidden"
        else
            echo "Nenhum PID oculto detectado"
        fi
        echo ""
        echo "=== Modulos do kernel ==="
        lsmod | awk "NR>1 {print \$1}" | while read mod; do
            info=$(modinfo "$mod" 2>/dev/null)
            author=$(echo "$info" | grep "^author:" | head -1)
            filename=$(echo "$info" | grep "^filename:" | head -1)
            echo "$mod | $author | $filename"
        done'
}

fase_hashes() {
    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ FASE 11/12: HASHES DE BINARIOS CRITICOS ━━━${NC}"
    echo ""

    executar "SHA256 /usr/bin/*" "$CASO_DIR/hashes/usr_bin.sha256" "sha256sum /usr/bin/* 2>/dev/null"
    executar "SHA256 /usr/sbin/*" "$CASO_DIR/hashes/usr_sbin.sha256" "sha256sum /usr/sbin/* 2>/dev/null"
    executar "SHA256 /bin/* /sbin/*" "$CASO_DIR/hashes/bin_sbin.sha256" "sha256sum /bin/* /sbin/* 2>/dev/null"
    executar "SHA256 libs criticas (libc, pam)" "$CASO_DIR/hashes/libs.sha256" \
        "sha256sum /lib/x86_64-linux-gnu/libc.so* /lib/x86_64-linux-gnu/libpam* /lib/x86_64-linux-gnu/libcrypt* 2>/dev/null"
    executar "Verificacao de integridade (dpkg -V)" "$CASO_DIR/hashes/dpkg_verify.txt" "dpkg -V 2>/dev/null"
}

fase_timeline() {
    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ FASE 12/12: TIMELINE DO FILESYSTEM ━━━${NC}"
    echo ""

    executar_gz "Timeline 30d (modificacao)" "$CASO_DIR/timeline/timeline_mtime_30d.csv" \
        'echo "timestamp,type,permissions,user,group,size,path"; find / -xdev -type f -mtime -30 -printf "%T+,modified,%M,%u,%g,%s,%p\n" 2>/dev/null | sort -r'

    executar_gz "Timeline 7d (acesso)" "$CASO_DIR/timeline/timeline_atime_7d.csv" \
        'echo "timestamp,type,permissions,user,group,size,path"; find / -xdev -type f -atime -7 -printf "%A+,accessed,%M,%u,%g,%s,%p\n" 2>/dev/null | sort -r | head -5000'

    executar_gz "Timeline 30d (metadata change)" "$CASO_DIR/timeline/timeline_ctime_30d.csv" \
        'echo "timestamp,type,permissions,user,group,size,path"; find / -xdev -type f -ctime -30 -printf "%C+,changed,%M,%u,%g,%s,%p\n" 2>/dev/null | sort -r'
}

fase_imagem_disco() {
    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ EXTRA: IMAGEM DE DISCO ━━━${NC}"
    echo ""

    ETAPA_ATUAL=$((ETAPA_ATUAL + 1))

    if [ -z "$DISCO_ALVO" ] || ! [ -b "$DISCO_ALVO" ] 2>/dev/null; then
        log_erro "Dispositivo invalido: ${DISCO_ALVO:-nao definido}"
        return
    fi

    local disco_size=$(blockdev --getsize64 "$DISCO_ALVO" 2>/dev/null)
    local disco_gb=$((disco_size / 1073741824))
    log_info "Criando imagem de $DISCO_ALVO (${disco_gb}GB)..."
    log_warn "Pode demorar HORAS. Ctrl+C salva coleta parcial."

    if command -v dc3dd &>/dev/null; then
        dc3dd if="$DISCO_ALVO" of="$CASO_DIR/disco/disco.dd" hash=sha256 log="$CASO_DIR/disco/imaging.log" 2>>"$LOG"
    else
        dd if="$DISCO_ALVO" of="$CASO_DIR/disco/disco.dd" bs=4M status=progress conv=noerror,sync 2>>"$LOG"
        sha256sum "$CASO_DIR/disco/disco.dd" > "$CASO_DIR/disco/disco.dd.sha256"
    fi
    log_ok "Imagem de disco criada"
}

# ======================= FINALIZAR =======================

finalizar() {
    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ FINALIZANDO ━━━${NC}"
    echo ""

    # Limpar arquivos vazios
    local vazios=$(find "$CASO_DIR" -type f -empty -not -name "coleta.log" | wc -l)
    find "$CASO_DIR" -type f -empty -not -name "coleta.log" -delete 2>/dev/null
    [ "$vazios" -gt 0 ] && log_info "Removidos $vazios arquivos vazios"

    # Limpar diretorios vazios (fases nao executadas ou sem resultado)
    find "$CASO_DIR" -mindepth 1 -type d -empty -delete 2>/dev/null

    # Hash de toda evidencia
    log_info "Gerando SHA256 de toda evidencia..."
    find "$CASO_DIR" -type f \
        -not -name "evidencia_hashes.sha256" \
        -not -name "coleta.log" \
        -not -name "RELATORIO.txt" \
        -exec sha256sum {} \; > "$CASO_DIR/evidencia_hashes.sha256" 2>/dev/null
    local total_hashes=$(wc -l < "$CASO_DIR/evidencia_hashes.sha256")
    log_ok "Hashes gerados: $total_hashes arquivos"

    # Calcular duracao
    local timestamp_fim=$(date +%s)
    local duracao=$((timestamp_fim - TIMESTAMP_INICIO))
    local duracao_fmt=$(formatar_duracao $duracao)

    local data_fim=$(date -u +"%Y-%m-%d_%H-%M-%S_UTC")
    local tamanho_total=$(du -sh "$CASO_DIR" | cut -f1)
    local total_arquivos=$(find "$CASO_DIR" -type f | wc -l)

    # Gerar relatorio dinamico (so mostra pastas que existem)
    local estrutura=""
    [ -d "$CASO_DIR/sistema" ] && estrutura="${estrutura}  sistema/        Info do sistema, hardware, kernel, discos\n"
    [ -d "$CASO_DIR/memoria" ] && estrutura="${estrutura}  memoria/        Dump de RAM e metadados de memoria\n"
    [ -d "$CASO_DIR/processos" ] && estrutura="${estrutura}  processos/      Processos, hashes, file descriptors, maps\n"
    [ -d "$CASO_DIR/rede" ] && estrutura="${estrutura}  rede/           Conexoes, interfaces, firewall, ARP, DNS\n"
    [ -d "$CASO_DIR/usuarios" ] && estrutura="${estrutura}  usuarios/       Contas, logins, SSH keys, historico bash\n"
    [ -d "$CASO_DIR/filesystem" ] && estrutura="${estrutura}  filesystem/     Arquivos abertos, deletados, SUID, recentes\n"
    [ -d "$CASO_DIR/servicos" ] && estrutura="${estrutura}  servicos/       Systemd, cron, at, init scripts\n"
    [ -d "$CASO_DIR/logs" ] && estrutura="${estrutura}  logs/           /var/log completo + journalctl\n"
    [ -d "$CASO_DIR/artefatos" ] && estrutura="${estrutura}  artefatos/      Persistencia, rootkit checks, suspeitos\n"
    [ -d "$CASO_DIR/hashes" ] && estrutura="${estrutura}  hashes/         SHA256 de binarios criticos do sistema\n"
    [ -d "$CASO_DIR/timeline" ] && estrutura="${estrutura}  timeline/       Timeline de modificacoes do filesystem\n"
    [ -d "$CASO_DIR/disco" ] && estrutura="${estrutura}  disco/          Imagem de disco\n"

    cat > "$CASO_DIR/RELATORIO.txt" << RELATORIO
============================================================
         RELATORIO DE COLETA FORENSE
============================================================

Servidor:       $HOSTNAME_ALVO
Kernel:         $(uname -r)
Data inicio:    $DATA_INICIO
Data fim:       $data_fim
Duracao:        $duracao_fmt
Coletado por:   $(whoami)@$(hostname)
Script versao:  $VERSAO

Destino:        $CASO_DIR
Tamanho total:  $tamanho_total
Arquivos:       $total_arquivos

Resultado:
  Sucesso:   $CONTAGEM_OK
  Parcial:   $CONTAGEM_WARN
  Falha:     $CONTAGEM_ERRO

Fases executadas: ${FASES_SELECIONADAS[*]}

--- ESTRUTURA ---

$(echo -e "$estrutura")
--- INTEGRIDADE ---

Hash de cada arquivo: evidencia_hashes.sha256
Total de hashes:      $total_hashes
Log de execucao:      coleta.log

============================================================
RELATORIO

    # Tela final
    echo ""
    echo -e "  ${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║            COLETA FINALIZADA COM SUCESSO             ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "  ${NC}"
    echo -e "  ${WHITE}Servidor:${NC}    $HOSTNAME_ALVO"
    echo -e "  ${WHITE}Duracao:${NC}     $duracao_fmt"
    echo -e "  ${WHITE}Destino:${NC}     ${CYAN}$CASO_DIR${NC}"
    echo -e "  ${WHITE}Tamanho:${NC}     ${YELLOW}$tamanho_total${NC}"
    echo -e "  ${WHITE}Arquivos:${NC}    $total_arquivos"
    echo ""
    echo -e "  ${WHITE}Resultado:${NC}   ${GREEN}$CONTAGEM_OK ok${NC} | ${YELLOW}$CONTAGEM_WARN parcial${NC} | ${RED}$CONTAGEM_ERRO falha${NC}"
    echo ""
    echo -e "  ${WHITE}Arquivos:${NC}"
    echo -e "    Relatorio:  $CASO_DIR/RELATORIO.txt"
    echo -e "    Hashes:     $CASO_DIR/evidencia_hashes.sha256"
    echo -e "    Log:        $CASO_DIR/coleta.log"
    echo ""

    # Oferecer compactar
    echo -ne "  ${ARROW} Compactar tudo em .tar.gz? (s/N) "
    read -r compactar
    if [[ "$compactar" =~ ^[Ss]$ ]]; then
        local tar_file="${CASO_DIR}.tar.gz"
        log_info "Compactando para ${tar_file}..."
        tar czf "$tar_file" -C "$(dirname "$CASO_DIR")" "$(basename "$CASO_DIR")" 2>/dev/null
        local tar_size=$(du -sh "$tar_file" | cut -f1)
        log_ok "Compactado: $tar_file ($tar_size)"
        echo ""
        echo -ne "  ${ARROW} Remover pasta original (manter so o .tar.gz)? (s/N) "
        read -r remover
        if [[ "$remover" =~ ^[Ss]$ ]]; then
            rm -rf "$CASO_DIR"
            log_ok "Pasta original removida"
        fi
    fi

    echo ""
    echo -e "  ${DIM}Pode remover o pendrive com seguranca apos 'sync'.${NC}"
    echo ""
    sync
}

# ======================= MENU PRINCIPAL =======================

menu_principal() {
    while true; do
        banner
        echo -e "  ${BOLD}MENU PRINCIPAL${NC}"
        linha
        echo ""
        echo -e "  ${GREEN}1)${NC} Coleta completa ${DIM}(guiada passo a passo)${NC}"
        echo -e "  ${GREEN}2)${NC} Coleta rapida    ${DIM}(tudo automatico, sem imagem de disco)${NC}"
        echo -e "  ${GREEN}3)${NC} Verificar ferramentas instaladas"
        echo -e "  ${GREEN}4)${NC} Sobre / ajuda"
        echo -e "  ${RED}0)${NC} Sair"
        echo ""
        echo -ne "  ${ARROW} Opcao: "
        read -r opcao

        case "$opcao" in
            1) modo_guiado ;;
            2) modo_rapido ;;
            3) banner; verificar_ferramentas; pausar ;;
            4) menu_sobre ;;
            0) echo -e "\n  Ate logo.\n"; exit 0 ;;
            *) echo -e "\n  ${CROSS} Opcao invalida"; sleep 1 ;;
        esac
    done
}

# ======================= MODO GUIADO =======================

modo_guiado() {
    menu_destino || return
    menu_fases || return
    menu_confirmacao || return
    executar_coleta
}

# ======================= MODO RAPIDO =======================

modo_rapido() {
    menu_destino || return

    # Ativar tudo exceto imagem de disco e RAM se sem AVML
    FASES_SELECIONADAS=(1 3 4 5 6 7 8 9 10 11 12)
    [ -n "$AVML_PATH" ] && FASES_SELECIONADAS=(1 2 3 4 5 6 7 8 9 10 11 12)
    DISCO_ALVO=""

    banner
    echo -e "  ${BOLD}COLETA RAPIDA${NC}"
    linha
    echo ""
    echo -e "  Destino: ${CYAN}$DESTINO${NC}"
    echo -e "  Fases:   ${GREEN}Todas (sem imagem de disco)${NC}"
    [ -z "$AVML_PATH" ] && echo -e "  RAM:     ${YELLOW}Desabilitado (AVML nao encontrado)${NC}"
    echo ""
    echo -ne "  ${ARROW} Iniciar? (s/N) "
    read -r conf
    [[ "$conf" =~ ^[Ss]$ ]] || return

    executar_coleta
}

# ======================= EXECUTAR COLETA =======================

executar_coleta() {
    setup_caso
    contar_etapas
    ETAPA_ATUAL=0
    CONTAGEM_OK=0
    CONTAGEM_WARN=0
    CONTAGEM_ERRO=0

    banner
    echo -e "  ${BOLD}EXECUTANDO COLETA${NC}"
    linha
    echo -e "  ${DIM}Caso: $(basename "$CASO_DIR")${NC}"
    echo -e "  ${DIM}Etapas: $TOTAL_ETAPAS | Ctrl+C salva coleta parcial${NC}"

    for fase in "${FASES_SELECIONADAS[@]}"; do
        verificar_espaco
        case $fase in
            1)  fase_sistema ;;
            2)  fase_memoria ;;
            3)  fase_processos ;;
            4)  fase_rede ;;
            5)  fase_usuarios ;;
            6)  fase_arquivos ;;
            7)  fase_servicos ;;
            8)  fase_configuracoes ;;
            9)  fase_logs ;;
            10) fase_persistencia ;;
            11) fase_hashes ;;
            12) fase_timeline ;;
            13) fase_imagem_disco ;;
        esac
    done

    finalizar
    pausar
}

# ======================= SOBRE =======================

menu_sobre() {
    banner
    echo -e "  ${BOLD}SOBRE${NC}"
    linha
    echo ""
    echo -e "  ${CYAN}PENTEFINO${NC} - Linux Forensic Evidence Collector"
    echo -e "  Todo sistema deixa um rastro. Pentefino encontra."
    echo ""
    echo -e "  Captura dados volateis e nao-volateis em ordem de"
    echo -e "  prioridade, com hash SHA256 para cadeia de custodia."
    echo ""
    echo -e "  ${BOLD}Ordem de volatilidade:${NC}"
    echo -e "    1.  RAM              ${DIM}(mais volatil)${NC}"
    echo -e "    2.  Processos"
    echo -e "    3.  Conexoes de rede"
    echo -e "    4.  Usuarios logados"
    echo -e "    5.  Arquivos abertos"
    echo -e "    6.  Servicos/crons"
    echo -e "    7.  Configuracoes"
    echo -e "    8.  Logs"
    echo -e "    9.  Persistencia"
    echo -e "    10. Hashes"
    echo -e "    11. Timeline"
    echo -e "    12. Disco            ${DIM}(menos volatil)${NC}"
    echo ""
    echo -e "  ${BOLD}Funcionalidades:${NC}"
    echo -e "    - Menu interativo com selecao de fases"
    echo -e "    - Progresso em tempo real com porcentagem"
    echo -e "    - Compressao automatica de arquivos grandes"
    echo -e "    - Recuperacao de arquivos deletados"
    echo -e "    - Deteccao basica de rootkit"
    echo -e "    - Hash SHA256 de toda evidencia (custodia)"
    echo -e "    - Ctrl+C salva coleta parcial"
    echo -e "    - Exportar como .tar.gz"
    echo ""
    echo -e "  ${DIM}v${VERSAO} | GPLv3 | github.com/SEU_USER/pentefino${NC}"
    pausar
}

# ======================= MAIN =======================

verificar_root
menu_principal
