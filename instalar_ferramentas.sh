#!/bin/bash
# ============================================================
# INSTALADOR DE FERRAMENTAS FORENSES
# Executa uma vez no Kali para preparar o ambiente
# ============================================================

set -e

echo "============================================"
echo " PENTEFINO - Instalador de Dependencias"
echo " github.com/SEU_USER/pentefino"
echo "============================================"
echo ""

sudo apt update

echo "[1/6] Sleuth Kit + Autopsy 2.x"
sudo apt install -y sleuthkit autopsy

echo "[2/6] Volatility 3"
sudo apt install -y python3-pip
pip3 install volatility3 --break-system-packages 2>/dev/null || pip3 install volatility3

echo "[3/6] Ferramentas de imaging e carving"
sudo apt install -y dc3dd dcfldd hashdeep testdisk foremost bulk-extractor

echo "[4/6] Rede e logs"
sudo apt install -y tshark net-tools iproute2

echo "[5/6] AVML (captura de memoria - Microsoft)"
mkdir -p ~/forense/bin
if [ ! -f ~/forense/bin/avml ]; then
    wget -q --show-progress -O ~/forense/bin/avml \
        https://github.com/microsoft/avml/releases/latest/download/avml
    chmod +x ~/forense/bin/avml
    echo "    AVML baixado em ~/forense/bin/avml"
else
    echo "    AVML ja existe"
fi

echo "[6/6] UAC (Unix-like Artifacts Collector)"
if [ ! -d ~/forense/uac ]; then
    git clone https://github.com/tclahr/uac.git ~/forense/uac
    echo "    UAC clonado em ~/forense/uac"
else
    echo "    UAC ja existe"
    cd ~/forense/uac && git pull
fi

echo ""
echo "============================================"
echo " TUDO INSTALADO"
echo "============================================"
echo ""
echo " Ferramentas em ~/forense/bin/"
echo " UAC em ~/forense/uac/"
echo ""
echo " Proximo passo:"
echo "   sudo bash ~/forense/pentefino.sh"
echo ""
