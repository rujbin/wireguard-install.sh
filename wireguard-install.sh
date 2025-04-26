#!/bin/bash

# WireGuard Full Automation Script
# Installs WireGuard, configures server and first client, sets up firewall rules, generates QR code.
# Supports IPv4 and IPv6.

# --- Konfiguration (Anpassbar bei Bedarf) ---
WG_INTERFACE="wg0"
WG_PORT="51820" # Standard WireGuard Port
WG_IPV4_SUBNET="10.0.0.0/24" # Privates Subnetz für WireGuard VPN (IPv4)
WG_IPV6_SUBNET="fd86:ea04:4453::/64" # Privates Unique Local Address (ULA) Subnetz für WireGuard VPN (IPv6)
SERVER_WG_IPV4="10.0.0.1" # Server IP im WG Subnetz (IPv4)
SERVER_WG_IPV6="fd86:ea04:4453::1" # Server IP im WG Subnetz (IPv6)
CLIENT_WG_IPV4="10.0.0.2" # Erste Client IP im WG Subnetz (IPv4)
CLIENT_WG_IPV6="fd86:ea04:4453::2" # Erste Client IP im WG Subnetz (IPv6)
CLIENT_NAME="client1" # Name für die erste Client-Konfigurationsdatei
# DNS Server für Clients (optional, aber empfohlen)
# Cloudflare (Standard), Google oder eigene verwenden
CLIENT_DNS_1="1.1.1.1"
CLIENT_DNS_2="1.0.0.1" # Optional, leer lassen wenn nicht benötigt
CLIENT_DNS_IPV6="2606:4700:4700::1111" # Optionaler IPv6 DNS, leer lassen wenn nicht benötigt

# --- Ende der Konfiguration ---

# Globale Variablen
OS=""
VER=""
SERVER_PUB_NIC=""
SERVER_IPV4=""
SERVER_IPV6=""
USE_IPV6=false
SERVER_PRIVKEY=""
SERVER_PUBKEY=""
CLIENT_PRIVKEY=""
CLIENT_PUBKEY=""
CLIENT_CONF_PATH="" # Pfad zur finalen Client-Konfig
FIREWALLD_ACTIVE=false

# Exit on error
set -e

# --- Hilfsfunktionen ---
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "FEHLER: Dieses Skript muss als root ausgeführt werden (z.B. mit 'sudo bash $0')."
        exit 1
    fi
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VER=$DISTRIB_RELEASE
    elif [ -f /etc/debian_version ]; then
        OS=debian
        VER=$(cat /etc/debian_version)
    elif [ -f /etc/redhat-release ]; then
         OS=$(cat /etc/redhat-release | cut -d' ' -f1)
         VER=$(cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//)
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    OS=$(echo "$OS" | tr '[:upper:]' '[:lower:]') # Lowercase OS name
    echo "Betriebssystem erkannt: $OS $VER"
}

install_packages() {
    echo "Installiere notwendige Pakete..."
    if [[ "$OS" == "debian" || "$OS" == "ubuntu" ]]; then
        apt-get update
        # openresolv wird für DNS via wg-quick benötigt, iptables für PostUp/Down
        apt-get install -y wireguard-tools qrencode iptables openresolv
    elif [[ "$OS" == "centos" || "$OS" == "fedora" || "$OS" == "rhel" || "$OS" == "almalinux" || "$OS" == "rocky" ]]; then
        # Prüfe, ob firewalld oder iptables-services installiert sind
        PKG_MANAGER="dnf"
        if ! command -v dnf > /dev/null; then PKG_MANAGER="yum"; fi

        if [[ "$OS" == "centos" && ${VER%%.*} -eq 7 ]]; then
             echo "CentOS 7 wird erkannt. EPEL Repository wird benötigt."
             $PKG_MANAGER install -y epel-release
             # wireguard-dkms könnte auch nötig sein, falls Kernel < 5.6
             $PKG_MANAGER install -y wireguard-tools qrencode iptables-services # wireguard-dkms
        else
             # Neuere Systeme haben WireGuard meist im Kernel
             $PKG_MANAGER install -y wireguard-tools qrencode iptables # iptables für PostUp/Down Kommandos
        fi
        # Hinweis: Firewall-Konfiguration erfolgt in configure_firewall()
    else
        echo "FEHLER: Nicht unterstützte Distribution '$OS'. Bitte manuell installieren: wireguard-tools, qrencode, iptables."
        exit 1
    fi

    # Prüfe ob wg Kommando verfügbar ist
    command -v wg >/dev/null 2>&1 || { echo "FEHLER: 'wg' Befehl nach Installation nicht gefunden. Ist das Kernel-Modul geladen/installiert?"; exit 1; }
    echo "Notwendige Pakete installiert."
}

detect_network() {
    echo "Ermittle Netzwerk-Konfiguration..."
    SERVER_PUB_NIC=$(ip route | grep default | awk '{print $5}' | head -n 1)
    if [[ -z "$SERVER_PUB_NIC" ]]; then
        echo "FEHLER: Konnte das Standard-Netzwerkinterface nicht automatisch finden."
        exit 1
    fi
    echo "Öffentliches Interface erkannt: $SERVER_PUB_NIC"

    # Versuche öffentliche IPv4 zu ermitteln
    SERVER_IPV4=$(ip -4 addr show dev "$SERVER_PUB_NIC" | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 | head -n 1)
    if [[ -z "$SERVER_IPV4" || "$SERVER_IPV4" == 10.* || "$SERVER_IPV4" == 192.168.* || "$SERVER_IPV4" == 172.{16..31}.* ]]; then
        echo "Lokale IPv4 auf $SERVER_PUB_NIC ist privat oder nicht gefunden, versuche externen Dienst..."
        SERVER_IPV4=$(curl -4fsS https://ifconfig.me/ip || curl -4fsS https://api.ipify.org || wget -qO- -t1 -T2 ipv4.icanhazip.com)
    fi
    if [[ -z "$SERVER_IPV4" ]]; then
        echo "FEHLER: Konnte die öffentliche IPv4 Adresse nicht ermitteln."
        exit 1
    fi
    echo "Öffentliche IPv4 erkannt: $SERVER_IPV4"

    # Versuche öffentliche IPv6 zu ermitteln (optional)
    SERVER_IPV6=$(ip -6 addr show dev "$SERVER_PUB_NIC" scope global | grep 'inet6' | awk '{print $2}' | cut -d'/' -f1 | head -n 1)
    if [[ -z "$SERVER_IPV6" || "$SERVER_IPV6" == fe80::* ]]; then
        echo "Keine lokale globale IPv6 auf $SERVER_PUB_NIC gefunden, versuche externen Dienst..."
        SERVER_IPV6=$(curl -6fsS https://ifconfig.me/ip || curl -6fsS https://api6.ipify.org || wget -qO- -t1 -T2 ipv6.icanhazip.com)
    fi

    if [[ -z "$SERVER_IPV6" || "$SERVER_IPV6" == fe80::* ]]; then
        echo "WARNUNG: Konnte keine öffentliche IPv6 Adresse ermitteln oder nur Link-Local gefunden. IPv6 wird für Client-Endpoint und NAT übersprungen."
        USE_IPV6=false
    else
        echo "Öffentliche IPv6 erkannt: $SERVER_IPV6"
        USE_IPV6=true
    fi
}

configure_firewall() {
    echo "Konfiguriere Firewall..."

    # Prüfen ob firewalld aktiv ist (relevant für RHEL-basierte Systeme)
    if systemctl is-active --quiet firewalld && systemctl is-enabled --quiet firewalld; then
        FIREWALLD_ACTIVE=true
        echo "Firewalld ist aktiv. Konfiguriere firewalld..."
        # Öffne WireGuard Port permanent
        firewall-cmd --permanent --zone=public --add-port=${WG_PORT}/udp
        # Aktiviere Masquerading (NAT) für die Zone (sollte IPv4+IPv6 abdecken)
        firewall-cmd --permanent --zone=public --add-masquerade
        # Lade firewalld neu, um Regeln anzuwenden
        echo "Lade firewalld Regeln neu..."
        firewall-cmd --reload
        echo "Firewalld konfiguriert: Port ${WG_PORT}/udp geöffnet und Masquerading in Zone 'public' aktiviert."
    else
        FIREWALLD_ACTIVE=false
        echo "Firewalld nicht aktiv oder nicht installiert. Verwende iptables über PostUp/PostDown."
        # Füge temporäre Regel hinzu, um sicherzustellen, dass der Port offen ist,
        # bevor wg-quick die persistenten Regeln (falls vorhanden) lädt.
        if command -v iptables >/dev/null 2>&1; then
            if ! iptables -C INPUT -p udp --dport ${WG_PORT} -j ACCEPT > /dev/null 2>&1; then
                iptables -I INPUT -p udp --dport ${WG_PORT} -j ACCEPT
                echo "Temporäre iptables Regel für Port ${WG_PORT}/udp hinzugefügt."
            fi
        fi
         if [ "$USE_IPV6" = true ] && command -v ip6tables >/dev/null 2>&1; then
             if ! ip6tables -C INPUT -p udp --dport ${WG_PORT} -j ACCEPT > /dev/null 2>&1; then
                 ip6tables -I INPUT -p udp --dport ${WG_PORT} -j ACCEPT
                 echo "Temporäre ip6tables Regel für Port ${WG_PORT}/udp hinzugefügt."
             fi
         fi
         echo "NAT und Forwarding werden durch PostUp/PostDown in /etc/wireguard/${WG_INTERFACE}.conf geregelt."
         echo "HINWEIS: Wenn Sie iptables-services verwenden, stellen Sie sicher, dass die Regeln gespeichert werden (z.B. 'service iptables save' oder 'iptables-save > /etc/sysconfig/iptables')."
    fi
}


generate_keys() {
    echo "Generiere Schlüsselpaare..."
    umask 077 # Stelle sicher, dass Schlüssel nur für root lesbar sind
    mkdir -p /etc/wireguard/

    SERVER_PRIVKEY=$(wg genkey)
    SERVER_PUBKEY=$(echo "$SERVER_PRIVKEY" | wg pubkey)
    echo "$SERVER_PRIVKEY" > "/etc/wireguard/${WG_INTERFACE}_server_private.key"
    echo "$SERVER_PUBKEY" > "/etc/wireguard/${WG_INTERFACE}_server_public.key"
    chmod 600 "/etc/wireguard/${WG_INTERFACE}_server_private.key"

    CLIENT_PRIVKEY=$(wg genkey)
    CLIENT_PUBKEY=$(echo "$CLIENT_PRIVKEY" | wg pubkey)
    echo "$CLIENT_PRIVKEY" > "/etc/wireguard/${CLIENT_NAME}_private.key"
    echo "$CLIENT_PUBKEY" > "/etc/wireguard/${CLIENT_NAME}_public.key"
    chmod 600 "/etc/wireguard/${CLIENT_NAME}_private.key"

    echo "Schlüssel generiert und in /etc/wireguard/ gespeichert."
}

configure_server() {
    echo "Konfiguriere WireGuard Server (/etc/wireguard/${WG_INTERFACE}.conf)..."

    # Firewall-Regeln für PostUp/PostDown
    # HINWEIS: MASQUERADE Regeln werden nur eingefügt, wenn firewalld NICHT aktiv ist.
    IPTABLES_POSTUP="iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT" # Erlaube Forwarding in beide Richtungen
    IPTABLES_POSTDOWN="iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT"
    IP6TABLES_POSTUP=""
    IP6TABLES_POSTDOWN=""

    if [ "$FIREWALLD_ACTIVE" = false ]; then
        IPTABLES_POSTUP="${IPTABLES_POSTUP}; iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE"
        IPTABLES_POSTDOWN="${IPTABLES_POSTDOWN}; iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE"
        if [ "$USE_IPV6" = true ]; then
            IP6TABLES_POSTUP="ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -A FORWARD -o %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE"
            IP6TABLES_POSTDOWN="ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -D FORWARD -o %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE"
        fi
    else
        # Nur Forwarding Regeln wenn firewalld aktiv ist (Masquerade wird von firewalld gehandhabt)
         if [ "$USE_IPV6" = true ]; then
            IP6TABLES_POSTUP="ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -A FORWARD -o %i -j ACCEPT"
            IP6TABLES_POSTDOWN="ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -D FORWARD -o %i -j ACCEPT"
         fi
    fi

    # Server Konfigurationsdatei erstellen
    cat > "/etc/wireguard/${WG_INTERFACE}.conf" << EOF
[Interface]
Address = ${SERVER_WG_IPV4}/$(echo $WG_IPV4_SUBNET | cut -d'/' -f2)
$( [ "$USE_IPV6" = true ] && echo "Address = ${SERVER_WG_IPV6}/$(echo $WG_IPV6_SUBNET | cut -d'/' -f2)" )
ListenPort = ${WG_PORT}
PrivateKey = $(cat "/etc/wireguard/${WG_INTERFACE}_server_private.key")
# Firewall Regeln / NAT aktivieren (wenn nötig)
PostUp = ${IPTABLES_POSTUP}$( [ -n "$IP6TABLES_POSTUP" ] && echo "; ${IP6TABLES_POSTUP}" || echo "" )
PostDown = ${IPTABLES_POSTDOWN}$( [ -n "$IP6TABLES_POSTDOWN" ] && echo "; ${IP6TABLES_POSTDOWN}" || echo "" )
SaveConfig = false

# --- Erster Client ---
[Peer]
# Name = ${CLIENT_NAME}
PublicKey = $(cat "/etc/wireguard/${CLIENT_NAME}_public.key")
AllowedIPs = ${CLIENT_WG_IPV4}/32$( [ "$USE_IPV6" = true ] && echo ", ${CLIENT_WG_IPV6}/128" )
EOF
    chmod 600 "/etc/wireguard/${WG_INTERFACE}.conf"
    echo "Server Konfiguration erstellt."
}

configure_client() {
    # Pfad für die Client-Konfiguration bestimmen
    if [ -n "$SUDO_USER" ]; then
        # Versuche Home-Verzeichnis des ursprünglichen Benutzers zu finden
        USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        if [ -d "$USER_HOME" ]; then
             CLIENT_CONF_PATH="${USER_HOME}/${CLIENT_NAME}.conf"
             echo "Client Konfiguration wird in '$CLIENT_CONF_PATH' für Benutzer '$SUDO_USER' gespeichert."
        else
            CLIENT_CONF_PATH="/root/${CLIENT_NAME}.conf"
            echo "WARNUNG: Home-Verzeichnis für '$SUDO_USER' nicht gefunden. Speichere in '$CLIENT_CONF_PATH'."
        fi
    else
        CLIENT_CONF_PATH="/root/${CLIENT_NAME}.conf"
         echo "Kein SUDO_USER gefunden. Speichere Client Konfiguration in '$CLIENT_CONF_PATH'."
    fi

    echo "Erstelle Client Konfigurationsdatei (${CLIENT_CONF_PATH})..."

    # Wähle den Endpoint basierend auf verfügbarer IP Version
    ENDPOINT=""
    # Bevorzuge IPv6, wenn verfügbar und nicht link-local
    if [[ "$USE_IPV6" = true && -n "$SERVER_IPV6" && ! "$SERVER_IPV6" == fe80::* ]]; then
        ENDPOINT="[${SERVER_IPV6}]:${WG_PORT}"
    fi
    # Fallback auf IPv4 oder wenn nur IPv4 verfügbar
    if [[ -z "$ENDPOINT" && -n "$SERVER_IPV4" ]]; then
        ENDPOINT="${SERVER_IPV4}:${WG_PORT}"
    fi

    if [[ -z "$ENDPOINT" ]]; then
        echo "FEHLER: Konnte keinen gültigen Server Endpoint (IPv4 oder IPv6) bestimmen."
        exit 1
    fi
    echo "Client wird Endpoint verwenden: $ENDPOINT"

    # DNS String bauen
    DNS_STRING="${CLIENT_DNS_1}"
    [ -n "$CLIENT_DNS_2" ] && DNS_STRING="${DNS_STRING}, ${CLIENT_DNS_2}"
    [ -n "$CLIENT_DNS_IPV6" ] && DNS_STRING="${DNS_STRING}, ${CLIENT_DNS_IPV6}"

    # Client Konfigurationsdatei erstellen
    cat > "${CLIENT_CONF_PATH}" << EOF
[Interface]
# Name = ${CLIENT_NAME}
PrivateKey = $(cat "/etc/wireguard/${CLIENT_NAME}_private.key")
Address = ${CLIENT_WG_IPV4}/$(echo $WG_IPV4_SUBNET | cut -d'/' -f2)
$( [ "$USE_IPV6" = true ] && echo "Address = ${CLIENT_WG_IPV6}/$(echo $WG_IPV6_SUBNET | cut -d'/' -f2)" )
DNS = ${DNS_STRING}

[Peer]
# Name = Server
PublicKey = $(cat "/etc/wireguard/${WG_INTERFACE}_server_public.key")
Endpoint = ${ENDPOINT}
AllowedIPs = 0.0.0.0/0$( [ "$USE_IPV6" = true ] && echo ", ::/0" )
# Optional: PersistentKeepalive alle 25 Sekunden senden, um NAT/Firewall offen zu halten
# PersistentKeepalive = 25
EOF

    chmod 600 "${CLIENT_CONF_PATH}"
    # Berechtigungen anpassen, falls für sudo-Benutzer gespeichert
    if [ -n "$SUDO_USER" ] && [[ "$CLIENT_CONF_PATH" == "$USER_HOME"* ]]; then
         if id "$SUDO_USER" >/dev/null 2>&1; then
             chown "$SUDO_USER":"$(id -gn $SUDO_USER)" "${CLIENT_CONF_PATH}"
             echo "Besitz der Client-Konfiguration an '$SUDO_USER' übertragen."
         else
             echo "WARNUNG: Benutzer '$SUDO_USER' existiert nicht, Berechtigungen nicht geändert."
         fi
    fi
    echo "Client Konfiguration gespeichert in ${CLIENT_CONF_PATH}"
}

enable_forwarding() {
    echo "Aktiviere IP Forwarding..."
    CONF_FILE="/etc/sysctl.d/99-wireguard-forward.conf"
    NEEDS_RELOAD=false

    # IPv4 Forwarding
    if ! grep -qxF "net.ipv4.ip_forward=1" "$CONF_FILE" &>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> "$CONF_FILE"
        NEEDS_RELOAD=true
    fi
     # Aktiviere sofort
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # IPv6 Forwarding
    if [ "$USE_IPV6" = true ]; then
         if ! grep -qxF "net.ipv6.conf.all.forwarding=1" "$CONF_FILE" &>/dev/null; then
             echo "net.ipv6.conf.all.forwarding=1" >> "$CONF_FILE"
             NEEDS_RELOAD=true
         fi
         # Aktiviere sofort
         sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null
    fi

    if [ "$NEEDS_RELOAD" = true ]; then
        sysctl -p "$CONF_FILE" > /dev/null
        echo "IP Forwarding permanent aktiviert/aktualisiert in $CONF_FILE."
    else
        echo "IP Forwarding war bereits korrekt konfiguriert in $CONF_FILE."
    fi
}

start_wireguard() {
    echo "Starte und aktiviere WireGuard Service (wg-quick@${WG_INTERFACE})..."
    systemctl enable wg-quick@${WG_INTERFACE} > /dev/null
    # Restart statt start, um sicherzustellen, dass die neue Konfiguration geladen wird
    systemctl restart wg-quick@${WG_INTERFACE}

    # Kurze Pause und Statusprüfung
    sleep 2
    if systemctl is-active --quiet wg-quick@${WG_INTERFACE}; then
        echo "WireGuard Service läuft."
        wg show ${WG_INTERFACE}
    else
        echo "FEHLER: WireGuard Service konnte nicht gestartet werden!"
        echo "Überprüfe Logs mit: journalctl -u wg-quick@${WG_INTERFACE}"
        echo "Überprüfe Konfiguration: /etc/wireguard/${WG_INTERFACE}.conf"
        exit 1
    fi
}

generate_qr_code() {
    # Prüfe ob qrencode installiert ist
    if ! command -v qrencode >/dev/null 2>&1; then
        echo "WARNUNG: 'qrencode' Befehl nicht gefunden. QR-Code kann nicht generiert werden."
        echo "Installieren Sie 'qrencode' manuell und führen Sie 'qrencode -t ansiutf8 < ${CLIENT_CONF_PATH}' aus."
        return 1 # Signalisiert, dass QR-Code nicht generiert wurde
    fi

    echo "Generiere QR-Code für Client Konfiguration (${CLIENT_CONF_PATH})..."
    echo "Stellen Sie sicher, dass Ihr Terminal UTF-8 unterstützt und die Schriftgröße klein genug ist."
    echo ""
    qrencode -t ansiutf8 < "${CLIENT_CONF_PATH}"
    echo ""
    echo "QR-Code oben kann mit der WireGuard Mobile App gescannt werden."
    return 0
}

# --- Hauptablauf ---
check_root
detect_distro
install_packages
detect_network
configure_firewall # Firewall konfigurieren *vor* Schlüsselerzeugung/Serverkonfig
generate_keys
configure_server # Verwendet $FIREWALLD_ACTIVE
configure_client # Verwendet $SUDO_USER
enable_forwarding
start_wireguard

# QR Code nur generieren wenn qrencode vorhanden ist
QR_GENERATED=false
if generate_qr_code; then
    QR_GENERATED=true
fi

echo ""
echo "--- WireGuard Installation abgeschlossen ---"
echo "Server Konfiguration: /etc/wireguard/${WG_INTERFACE}.conf"
echo "Server Private Key:   /etc/wireguard/${WG_INTERFACE}_server_private.key"
echo "Client Konfiguration: ${CLIENT_CONF_PATH}"
echo "Client Private Key:   /etc/wireguard/${CLIENT_NAME}_private.key"

if [ "$QR_GENERATED" = false ]; then
     echo "Client QR-Code konnte nicht generiert werden (siehe Warnung oben)."
fi

echo ""
echo "Der WireGuard-Dienst läuft und ist für den Start beim Booten aktiviert."
if [ "$FIREWALLD_ACTIVE" = true ]; then
    echo "Firewalld wurde konfiguriert (Port ${WG_PORT}/udp und Masquerading)."
else
    echo "Stellen Sie sicher, dass der UDP Port ${WG_PORT} in Ihrer externen Firewall (falls vorhanden) geöffnet ist."
    echo "NAT/Forwarding werden über PostUp/Down in der wg-Konfigurationsdatei gehandhabt."
fi
echo ""
echo "Um einen weiteren Client hinzuzufügen: "
echo "1. Generieren Sie ein neues Schlüsselpaar (wg genkey | tee clientX_private.key | wg pubkey > clientX_public.key)."
echo "2. Fügen Sie einen neuen [Peer] Block zur /etc/wireguard/${WG_INTERFACE}.conf hinzu mit dem Public Key des neuen Clients und einer freien IP aus ${WG_IPV4_SUBNET} / ${WG_IPV6_SUBNET}."
echo "   Beispiel:"
echo "   [Peer]"
echo "   # Name = clientX"
echo "   PublicKey = <Public Key von clientX_public.key>"
echo "   AllowedIPs = 10.0.0.X/32, fd86:ea04:4453::X/128"
echo "3. Starten Sie den WireGuard Dienst neu: systemctl restart wg-quick@${WG_INTERFACE}"
echo "4. Erstellen Sie die Konfigurationsdatei für den neuen Client (ähnlich wie ${CLIENT_CONF_PATH})."

exit 0
