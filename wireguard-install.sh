#!/bin/bash

# WireGuard Full Automation Script
# Installs WireGuard, configures server and first client, sets up firewall rules, generates QR code.
# Supports IPv4 and IPv6.
# UPDATED: Checks for existing config and offers to add new clients.

# --- Konfiguration (Anpassbar bei Bedarf) ---
WG_INTERFACE="wg0"
WG_PORT="51820" # Standard WireGuard Port
WG_IPV4_SUBNET="10.0.0.0/24" # Privates Subnetz für WireGuard VPN (IPv4)
WG_IPV6_SUBNET="fd86:ea04:4453::/64" # Privates Unique Local Address (ULA) Subnetz für WireGuard VPN (IPv6)
SERVER_WG_IPV4="10.0.0.1" # Server IP im WG Subnetz (IPv4)
SERVER_WG_IPV6="fd86:ea04:4453::1" # Server IP im WG Subnetz (IPv6)
# CLIENT_WG_IPV4="10.0.0.2" # Erste Client IP - wird jetzt dynamischer ermittelt oder für den ersten Client verwendet
# CLIENT_WG_IPV6="fd86:ea04:4453::2" # Erste Client IP - wird jetzt dynamischer ermittelt oder für den ersten Client verwendet
FIRST_CLIENT_NAME="client1" # Name für die *erste* Client-Konfigurationsdatei
# DNS Server für Clients (optional, aber empfohlen)
CLIENT_DNS_1="1.1.1.1" # Cloudflare (Standard), Google oder eigene verwenden
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
SERVER_PRIVKEY="" # Wird nur bei Neuinstallation gesetzt
SERVER_PUBKEY=""  # Wird nur bei Neuinstallation gesetzt oder aus Datei gelesen
# Client Keys werden jetzt pro Client generiert
# CLIENT_PRIVKEY=""
# CLIENT_PUBKEY=""
CLIENT_CONF_PATH="" # Pfad zur finalen Client-Konfig (wird dynamisch gesetzt)
FIREWALLD_ACTIVE=false
WG_CONF_FILE="/etc/wireguard/${WG_INTERFACE}.conf"
SERVER_PUBKEY_FILE="/etc/wireguard/${WG_INTERFACE}_server_public.key"
SERVER_PRIVKEY_FILE="/etc/wireguard/${WG_INTERFACE}_server_private.key" # Für die Server-Konfig benötigt

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
    # (Funktion unverändert)
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
    # (Funktion leicht angepasst für Klarheit)
    echo "Installiere notwendige Pakete (falls noch nicht vorhanden)..."
    PACKAGES_NEEDED="wireguard-tools qrencode iptables" # Basispakete
    PACKAGES_TO_INSTALL=""

    for pkg in $PACKAGES_NEEDED; do
        if ! command -v $pkg >/dev/null 2>&1 && ! dpkg -s $pkg > /dev/null 2>&1 && ! rpm -q $pkg > /dev/null 2>&1; then
             PACKAGES_TO_INSTALL="${PACKAGES_TO_INSTALL} ${pkg}"
        fi
    done

     # Distributionsspezifische Pakete/Manager
     if [[ "$OS" == "debian" || "$OS" == "ubuntu" ]]; then
         PKG_MANAGER="apt-get"
         UPDATE_CMD="apt-get update"
         INSTALL_CMD="apt-get install -y"
         # Evtl. iptables-persistent hinzufügen, falls gewünscht
     elif [[ "$OS" == "centos" || "$OS" == "fedora" || "$OS" == "rhel" || "$OS" == "almalinux" || "$OS" == "rocky" ]]; then
         PKG_MANAGER="dnf"
         if ! command -v dnf > /dev/null; then PKG_MANAGER="yum"; fi
         UPDATE_CMD="" # dnf/yum machen das implizit
         INSTALL_CMD="$PKG_MANAGER install -y"
         if [[ "$OS" == "centos" && ${VER%%.*} -eq 7 ]]; then
            # EPEL für CentOS 7 benötigt
            if ! rpm -q epel-release > /dev/null 2>&1; then
                echo "CentOS 7: Installiere EPEL Repository..."
                $PKG_MANAGER install -y epel-release
            fi
            # iptables-services für persistente Regeln auf C7
            if ! rpm -q iptables-services > /dev/null 2>&1; then
                 PACKAGES_TO_INSTALL="${PACKAGES_TO_INSTALL} iptables-services"
            fi
         fi
     else
         echo "FEHLER: Nicht unterstützte Distribution '$OS'. Bitte manuell installieren: $PACKAGES_NEEDED."
         exit 1
     fi

     if [ -n "$PACKAGES_TO_INSTALL" ]; then
        echo "Folgende Pakete werden installiert: $PACKAGES_TO_INSTALL"
        if [ -n "$UPDATE_CMD" ]; then $UPDATE_CMD; fi
        $INSTALL_CMD $PACKAGES_TO_INSTALL
     else
        echo "Notwendige Pakete scheinen bereits installiert zu sein."
     fi

    # Prüfe ob wg Kommando verfügbar ist
    command -v wg >/dev/null 2>&1 || { echo "FEHLER: 'wg' Befehl nach Installation nicht gefunden. Ist das Kernel-Modul geladen/installiert?"; exit 1; }
    echo "Paketprüfung abgeschlossen."
}


detect_network() {
    # (Funktion unverändert)
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
        SERVER_IPV4=$(curl -4fsS https://ifconfig.me/ip || curl -4fsS https://api.ipify.org || wget -qO- -t1 -T2 ipv4.icanhazip.com || echo "")
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
        SERVER_IPV6=$(curl -6fsS https://ifconfig.me/ip || curl -6fsS https://api6.ipify.org || wget -qO- -t1 -T2 ipv6.icanhazip.com || echo "")
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
    # (Funktion unverändert)
    echo "Konfiguriere Firewall..."

    # Prüfen ob firewalld aktiv ist (relevant für RHEL-basierte Systeme)
    if systemctl is-active --quiet firewalld && systemctl is-enabled --quiet firewalld; then
        FIREWALLD_ACTIVE=true
        echo "Firewalld ist aktiv. Konfiguriere firewalld..."
        # Öffne WireGuard Port permanent
        firewall-cmd --permanent --zone=public --add-port=${WG_PORT}/udp
        # Aktiviere Masquerading (NAT) für die Zone (sollte IPv4+IPv6 abdecken)
        # Prüfe ob Masquerading schon aktiv ist, um Meldungen zu vermeiden
        if ! firewall-cmd --query-masquerade --permanent > /dev/null; then
             firewall-cmd --permanent --zone=public --add-masquerade
        fi
        # Lade firewalld neu, um Regeln anzuwenden
        echo "Lade firewalld Regeln neu..."
        firewall-cmd --reload
        echo "Firewalld konfiguriert: Port ${WG_PORT}/udp geöffnet und Masquerading in Zone 'public' aktiviert (falls noch nicht geschehen)."
    else
        FIREWALLD_ACTIVE=false
        echo "Firewalld nicht aktiv oder nicht installiert. Verwende iptables über PostUp/PostDown."
        # Füge temporäre Regel hinzu, um sicherzustellen, dass der Port offen ist,
        # bevor wg-quick die persistenten Regeln (falls vorhanden) lädt.
        if command -v iptables >/dev/null 2>&1; then
            if ! iptables -C INPUT -p udp --dport ${WG_PORT} -j ACCEPT > /dev/null 2>&1; then
                iptables -I INPUT 1 -p udp --dport ${WG_PORT} -j ACCEPT # Insert at top
                echo "Temporäre iptables Regel für Port ${WG_PORT}/udp hinzugefügt."
            fi
        fi
         if [ "$USE_IPV6" = true ] && command -v ip6tables >/dev/null 2>&1; then
            if ! ip6tables -C INPUT -p udp --dport ${WG_PORT} -j ACCEPT > /dev/null 2>&1; then
                 ip6tables -I INPUT 1 -p udp --dport ${WG_PORT} -j ACCEPT # Insert at top
                 echo "Temporäre ip6tables Regel für Port ${WG_PORT}/udp hinzugefügt."
            fi
         fi
         echo "NAT und Forwarding werden durch PostUp/PostDown in ${WG_CONF_FILE} geregelt."
         echo "HINWEIS: Wenn Sie iptables-services oder nftables verwenden, stellen Sie sicher, dass die Regeln gespeichert werden (z.B. 'service iptables save', 'iptables-save > /etc/sysconfig/iptables', 'systemctl enable nftables')."
    fi
}

# $1: Client Name
# $2: Client Private Key File Path
# $3: Client Public Key File Path
generate_client_keys() {
    local client_name="$1"
    local privkey_file="$2"
    local pubkey_file="$3"
    echo "Generiere Schlüsselpaar für Client '$client_name'..."
    umask 077
    local client_privkey=$(wg genkey)
    local client_pubkey=$(echo "$client_privkey" | wg pubkey)
    echo "$client_privkey" > "$privkey_file"
    echo "$client_pubkey" > "$pubkey_file"
    chmod 600 "$privkey_file"
    echo "Schlüssel für '$client_name' gespeichert in /etc/wireguard/"
}


generate_server_keys() {
    echo "Generiere Server Schlüsselpaar..."
    umask 077 # Stelle sicher, dass Schlüssel nur für root lesbar sind
    mkdir -p /etc/wireguard/
    SERVER_PRIVKEY=$(wg genkey)
    SERVER_PUBKEY=$(echo "$SERVER_PRIVKEY" | wg pubkey)
    echo "$SERVER_PRIVKEY" > "$SERVER_PRIVKEY_FILE"
    echo "$SERVER_PUBKEY" > "$SERVER_PUBKEY_FILE"
    chmod 600 "$SERVER_PRIVKEY_FILE"
    echo "Server Schlüssel generiert und in /etc/wireguard/ gespeichert."
}

# $1: Client Name
# $2: Client Config File Path
# $3: Client Private Key
# $4: Client WG IPv4
# $5: Client WG IPv6 (kann leer sein)
# $6: Server Public Key
# $7: Server Endpoint
create_client_config_file() {
    local client_name="$1"
    local client_conf_path="$2"
    local client_privkey="$3"
    local client_wg_ipv4="$4"
    local client_wg_ipv6="$5"
    local server_pubkey="$6"
    local server_endpoint="$7"

    local ipv4_cidr=$(echo $WG_IPV4_SUBNET | cut -d'/' -f2)
    local ipv6_cidr=$(echo $WG_IPV6_SUBNET | cut -d'/' -f2)

    # DNS String bauen
    local DNS_STRING="${CLIENT_DNS_1}"
    [ -n "$CLIENT_DNS_2" ] && DNS_STRING="${DNS_STRING}, ${CLIENT_DNS_2}"
    [ -n "$CLIENT_DNS_IPV6" ] && [ "$USE_IPV6" = true ] && DNS_STRING="${DNS_STRING}, ${CLIENT_DNS_IPV6}"

    echo "Erstelle Client Konfigurationsdatei (${client_conf_path})..."
    cat > "${client_conf_path}" << EOF
[Interface]
# Name = ${client_name}
PrivateKey = ${client_privkey}
Address = ${client_wg_ipv4}/${ipv4_cidr}
$( [ "$USE_IPV6" = true ] && [ -n "$client_wg_ipv6" ] && echo "Address = ${client_wg_ipv6}/${ipv6_cidr}" )
DNS = ${DNS_STRING}

[Peer]
# Name = Server
PublicKey = ${server_pubkey}
Endpoint = ${server_endpoint}
AllowedIPs = 0.0.0.0/0$( [ "$USE_IPV6" = true ] && echo ", ::/0" )
# Optional: PersistentKeepalive alle 25 Sekunden senden, um NAT/Firewall offen zu halten
# PersistentKeepalive = 25
EOF

    chmod 600 "${client_conf_path}"
     # Berechtigungen anpassen, falls für sudo-Benutzer gespeichert
    if [ -n "$SUDO_USER" ]; then
        USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        if [[ -d "$USER_HOME" && "$client_conf_path" == "$USER_HOME"* ]]; then
            if id "$SUDO_USER" >/dev/null 2>&1; then
                chown "$SUDO_USER":"$(id -gn $SUDO_USER)" "${client_conf_path}"
                echo "Besitz der Client-Konfiguration an '$SUDO_USER' übertragen."
            else
                 echo "WARNUNG: Benutzer '$SUDO_USER' existiert nicht, Berechtigungen nicht geändert."
            fi
        fi
    fi
    echo "Client Konfiguration gespeichert in ${client_conf_path}"
}

configure_server() {
    echo "Konfiguriere WireGuard Server (${WG_CONF_FILE})..."

    # Firewall-Regeln für PostUp/PostDown
    # HINWEIS: MASQUERADE Regeln werden nur eingefügt, wenn firewalld NICHT aktiv ist.
    IPTABLES_POSTUP="iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT"
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
    cat > "${WG_CONF_FILE}" << EOF
[Interface]
Address = ${SERVER_WG_IPV4}/$(echo $WG_IPV4_SUBNET | cut -d'/' -f2)
$( [ "$USE_IPV6" = true ] && echo "Address = ${SERVER_WG_IPV6}/$(echo $WG_IPV6_SUBNET | cut -d'/' -f2)" )
ListenPort = ${WG_PORT}
PrivateKey = $(cat "${SERVER_PRIVKEY_FILE}")
# Firewall Regeln / NAT aktivieren (wenn nötig)
PostUp = ${IPTABLES_POSTUP}$( [ -n "$IP6TABLES_POSTUP" ] && echo "; ${IP6TABLES_POSTUP}" || echo "" )
PostDown = ${IPTABLES_POSTDOWN}$( [ -n "$IP6TABLES_POSTDOWN" ] && echo "; ${IP6TABLES_POSTDOWN}" || echo "" )
SaveConfig = false

# --- Peers folgen hier ---

EOF
    chmod 600 "${WG_CONF_FILE}"
    echo "Server Grundkonfiguration erstellt."
}

# $1: Client Name
# $2: Client Public Key
# $3: Client WG IPv4
# $4: Client WG IPv6 (kann leer sein)
add_peer_to_server_config() {
    local client_name="$1"
    local client_pubkey="$2"
    local client_wg_ipv4="$3"
    local client_wg_ipv6="$4"

    echo "Füge Peer '$client_name' zur Server Konfiguration hinzu..."
    cat >> "${WG_CONF_FILE}" << EOF

# --- Client: ${client_name} ---
[Peer]
# Name = ${client_name}
PublicKey = ${client_pubkey}
AllowedIPs = ${client_wg_ipv4}/32$( [ "$USE_IPV6" = true ] && [ -n "$client_wg_ipv6" ] && echo ", ${client_wg_ipv6}/128" )
EOF
    echo "Peer '$client_name' hinzugefügt."
}


enable_forwarding() {
    # (Funktion unverändert)
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
        echo "IP Forwarding war bereits korrekt konfiguriert (oder wurde soeben aktiviert)."
    fi
}

start_wireguard() {
    echo "Starte/Restarte und aktiviere WireGuard Service (wg-quick@${WG_INTERFACE})..."
    # Sicherstellen, dass der Service aktiviert ist
    if ! systemctl is-enabled --quiet wg-quick@${WG_INTERFACE}; then
        systemctl enable wg-quick@${WG_INTERFACE} > /dev/null
    fi
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
        echo "Überprüfe Konfiguration: ${WG_CONF_FILE}"
        # Bei Neuinstallation ggf. relevante Schlüsselpfade nennen
        if [ ! -f "$SERVER_PRIVKEY_FILE" ]; then
             echo "Server Private Key fehlt? ${SERVER_PRIVKEY_FILE}"
        fi
        # Wenn es um einen neuen Client ging, ist der Server-Log relevant
        exit 1
    fi
}

# $1: Client Config File Path
generate_qr_code() {
    local client_conf_path="$1"
    # Prüfe ob qrencode installiert ist
    if ! command -v qrencode >/dev/null 2>&1; then
        echo "WARNUNG: 'qrencode' Befehl nicht gefunden. QR-Code kann nicht generiert werden."
        echo "Installieren Sie 'qrencode' manuell und führen Sie 'qrencode -t ansiutf8 < ${client_conf_path}' aus."
        return 1 # Signalisiert, dass QR-Code nicht generiert wurde
    fi

    if [ ! -f "$client_conf_path" ]; then
        echo "FEHLER: Client Konfigurationsdatei '${client_conf_path}' nicht gefunden für QR-Code Generierung."
        return 1
    fi

    echo "Generiere QR-Code für Client Konfiguration (${client_conf_path})..."
    echo "Stellen Sie sicher, dass Ihr Terminal UTF-8 unterstützt und die Schriftgröße klein genug ist."
    echo ""
    qrencode -t ansiutf8 < "${client_conf_path}"
    echo ""
    echo "QR-Code oben kann mit der WireGuard Mobile App gescannt werden."
    return 0
}

# Funktion zum Ermitteln der nächsten freien IPs
find_next_ips() {
    local last_ipv4_suffix=1 # Start bei .2 (Suffix 1 ist Server)
    local last_ipv6_suffix=1 # Start bei ::2 (Suffix 1 ist Server)
    local ipv4_base=$(echo $SERVER_WG_IPV4 | cut -d'.' -f1-3)
    local ipv6_base=$(echo $SERVER_WG_IPV6 | sed 's/::1$//') # Basis-Teil der ULA

    # Extrahiere alle vorhandenen Client-IP-Suffixe aus AllowedIPs
    if [ -f "$WG_CONF_FILE" ]; then
        # IPv4 Suffixe
        current_ipv4_suffixes=$(grep AllowedIPs "$WG_CONF_FILE" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep "^${ipv4_base}\." | cut -d'.' -f4 | sort -n)
        if [ -n "$current_ipv4_suffixes" ]; then
            last_ipv4_suffix=$(echo "$current_ipv4_suffixes" | tail -n 1)
        fi

        # IPv6 Suffixe (Hex)
        if [ "$USE_IPV6" = true ]; then
             # Extrahieren, ::X am Ende suchen, X (Hex) nehmen, dezimal umwandeln, sortieren
             current_ipv6_suffixes_hex=$(grep AllowedIPs "$WG_CONF_FILE" | grep -oE 'fd[0-9a-f:]+::[0-9a-f]+' | grep "^${ipv6_base}::" | sed 's/.*:://' | sort -n)
             if [ -n "$current_ipv6_suffixes_hex" ]; then
                 last_ipv6_suffix_hex=$(echo "$current_ipv6_suffixes_hex" | tail -n 1)
                 # Konvertiere Hex zu Dezimal für Inkrementierung
                 last_ipv6_suffix=$((16#$last_ipv6_suffix_hex))
             fi
        fi
    fi

    # Nächste IPs berechnen
    NEXT_CLIENT_WG_IPV4="${ipv4_base}.$((last_ipv4_suffix + 1))"
    if [ "$USE_IPV6" = true ]; then
        next_ipv6_suffix_dec=$((last_ipv6_suffix + 1))
        # Konvertiere zurück zu Hex für die Adresse
        next_ipv6_suffix_hex=$(printf '%x\n' $next_ipv6_suffix_dec)
        NEXT_CLIENT_WG_IPV6="${ipv6_base}::${next_ipv6_suffix_hex}"
    else
        NEXT_CLIENT_WG_IPV6=""
    fi

    echo "Nächste verfügbare Client IPs: IPv4=$NEXT_CLIENT_WG_IPV4, IPv6=$NEXT_CLIENT_WG_IPV6"
}

# Workflow zum Hinzufügen eines neuen Clients
add_new_client_workflow() {
    echo ""
    echo "--- Neuen WireGuard Client hinzufügen ---"

    # Nächste IPs finden
    find_next_ips # Setzt NEXT_CLIENT_WG_IPV4 und NEXT_CLIENT_WG_IPV6

    # Client Namen abfragen
    local new_client_name=""
    while [[ -z "$new_client_name" ]]; do
        read -p "Geben Sie einen Namen für den neuen Client ein (z.B. handy_peter): " new_client_name
        # Einfache Validierung: keine Leerzeichen, nicht leer
        if [[ "$new_client_name" =~ \s ]] || [[ -z "$new_client_name" ]]; then
            echo "Ungültiger Name. Bitte keine Leerzeichen verwenden."
            new_client_name=""
        fi
        # Prüfen ob Schlüsseldateien schon existieren
        if [ -f "/etc/wireguard/${new_client_name}_private.key" ]; then
             echo "WARNUNG: Schlüsseldatei /etc/wireguard/${new_client_name}_private.key existiert bereits. Überschreiben?"
             read -p "Fortfahren? (j/N): " confirm_overwrite
             if [[ ! "$confirm_overwrite" =~ ^[jJ]([aA])?$ ]]; then
                 new_client_name="" # Erneut fragen
             fi
        fi
    done

    local client_privkey_file="/etc/wireguard/${new_client_name}_private.key"
    local client_pubkey_file="/etc/wireguard/${new_client_name}_public.key"

    # Client Schlüssel generieren
    generate_client_keys "$new_client_name" "$client_privkey_file" "$client_pubkey_file"
    local client_privkey=$(cat "$client_privkey_file")
    local client_pubkey=$(cat "$client_pubkey_file")

    # Peer zur Server Konfiguration hinzufügen
    add_peer_to_server_config "$new_client_name" "$client_pubkey" "$NEXT_CLIENT_WG_IPV4" "$NEXT_CLIENT_WG_IPV6"

    # Server Public Key und Endpoint bestimmen (brauchen wir für Client-Konfig)
    if [ ! -f "$SERVER_PUBKEY_FILE" ]; then
        echo "FEHLER: Server Public Key Datei (${SERVER_PUBKEY_FILE}) nicht gefunden!"
        exit 1
    fi
    local server_pubkey=$(cat "$SERVER_PUBKEY_FILE")

    # Endpoint bestimmen (wie im Original-Skript)
    local ENDPOINT=""
    if [[ "$USE_IPV6" = true && -n "$SERVER_IPV6" && ! "$SERVER_IPV6" == fe80::* ]]; then
        ENDPOINT="[${SERVER_IPV6}]:${WG_PORT}"
    fi
    if [[ -z "$ENDPOINT" && -n "$SERVER_IPV4" ]]; then
        ENDPOINT="${SERVER_IPV4}:${WG_PORT}"
    fi
    if [[ -z "$ENDPOINT" ]]; then
        echo "FEHLER: Konnte keinen gültigen Server Endpoint (IPv4 oder IPv6) bestimmen."
        exit 1
    fi
    echo "Server Endpoint für Client: $ENDPOINT"

    # Pfad für Client-Konfig bestimmen
    local client_conf_path=""
    if [ -n "$SUDO_USER" ]; then
        USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        if [ -d "$USER_HOME" ]; then
            client_conf_path="${USER_HOME}/${new_client_name}.conf"
            echo "Client Konfiguration wird in '$client_conf_path' für Benutzer '$SUDO_USER' gespeichert."
        else
            client_conf_path="/root/${new_client_name}.conf"
            echo "WARNUNG: Home-Verzeichnis für '$SUDO_USER' nicht gefunden. Speichere in '$client_conf_path'."
        fi
    else
        client_conf_path="/root/${new_client_name}.conf"
        echo "Kein SUDO_USER gefunden. Speichere Client Konfiguration in '$client_conf_path'."
    fi

    # Client Konfigurationsdatei erstellen
    create_client_config_file "$new_client_name" "$client_conf_path" "$client_privkey" "$NEXT_CLIENT_WG_IPV4" "$NEXT_CLIENT_WG_IPV6" "$server_pubkey" "$ENDPOINT"

    # WireGuard neu starten, um den neuen Peer zu laden
    start_wireguard

    # QR Code generieren
    generate_qr_code "$client_conf_path"

    echo ""
    echo "--- Neuer Client '$new_client_name' hinzugefügt ---"
    echo "Server Konfiguration aktualisiert: ${WG_CONF_FILE}"
    echo "Client Konfiguration gespeichert: ${client_conf_path}"
    echo "Client Private Key: ${client_privkey_file}"
    echo "Verwenden Sie die Konfigurationsdatei oder den QR-Code auf dem Client-Gerät."
}


# --- Hauptablauf ---
check_root
detect_distro
detect_network # Netzwerkinfo wird immer benötigt (für Endpoint)

if [ -f "$WG_CONF_FILE" ]; then
    echo "Vorhandene WireGuard-Konfiguration gefunden: $WG_CONF_FILE"
    # Prüfen ob der Service läuft
    if systemctl is-active --quiet wg-quick@${WG_INTERFACE}; then
         echo "WireGuard Service (wg-quick@${WG_INTERFACE}) ist aktiv."
    else
         echo "WARNUNG: WireGuard Service (wg-quick@${WG_INTERFACE}) ist NICHT aktiv."
         read -p "Möchten Sie versuchen, den Dienst zu starten? (j/N): " start_service
         if [[ "$start_service" =~ ^[jJ]([aA])?$ ]]; then
             start_wireguard # Versucht Start/Restart & Aktivierung
         fi
    fi

    echo ""
    read -p "Möchten Sie einen neuen Client hinzufügen? (j/N): " add_client
    if [[ "$add_client" =~ ^[jJ]([aA])?$ ]]; then
        # Pakete prüfen/installieren, falls doch was fehlt (z.B. qrencode)
        install_packages
        # Firewall prüfen/konfigurieren (schadet nicht, falls Regeln fehlen)
        configure_firewall
        # IP Forwarding prüfen/aktivieren (wichtig!)
        enable_forwarding
        # Den neuen Client hinzufügen
        add_new_client_workflow
    else
        echo "Keine Änderungen vorgenommen. Skript wird beendet."
        exit 0
    fi
else
    echo "Keine vorhandene WireGuard-Konfiguration gefunden (${WG_CONF_FILE})."
    echo "Starte erstmalige Installation und Konfiguration..."
    echo ""

    install_packages
    configure_firewall
    generate_server_keys # Server Keys generieren
    # Ersten Client vorbereiten
    FIRST_CLIENT_PRIVKEY_FILE="/etc/wireguard/${FIRST_CLIENT_NAME}_private.key"
    FIRST_CLIENT_PUBKEY_FILE="/etc/wireguard/${FIRST_CLIENT_NAME}_public.key"
    generate_client_keys "$FIRST_CLIENT_NAME" "$FIRST_CLIENT_PRIVKEY_FILE" "$FIRST_CLIENT_PUBKEY_FILE"
    FIRST_CLIENT_PRIVKEY=$(cat "$FIRST_CLIENT_PRIVKEY_FILE")
    FIRST_CLIENT_PUBKEY=$(cat "$FIRST_CLIENT_PUBKEY_FILE")

    # Nächste IPs für den *ersten* Client finden (wird typischerweise .2 / ::2 sein)
    find_next_ips
    FIRST_CLIENT_WG_IPV4=$NEXT_CLIENT_WG_IPV4
    FIRST_CLIENT_WG_IPV6=$NEXT_CLIENT_WG_IPV6

    configure_server # Server Basiskonfig erstellen
    add_peer_to_server_config "$FIRST_CLIENT_NAME" "$FIRST_CLIENT_PUBKEY" "$FIRST_CLIENT_WG_IPV4" "$FIRST_CLIENT_WG_IPV6" # Ersten Peer hinzufügen

    # Server Public Key und Endpoint bestimmen
    if [ ! -f "$SERVER_PUBKEY_FILE" ]; then echo "FEHLER: Server Public Key Datei nicht gefunden!"; exit 1; fi
    server_pubkey=$(cat "$SERVER_PUBKEY_FILE")
    ENDPOINT=""
    if [[ "$USE_IPV6" = true && -n "$SERVER_IPV6" && ! "$SERVER_IPV6" == fe80::* ]]; then
        ENDPOINT="[${SERVER_IPV6}]:${WG_PORT}"
    fi
    if [[ -z "$ENDPOINT" && -n "$SERVER_IPV4" ]]; then
        ENDPOINT="${SERVER_IPV4}:${WG_PORT}"
    fi
    if [[ -z "$ENDPOINT" ]]; then echo "FEHLER: Konnte keinen gültigen Server Endpoint bestimmen."; exit 1; fi

    # Pfad für erste Client-Konfig bestimmen
    client_conf_path=""
    if [ -n "$SUDO_USER" ]; then
        USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        if [ -d "$USER_HOME" ]; then
            client_conf_path="${USER_HOME}/${FIRST_CLIENT_NAME}.conf"
        else
            client_conf_path="/root/${FIRST_CLIENT_NAME}.conf"
        fi
    else
        client_conf_path="/root/${FIRST_CLIENT_NAME}.conf"
    fi
    CLIENT_CONF_PATH=$client_conf_path # Für die Abschlussmeldung

    # Erste Client Konfigurationsdatei erstellen
    create_client_config_file "$FIRST_CLIENT_NAME" "$client_conf_path" "$FIRST_CLIENT_PRIVKEY" "$FIRST_CLIENT_WG_IPV4" "$FIRST_CLIENT_WG_IPV6" "$server_pubkey" "$ENDPOINT"

    enable_forwarding
    start_wireguard

    # QR Code generieren
    QR_GENERATED=false
    if generate_qr_code "$client_conf_path"; then
        QR_GENERATED=true
    fi

    echo ""
    echo "--- WireGuard Erstinstallation abgeschlossen ---"
    echo "Server Konfiguration: ${WG_CONF_FILE}"
    echo "Server Private Key:   ${SERVER_PRIVKEY_FILE}"
    echo "Server Public Key:    ${SERVER_PUBKEY_FILE}"
    echo "Erste Client Konfig:  ${CLIENT_CONF_PATH}"
    echo "Erste Client PrivKey: ${FIRST_CLIENT_PRIVKEY_FILE}"

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
    echo "Um dieses Skript erneut auszuführen, wird es anbieten, weitere Clients hinzuzufügen."

fi

exit 0
