#!/bin/bash

# WireGuard Full Automation Script
# Installs WireGuard, configures server and first client, sets up iptables rules, generates QR code.
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
CLIENT_DNS_2="1.0.0.1"
CLIENT_DNS_IPV6="2606:4700:4700::1111" # Optionaler IPv6 DNS

# --- Ende der Konfiguration ---

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
        # Freedesktop.org and systemd
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        # linuxbase.org
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [ -f /etc/lsb-release ]; then
        # For some versions of Debian/Ubuntu without lsb_release command
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VER=$DISTRIB_RELEASE
    elif [ -f /etc/debian_version ]; then
        # Older Debian/Ubuntu/etc.
        OS=Debian
        VER=$(cat /etc/debian_version)
    elif [ -f /etc/redhat-release ]; then
        # Older Red Hat, CentOS, etc.
         OS=$(cat /etc/redhat-release | cut -d' ' -f1)
         VER=$(cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//)
    else
        # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
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
        apt-get install -y wireguard qrencode iptables openresolv # openresolv für DNS in wg-quick
    elif [[ "$OS" == "centos" || "$OS" == "fedora" || "$OS" == "rhel" || "$OS" == "almalinux" || "$OS" == "rocky" ]]; then
         if [[ "$OS" == "centos" && ${VER%%.*} -lt 8 ]]; then
             echo "CentOS 7 wird erkannt. EPEL Repository wird benötigt."
             yum install -y epel-release
             yum install -y wireguard-tools qrencode iptables-services # wireguard-dkms könnte auch nötig sein, falls Kernel < 5.6
         else
             dnf install -y wireguard-tools qrencode iptables-services # Kernel sollte WireGuard Modul haben
         fi
         # Stelle sicher, dass iptables verwendet wird, falls firewalld aktiv ist (oder konfiguriere firewalld)
         # systemctl disable --now firewalld # Vorsicht! Deaktiviert firewalld komplett.
         # systemctl enable --now iptables ip6tables # Alternative, falls firewalld deaktiviert wird
         # echo "WARNUNG: firewalld könnte aktiv sein. Regeln werden für iptables erstellt."
         # echo "         Manuelle Konfiguration von firewalld könnte nötig sein: 'firewall-cmd --add-port=${WG_PORT}/udp --permanent && firewall-cmd --reload'"
    else
        echo "FEHLER: Nicht unterstützte Distribution '$OS'. Bitte manuell installieren: wireguard-tools, qrencode, iptables."
        exit 1
    fi
    echo "Pakete installiert."
}

detect_network() {
    echo "Ermittle Netzwerk-Konfiguration..."
    SERVER_PUB_NIC=$(ip route | grep default | awk '{print $5}' | head -n 1)
    if [[ -z "$SERVER_PUB_NIC" ]]; then
        echo "FEHLER: Konnte das Standard-Netzwerkinterface nicht automatisch finden."
        exit 1
    fi
    echo "Öffentliches Interface erkannt: $SERVER_PUB_NIC"

    # Versuche öffentliche IPv4 zu ermitteln (mehrere Methoden)
    SERVER_IPV4=$(ip -4 addr show dev "$SERVER_PUB_NIC" | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 | head -n 1)
    if [[ -z "$SERVER_IPV4" ]]; then
        echo "Konnte lokale IPv4 auf $SERVER_PUB_NIC nicht finden, versuche externen Dienst..."
        SERVER_IPV4=$(curl -4s https://ifconfig.me/ip || curl -4s https://api.ipify.org || wget -qO- -t1 -T2 ipv4.icanhazip.com)
    fi
    if [[ -z "$SERVER_IPV4" ]]; then
        echo "FEHLER: Konnte die öffentliche IPv4 Adresse nicht ermitteln."
        exit 1
    fi
     echo "Öffentliche IPv4 erkannt: $SERVER_IPV4"

    # Versuche öffentliche IPv6 zu ermitteln (optional)
    SERVER_IPV6=$(ip -6 addr show dev "$SERVER_PUB_NIC" scope global | grep 'inet6' | awk '{print $2}' | cut -d'/' -f1 | head -n 1)
     if [[ -z "$SERVER_IPV6" ]]; then
        echo "Konnte keine globale IPv6 auf $SERVER_PUB_NIC finden, versuche externen Dienst..."
        SERVER_IPV6=$(curl -6s https://ifconfig.me/ip || curl -6s https://api6.ipify.org || wget -qO- -t1 -T2 ipv6.icanhazip.com)
     fi

    if [[ -z "$SERVER_IPV6" ]]; then
        echo "WARNUNG: Konnte keine öffentliche IPv6 Adresse ermitteln. IPv6 wird für den Client-Endpoint übersprungen."
        USE_IPV6=false
    else
        echo "Öffentliche IPv6 erkannt: $SERVER_IPV6"
        USE_IPV6=true
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
    IPTABLES_POSTUP="iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE"
    IPTABLES_POSTDOWN="iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE"

    IP6TABLES_POSTUP=""
    IP6TABLES_POSTDOWN=""
    if [ "$USE_IPV6" = true ]; then
        IP6TABLES_POSTUP="ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE"
        IP6TABLES_POSTDOWN="ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE"
    fi

    # Server Konfigurationsdatei erstellen
    cat > "/etc/wireguard/${WG_INTERFACE}.conf" << EOF
[Interface]
Address = ${SERVER_WG_IPV4}/$(echo $WG_IPV4_SUBNET | cut -d'/' -f2)
$( [ "$USE_IPV6" = true ] && echo "Address = ${SERVER_WG_IPV6}/$(echo $WG_IPV6_SUBNET | cut -d'/' -f2)" )
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIVKEY}
# Firewall Regeln / NAT aktivieren, wenn Interface startet
PostUp = ${IPTABLES_POSTUP}; ${IP6TABLES_POSTUP}
# Firewall Regeln entfernen, wenn Interface stoppt
PostDown = ${IPTABLES_POSTDOWN}; ${IP6TABLES_POSTDOWN}
SaveConfig = false # Änderungen an der Konfiguration NICHT automatisch speichern

# --- Erster Client ---
[Peer]
# Name = ${CLIENT_NAME}
PublicKey = ${CLIENT_PUBKEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32$( [ "$USE_IPV6" = true ] && echo ", ${CLIENT_WG_IPV6}/128" )
EOF
    chmod 600 "/etc/wireguard/${WG_INTERFACE}.conf"
    echo "Server Konfiguration erstellt."
}

configure_client() {
    echo "Erstelle Client Konfigurationsdatei (~/${CLIENT_NAME}.conf)..."

    # Wähle den Endpoint basierend auf verfügbarer IP Version
    ENDPOINT=""
    if [[ "$USE_IPV6" = true && -n "$SERVER_IPV6" ]]; then
        # Bevorzuge IPv6, wenn verfügbar und nicht link-local
        if [[ ! $SERVER_IPV6 =~ ^fe80:: ]]; then
             ENDPOINT="[${SERVER_IPV6}]:${WG_PORT}"
        fi
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

    # Client Konfigurationsdatei erstellen
    cat > ~/"${CLIENT_NAME}.conf" << EOF
[Interface]
# Name = ${CLIENT_NAME}
PrivateKey = ${CLIENT_PRIVKEY}
Address = ${CLIENT_WG_IPV4}/$(echo $WG_IPV4_SUBNET | cut -d'/' -f2)
$( [ "$USE_IPV6" = true ] && echo "Address = ${CLIENT_WG_IPV6}/$(echo $WG_IPV6_SUBNET | cut -d'/' -f2)" )
DNS = ${CLIENT_DNS_1}$( [ -n "$CLIENT_DNS_2" ] && echo ", ${CLIENT_DNS_2}" )$( [ -n "$CLIENT_DNS_IPV6" ] && echo ", ${CLIENT_DNS_IPV6}" )

[Peer]
# Name = Server
PublicKey = ${SERVER_PUBKEY}
Endpoint = ${ENDPOINT}
AllowedIPs = 0.0.0.0/0$( [ "$USE_IPV6" = true ] && echo ", ::/0" )
# Optional: PersistentKeepalive alle 25 Sekunden senden, um NAT/Firewall offen zu halten
# PersistentKeepalive = 25
EOF
    chmod 600 ~/"${CLIENT_NAME}.conf"
    echo "Client Konfiguration gespeichert in ~/${CLIENT_NAME}.conf"
}

enable_forwarding() {
    echo "Aktiviere IP Forwarding..."
    # Aktiviere sofort
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    if [ "$USE_IPV6" = true ]; then
        sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null
    fi

    # Mache es permanent
    CONF_FILE="/etc/sysctl.d/99-wireguard-forward.conf"
    if [ ! -f "$CONF_FILE" ]; then
        echo "net.ipv4.ip_forward=1" > "$CONF_FILE"
        if [ "$USE_IPV6" = true ]; then
            echo "net.ipv6.conf.all.forwarding=1" >> "$CONF_FILE"
        fi
        sysctl -p "$CONF_FILE" > /dev/null
        echo "IP Forwarding permanent aktiviert in $CONF_FILE."
    else
        # Sicherstellen, dass die Werte gesetzt sind
        grep -qxF "net.ipv4.ip_forward=1" "$CONF_FILE" || echo "net.ipv4.ip_forward=1" >> "$CONF_FILE"
        if [ "$USE_IPV6" = true ]; then
             grep -qxF "net.ipv6.conf.all.forwarding=1" "$CONF_FILE" || echo "net.ipv6.conf.all.forwarding=1" >> "$CONF_FILE"
        fi
         sysctl -p "$CONF_FILE" > /dev/null
        echo "IP Forwarding war bereits konfiguriert, Werte überprüft in $CONF_FILE."
    fi
}

start_wireguard() {
    echo "Starte und aktiviere WireGuard Service (wg-quick@${WG_INTERFACE})..."
    systemctl enable wg-quick@${WG_INTERFACE}
    systemctl restart wg-quick@${WG_INTERFACE} # Neustart statt nur Start, falls es schon lief

    # Kurze Pause und Statusprüfung
    sleep 2
    if systemctl is-active --quiet wg-quick@${WG_INTERFACE}; then
        echo "WireGuard Service läuft."
        wg show ${WG_INTERFACE}
    else
        echo "FEHLER: WireGuard Service konnte nicht gestartet werden!"
        echo "Überprüfe Logs mit: journalctl -u wg-quick@${WG_INTERFACE}"
        exit 1
    fi
}

generate_qr_code() {
    echo "Generiere QR-Code für Client Konfiguration (~/${CLIENT_NAME}.conf)..."
    echo "Stellen Sie sicher, dass Ihr Terminal UTF-8 unterstützt und die Schriftgröße klein genug ist."
    echo ""
    qrencode -t ansiutf8 < ~/"${CLIENT_NAME}.conf"
    echo ""
    echo "QR-Code oben kann mit der WireGuard Mobile App gescannt werden."
    echo "Die Konfigurationsdatei befindet sich unter: ~/${CLIENT_NAME}.conf"
}

# --- Hauptablauf ---
check_root
detect_distro
install_packages
detect_network
generate_keys
configure_server
configure_client
enable_forwarding
start_wireguard
generate_qr_code

echo ""
echo "--- WireGuard Installation abgeschlossen ---"
echo "Server Konfiguration: /etc/wireguard/${WG_INTERFACE}.conf"
echo "Client Konfiguration: ~/${CLIENT_NAME}.conf (und als QR-Code oben)"
echo "Der WireGuard-Dienst läuft und ist für den Start beim Booten aktiviert."
echo "Stellen Sie sicher, dass der UDP Port ${WG_PORT} in Ihrer externen Firewall (falls vorhanden) geöffnet ist."
echo "Um einen weiteren Client hinzuzufügen: "
echo "1. Generieren Sie ein neues Schlüsselpaar (wg genkey | tee clientX_private.key | wg pubkey > clientX_public.key)."
echo "2. Fügen Sie einen neuen [Peer] Block zur /etc/wireguard/${WG_INTERFACE}.conf hinzu mit dem Public Key des neuen Clients und einer freien IP aus ${WG_IPV4_SUBNET} / ${WG_IPV6_SUBNET}."
echo "3. Starten Sie den WireGuard Dienst neu: systemctl restart wg-quick@${WG_INTERFACE}"
echo "4. Erstellen Sie die Konfigurationsdatei für den neuen Client."

exit 0
