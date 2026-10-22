#!/bin/sh
# sshd-always-on.sh - SSH on every boot, with or without debug mode.
#
#   sh sshd-always-on.sh install   SSH always on (survives reboots and debug mode going off)
#   sh sshd-always-on.sh remove    back to stock: SSH only while debug mode is on
#   sh sshd-always-on.sh status    show what is in place and whether port 22 is open
#
# Why stock SSH dies without debug mode - three separate gates, all handled here:
#  1. Start:    /lib/systemd/system/sshd.socket is WantedBy=debug.target only. The boot target
#               is early.target (multi-user.target comes later via late.target, if at all), so
#               the socket is now also wanted by early.target, sockets.target and multi-user.target.
#  2. Stop:     sshd.socket has PartOf=debug.target, so leaving debug mode stops it. The /etc
#               override drops PartOf.
#  3. Firewall: port 22 is only allowed by a rule firewalldZ puts in chain "inputdebug" while
#               debug mode is on; without it, the input chain ends in "logblocked" and drops SSH.
#               sshd-always-on-fw.service keeps "tcp dport 22 accept" at the top of the ip and
#               ip6 input chains (re-checked every 15 s, in case firewalldZ reloads its rules).
#
# Nothing in /lib or /usr is changed. All files are new; "remove" deletes them.
set -u

UNIT=sshd.socket
STOCK=/lib/systemd/system/$UNIT
SYSD=/etc/systemd/system
OVR=$SYSD/$UNIT
FWSVC=sshd-always-on-fw.service
FWUNIT=$SYSD/$FWSVC
FWSCRIPT=/etc/sshd-always-on/keep-port22-open.sh
TARGETS="early.target sockets.target multi-user.target"
MARK="# sshd-always-on.sh"
NFT=/usr/sbin/nft

say() { echo "[sshd-always-on] $*"; }
die() { say "ERROR: $*"; exit 1; }

# / is mounted read-only on the MGU: remount rw only for the change, then back to ro
RW_DONE=0
rootfs_rw() {
    if touch /etc/.sshd-rw-test 2>/dev/null; then rm -f /etc/.sshd-rw-test; return 0; fi
    mount -o remount,rw / || die "cannot remount / read-write"
    RW_DONE=1
}
rootfs_ro() {
    if [ "$RW_DONE" = 1 ]; then sync; mount -o remount,ro / 2>/dev/null || say "note: / stays rw until reboot (busy)"; fi
    RW_DONE=0
}

ours() { [ ! -e "$1" ] || grep -q "$MARK" "$1"; }   # absent, or made by this script

# write stdin to $1 as root:root 0644 (or $2), atomically
put() {
    cat > "$1.new" || die "cannot write $1"
    chown root:root "$1.new"; chmod "${2:-644}" "$1.new"
    mv -f "$1.new" "$1"
}

port22_rules() {   # list our live accept rules: "<family> <handle>"
    for fam in ip ip6; do
        $NFT -a list chain $fam filter input 2>/dev/null \
            | grep -E '^[[:space:]]*tcp dport 22 accept # handle [0-9]+$' \
            | sed -E "s/.*# handle ([0-9]+)$/$fam \1/"
    done
}

status() {
    if [ -f "$OVR" ] && grep -q "$MARK" "$OVR"; then say "sshd.socket override: installed"
    elif [ -f "$OVR" ]; then say "sshd.socket override: $OVR exists but NOT made by this script"
    else say "sshd.socket override: none (stock)"; fi
    for t in $TARGETS; do
        [ -L "$SYSD/$t.wants/$UNIT" ] && say "  wanted by $t: yes" || say "  wanted by $t: no"
    done
    say "  PartOf: '$(systemctl show -p PartOf --value $UNIT 2>/dev/null)' (stock: debug.target)"
    say "  sshd.socket: $(systemctl is-active $UNIT 2>/dev/null), enabled-at-boot: $( [ -L "$SYSD/early.target.wants/$UNIT" ] && echo yes || echo no)"
    say "firewall keeper: $(systemctl is-active $FWSVC 2>/dev/null) ($( [ -L "$SYSD/early.target.wants/$FWSVC" ] && echo enabled || echo not enabled))"
    n=$(port22_rules | wc -l)
    say "  port 22 accept rules live: $n (want 2: ip + ip6)"
    say "debug.target: $(systemctl is-active debug.target 2>/dev/null)"
}

install() {
    [ -f "$STOCK" ] || die "$STOCK not found - is this an MGU?"
    [ -x "$NFT" ] || die "$NFT not found"
    for f in "$OVR" "$FWUNIT" "$FWSCRIPT"; do ours "$f" || die "$f exists and was not made by this script - not touching it"; done
    grep -q '^ListenStream=22' "$STOCK" || die "unexpected stock $STOCK, aborting"

    rootfs_rw
    trap rootfs_ro EXIT

    # 1+2: sshd.socket without PartOf=debug.target, wanted by the boot targets too
    {
        echo "$MARK - remove with: sh sshd-always-on.sh remove (stock unit: $STOCK)"
        sed -e '/^PartOf=debug\.target$/d' \
            -e "s/^WantedBy=debug\.target\$/WantedBy=$TARGETS debug.target/" "$STOCK"
    } | put "$OVR"

    # 3: firewall keeper
    mkdir -p "$(dirname "$FWSCRIPT")"; chmod 755 "$(dirname "$FWSCRIPT")"
    put "$FWSCRIPT" 755 <<EOF
#!/bin/sh
$MARK
# Keeps "tcp dport 22 accept" at the top of the ip/ip6 input chains, so SSH is not dropped
# when firewalldZ removes its debug-mode rules. Re-checks every 15 s.
while :; do
    for fam in ip ip6; do
        if $NFT list chain \$fam filter input >/dev/null 2>&1 &&
           ! $NFT list chain \$fam filter input | grep -qE '^[[:space:]]*tcp dport 22 accept\$'; then
            $NFT insert rule \$fam filter input tcp dport 22 accept && echo "port 22 opened (\$fam)"
        fi
    done
    sleep 15
done
EOF
    put "$FWUNIT" <<EOF
$MARK
[Unit]
Description=Keep SSH (tcp/22) open in the firewall, also outside debug mode
After=firewalldz.service

[Service]
Type=simple
ExecStart=/bin/sh $FWSCRIPT
Restart=always
RestartSec=5

[Install]
WantedBy=early.target multi-user.target
EOF

    for t in $TARGETS; do mkdir -p "$SYSD/$t.wants"; ln -sfn "$OVR" "$SYSD/$t.wants/$UNIT"; done
    for t in early.target multi-user.target; do ln -sfn "$FWUNIT" "$SYSD/$t.wants/$FWSVC"; done
    sync
    rootfs_ro

    systemctl daemon-reload
    systemctl start $UNIT
    systemctl restart $FWSVC
    sleep 2
    say "installed"
    status
}

remove() {
    for f in "$OVR" "$FWUNIT" "$FWSCRIPT"; do ours "$f" || die "$f was not made by this script - not touching it"; done
    systemctl stop $FWSVC 2>/dev/null
    port22_rules | while read -r fam h; do $NFT delete rule $fam filter input handle "$h"; done

    rootfs_rw
    trap rootfs_ro EXIT
    for t in $TARGETS; do rm -f "$SYSD/$t.wants/$UNIT"; done
    for t in early.target multi-user.target; do rm -f "$SYSD/$t.wants/$FWSVC"; done
    rm -f "$OVR" "$FWUNIT" "$FWSCRIPT"
    rmdir "$(dirname "$FWSCRIPT")" 2>/dev/null
    sync
    rootfs_ro
    systemctl daemon-reload
    say "removed: back to stock (SSH only in debug mode; open sessions stay up)"
    status
}

[ "$(id -u)" = 0 ] || die "run as root"
case "${1:-status}" in
    install) install ;;
    remove)  remove ;;
    status)  status ;;
    *) sed -n 2,6p "$0"; exit 2 ;;
esac
