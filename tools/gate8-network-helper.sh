#!/bin/sh
set -eu

TABLE=paperboat_gate8
UID_VALUE=1000

case "${1:-}" in
  block-udp)
    /usr/sbin/nft delete table inet "$TABLE" 2>/dev/null || true
    /usr/sbin/nft add table inet "$TABLE"
    /usr/sbin/nft 'add chain inet paperboat_gate8 output { type filter hook output priority -10; policy accept; }'
    /usr/sbin/nft add rule inet "$TABLE" output meta skuid "$UID_VALUE" udp dport 53 counter accept
    /usr/sbin/nft add rule inet "$TABLE" output meta skuid "$UID_VALUE" meta l4proto udp counter drop
    ;;
  relay-only-udp)
    /usr/sbin/nft delete table inet "$TABLE" 2>/dev/null || true
    /usr/sbin/nft add table inet "$TABLE"
    /usr/sbin/nft 'add chain inet paperboat_gate8 output { type filter hook output priority -10; policy accept; }'
    /usr/sbin/nft add rule inet "$TABLE" output meta skuid "$UID_VALUE" udp dport 443 counter accept
    /usr/sbin/nft add rule inet "$TABLE" output meta skuid "$UID_VALUE" udp dport 53 counter accept
    /usr/sbin/nft add rule inet "$TABLE" output meta skuid "$UID_VALUE" meta l4proto udp counter drop
    ;;
  allow-udp)
    /usr/sbin/nft delete table inet "$TABLE" 2>/dev/null || true
    ;;
  status)
    /usr/sbin/nft list table inet "$TABLE" 2>/dev/null || printf 'udp_allowed\n'
    ;;
  dropped-packets)
    /usr/sbin/nft -j list table inet "$TABLE" 2>/dev/null |
      /usr/bin/jq -r '[.. | objects | .counter?.packets // empty] | add // 0' || printf '0\n'
    ;;
  *)
    printf 'usage: paperboat-gate8-network block-udp|relay-only-udp|allow-udp|status|dropped-packets\n' >&2
    exit 2
    ;;
esac
