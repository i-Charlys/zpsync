# ZPSync (Zero Proxy Sync)

Direct serverless NAT traversal and RUDP handoff for ultra-low-latency video streaming, built on top of [`zcrudp`](../zcrudp).

## Breakthroughs & Architecture (5 Layers)

```text
[Shared Secret S]
       │
       ▼
1. DISCOVERY (Serverless Bootstrapping)
   ├── Kademlia XOR-Sorted Mainline DHT (BEP 5 + BEP 44 put/get across [H-1, H, H+1])
   ├── STUN RFC 5389 + Symmetric Port-Stride Measurement (alt_port - pri_port)
   └── Offline / Manual IP:Port mode
       │
       ▼
2. STAGGERED HAPPY-EYEBALLS & X25519 FORWARD SECRECY
   ├── IPv6 Priority (t=0ms): Port_Cible = 10000 + (Hash(S || Time_Window) mod 55000)
   ├── IPv4 Sentinel (t=80ms): Layer-3 ICMP Echo Request w/ ChaCha20-Poly1305 payload
   └── 1-RTT Ephemeral X25519 (RFC 7748) -> Forward-Secure (PFS) 256-bit Cruise Key
       │
       ▼
3. HYBRID STRIDE + BIRTHDAY PARADOX (Strict Symmetric CGNAT)
   └── 256..500 UDP sockets combining measured-stride progression & coprime dispersion
       │
       ▼
4. VIDEO-AWARE CRUISE & HITLESS MIGRATION (Zero Added Latency)
   ├── `zpsync_cruise`: MTU fragmentation + Zero-RTT XOR FEC + PFS ChaCha20-Poly1305
   └── `zpsync_hop_make_before_break`: Hitless port/ECMP migration (0 dropped frames)
```

## Build & Test

```powershell
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## CLI Example

```powershell
# Probe local IPv6 & NAT type via STUN
./build/zpsync_peer.exe --probe

# Manual / offline loopback test (run in two terminals)
./build/zpsync_peer.exe --secret my-session-key --peer 127.0.0.1 --local-port 40001 --port 40002
./build/zpsync_peer.exe --secret my-session-key --peer 127.0.0.1 --local-port 40002 --port 40001
```
