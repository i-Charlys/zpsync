# ZPSync (Zero Proxy Sync)

Direct serverless NAT traversal and RUDP handoff for ultra-low-latency video streaming, built on top of [`zcrudp`](../zcrudp).

## 4-Layer Architecture

```text
[Shared Secret S]
       │
       ▼
1. DISCOVERY (Serverless Bootstrapping)
   ├── Mainline DHT (Node_ID = SHA1(S || UTC_Hour) across [H-1, H, H+1])
   ├── STUN RFC 5389 + NAT classification (stun.cloudflare.com / stun.l.google.com)
   └── Offline / Manual IP:Port mode
       │
       ▼
2. IPv6 PRIORITY (5G / Modern Fiber)
   └── Deterministic Port_Cible = 10000 + (Hash(S || Time_Window) mod 55000)
       │
       ▼
3. PORTLESS LAYER-3 SENTINEL (IPv4 Residential Boxes)
   └── ICMP Echo Request carrying ChaCha20-Poly1305 encrypted UDP port + ECMP hint
       │
       ▼
4. BIRTHDAY PARADOX SPRAY (Strict Symmetric CGNAT)
   └── 256..500 UDP sockets on Port_i = 10000 + (Hash(S || i) mod 55535)
       │
       ▼
5. CRUISE HANDOFF (Zero Added Latency)
   └── Native connected UDP socket + initialized `rudp_session_s` & `rudp_crypto_ctx_s`
       + dynamic port hopping (`zpsync_hop_port`) on ECMP/LAG congestion
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
