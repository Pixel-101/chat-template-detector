\# Server setup (OptiPlex)



\## Hardware and OS

\- Dell OptiPlex 7050

\- Intel Core i5-7500, 4 cores / 4 threads, 3.4-3.8 GHz

\- 16 GB RAM, 4 GB swap

\- 98 GB disk (70 GB free at setup)

\- No dedicated GPU: all models run on CPU

\- Ubuntu 24.04.5 LTS, kernel 6.8

\- Docker is installed from a previous setup (not used for the thesis)



\## Access

\- Home network: ssh optiplex  (192.168.178.89)

\- Anywhere via Tailscale: ssh optiplex-ts  (100.70.238.109)

\- Login by SSH key only from the laptop (ed25519)

\- No router ports are opened



\## Firewall (ufw)

\- SSH allowed on tailscale0

\- SSH allowed from 192.168.178.0/24 (home network only)



\## Rules

\- Long runs go inside tmux, so they survive the laptop disconnecting or crashing

\- Poisoned templates and model files stay on this machine and the laptop, never on GitHub

\- Ollama is never exposed to the internet



\## Still to do

\- Reserve 192.168.178.89 in the FRITZ!Box (v3)

\- Disable password login for SSH (v6)

\- Stop sleep and suspend (v7)

\- BIOS: power on after power loss (v8)

\- Disable Tailscale key expiry

\- Hotspot test before December (v14)

