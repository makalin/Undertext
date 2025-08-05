# Undertext 🕵️‍♂️📼  
**Stenographic Subtitle Broadcast over SDI with AES encryption and fine-grained access control**

---

## Overview

**Undertext** is a stealth subtitle broadcasting system that hides encrypted subtitle data inside the VANC (Vertical Ancillary Data) space of an SDI video stream. The subtitles are not visible in the normal video output but can be selectively decrypted and displayed by authorized devices.

This system uses a patched version of VLC’s `--vbi-page` demuxer to extract hidden data and a secure backend service (written in Rust) to distribute per-session decryption keys.

---

## 🔐 Features

- **AES-256 Encrypted Subtitles**: Subtitles are encrypted and split into 4-byte blocks.
- **Steganographic Embedding**: Data is hidden in the least-significant bits of the SDI VANC space.
- **Custom VLC Demux**: Exposes hidden subtitles as an ES track for playback.
- **Key-Based Access**: Backend microservice authenticates devices and grants one-time decryption keys using OAuth 2.0 PKCE.
- **Broadcast-grade**: Integrates seamlessly with SDI workflows and professional broadcast equipment.

---

## 🧱 Architecture

```

\[Subtitle Generator]
│
▼
\[AES Encryption + Chunker]
│
▼
\[SDI Encoder ↔ VANC LSB Injector]
│
▼
\[SDI Signal] ──────▶ \[VLC with Patched VBI Demux] ──────▶ \[Undertext Decryption Module]
▲
│
\[Rust PKCE Auth Server + Key Distribution]

```

---

## ⚙️ Installation

### VLC Patch

1. Clone VLC and apply the patch from `/vlc-patch/vbi-sub-es.diff`
2. Compile VLC with custom demux:
   ```bash
   ./configure --enable-vbi
   make
````

### Backend Microservice

```bash
cd undertext-server
cargo build --release
./target/release/undertext-server
```

Configure your `.env`:

```env
OAUTH_CLIENT_ID=your_client_id
OAUTH_REDIRECT=http://localhost:8080/callback
ENCRYPTION_MASTER_KEY=your_256bit_key_here
```

---

## 🔑 Authorization Flow

1. Viewer opens authorized VLC client.
2. OAuth PKCE flow authenticates the device.
3. Server issues a one-time key via HTTPS.
4. Subtitle stream is decrypted on-the-fly and rendered.

---

## 🧪 Use Cases

* Secure subtitle broadcast for live political events or court proceedings
* Multilingual streams with selective per-language access
* Covert training data delivery in surveillance or defense scenarios

---

## 🚧 Roadmap

* [ ] HLS/RTMP support
* [ ] WebVTT export and browser support
* [ ] Dynamic subtitle injection via OBS plugin
* [ ] TPM/Hardware-key integration

---

## 📜 License

MIT License © 2025 \[Mehmet T. AKALIN]

---

## 🛰️ Contact

Want to collaborate or contribute?
Open an issue or reach out at `makalin@gmail.com`.
