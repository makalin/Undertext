# Undertext Installation Guide

## Overview

Undertext is a stenographic subtitle broadcasting system that hides encrypted subtitle data inside the VANC (Vertical Ancillary Data) space of an SDI video stream. This guide will walk you through the complete installation and setup process.

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+, CentOS 8+, or similar)
- **Architecture**: x86_64 or ARM64
- **Memory**: Minimum 2GB RAM, 4GB recommended
- **Storage**: 1GB free space
- **Network**: Internet connection for OAuth authentication

### Required Software

1. **Rust** (1.70+)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

2. **GCC** and development tools
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install build-essential pkg-config libssl-dev libv4l-dev
   
   # CentOS/RHEL
   sudo yum groupinstall "Development Tools"
   sudo yum install openssl-devel v4l-utils-devel
   ```

3. **VLC** (optional, for client-side playback)
   ```bash
   # Ubuntu/Debian
   sudo apt-get install vlc libvlc-dev
   
   # CentOS/RHEL
   sudo yum install vlc vlc-devel
   ```

## Quick Installation

### Automated Build and Install

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/undertext.git
   cd undertext
   ```

2. **Run the build script**
   ```bash
   chmod +x scripts/build.sh
   ./scripts/build.sh --install
   ```

3. **Configure the server**
   ```bash
   sudo cp /etc/undertext/env.example /etc/undertext/.env
   sudo nano /etc/undertext/.env
   ```

4. **Start the service**
   ```bash
   sudo systemctl enable undertext-server
   sudo systemctl start undertext-server
   ```

## Manual Installation

### Step 1: Build the Backend Server

```bash
cd undertext-server

# Install SQLx CLI
cargo install sqlx-cli --no-default-features --features sqlite

# Build the project
cargo build --release

# Copy binary to system location
sudo cp target/release/undertext-server /usr/local/bin/
```

### Step 2: Build the Encoder Tools

```bash
cd encoder

# Build the tools
make

# Install
sudo cp sdi_vanc_injector /usr/local/bin/
sudo cp subtitle_encoder /usr/local/bin/
```

### Step 3: Configure OAuth

1. **Create Google OAuth 2.0 credentials**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing one
   - Enable the Google+ API
   - Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"
   - Set application type to "Web application"
   - Add authorized redirect URI: `http://localhost:8080/callback`
   - Note down the Client ID and Client Secret

2. **Generate encryption keys**
   ```bash
   # Generate master encryption key (32 bytes, base64 encoded)
   openssl rand -base64 32
   
   # Generate JWT secret
   openssl rand -base64 32
   ```

3. **Create configuration file**
   ```bash
   sudo mkdir -p /etc/undertext
   sudo nano /etc/undertext/.env
   ```

   Add the following content:
   ```env
   PORT=8080
   RUST_LOG=info
   DATABASE_URL=sqlite:/var/lib/undertext/undertext.db
   OAUTH_CLIENT_ID=your_google_oauth_client_id
   OAUTH_CLIENT_SECRET=your_google_oauth_client_secret
   OAUTH_REDIRECT_URI=http://localhost:8080/callback
   ENCRYPTION_MASTER_KEY=your_base64_encoded_32_byte_key
   JWT_SECRET=your_jwt_secret_key
   SESSION_TIMEOUT_MINUTES=60
   ```

### Step 4: Set Up Database

```bash
# Create database directory
sudo mkdir -p /var/lib/undertext
sudo chown undertext:undertext /var/lib/undertext

# Initialize database
cd undertext-server
sqlx database create
sqlx migrate run
```

### Step 5: Create System Service

```bash
sudo nano /etc/systemd/system/undertext-server.service
```

Add the following content:
```ini
[Unit]
Description=Undertext Subtitle Server
After=network.target

[Service]
Type=simple
User=undertext
Group=undertext
WorkingDirectory=/usr/local/bin
ExecStart=/usr/local/bin/undertext-server
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

```bash
# Create user
sudo useradd -r -s /bin/false undertext

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable undertext-server
sudo systemctl start undertext-server
```

## VLC Integration

### Option 1: Use Patched VLC

1. **Download and patch VLC**
   ```bash
   git clone https://code.videolan.org/videolan/vlc.git
   cd vlc
   patch -p1 < ../vlc-patch/vbi-sub-es.diff
   ```

2. **Build VLC with patches**
   ```bash
   ./bootstrap
   ./configure --enable-vbi
   make -j$(nproc)
   sudo make install
   ```

### Option 2: Use VLC Plugin

1. **Build the plugin**
   ```bash
   cd client
   gcc -shared -fPIC -o libundertext_plugin.so \
       -I/usr/include/vlc \
       vlc-undertext-plugin.c \
       -lvlc -lssl -lcrypto -ljson-c
   ```

2. **Install the plugin**
   ```bash
   sudo cp libundertext_plugin.so /usr/lib/vlc/plugins/
   ```

## Usage Examples

### Encoding Subtitles

1. **Create SRT subtitle file**
   ```srt
   1
   00:00:01,000 --> 00:00:04,000
   Hello, this is a test subtitle
   
   2
   00:00:05,000 --> 00:00:08,000
   This subtitle is hidden in the VANC data
   ```

2. **Encode subtitles**
   ```bash
   subtitle_encoder subtitles.srt encoded_subtitles.bin
   ```

3. **Inject into SDI stream**
   ```bash
   sdi_vanc_injector /dev/video0 encoded_subtitles.bin
   ```

### Client Playback

1. **Start VLC with Undertext support**
   ```bash
   vlc --vbi-page=1 sdi:///dev/video0
   ```

2. **Or use the plugin**
   ```bash
   vlc --sub-filter=undertext \
       --undertext-server=http://localhost:8080 \
       --undertext-token=your_session_token \
       --undertext-stream=stream_id \
       sdi:///dev/video0
   ```

## API Usage

### Authentication Flow

1. **Get authorization URL**
   ```bash
   curl http://localhost:8080/api/v1/auth/url
   ```

2. **Complete OAuth flow**
   ```bash
   curl -X POST http://localhost:8080/api/v1/auth/callback \
     -H "Content-Type: application/json" \
     -d '{
       "code": "authorization_code",
       "state": "state_value",
       "code_verifier": "code_verifier"
     }'
   ```

3. **Request decryption key**
   ```bash
   curl -X POST http://localhost:8080/api/v1/keys/request \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer your_session_token" \
     -d '{
       "stream_id": "your_stream_id",
       "session_token": "Bearer your_session_token"
     }'
   ```

## Troubleshooting

### Common Issues

1. **Server won't start**
   - Check logs: `sudo journalctl -u undertext-server -f`
   - Verify configuration: `sudo cat /etc/undertext/.env`
   - Check permissions: `sudo chown -R undertext:undertext /var/lib/undertext`

2. **OAuth authentication fails**
   - Verify OAuth credentials in `.env`
   - Check redirect URI matches Google Console settings
   - Ensure server is accessible at configured URL

3. **VLC plugin not loading**
   - Check plugin location: `/usr/lib/vlc/plugins/`
   - Verify dependencies: `ldd libundertext_plugin.so`
   - Check VLC logs: `vlc --verbose=2`

4. **SDI device not found**
   - Check device permissions: `sudo chmod 666 /dev/video0`
   - Verify device exists: `ls -la /dev/video*`
   - Install Video4Linux2 tools: `sudo apt-get install v4l-utils`

### Log Files

- **Server logs**: `sudo journalctl -u undertext-server`
- **VLC logs**: Check VLC interface or use `--verbose=2`
- **System logs**: `sudo dmesg | grep -i video`

## Security Considerations

1. **Encryption keys**: Store master keys securely, never in version control
2. **OAuth secrets**: Keep client secrets confidential
3. **Network security**: Use HTTPS in production
4. **Access control**: Implement proper user authentication
5. **Audit logging**: Monitor access to decryption keys

## Performance Tuning

1. **Database optimization**: Use connection pooling for high concurrency
2. **Memory usage**: Monitor memory consumption during encoding
3. **Network latency**: Place server close to clients for low latency
4. **SDI bandwidth**: Ensure sufficient bandwidth for VANC data

## Support

For issues and questions:
- **GitHub Issues**: [Create an issue](https://github.com/your-username/undertext/issues)
- **Email**: makalin@gmail.com
- **Documentation**: See `/docs` directory for detailed guides 