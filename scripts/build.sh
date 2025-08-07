#!/bin/bash

set -e

echo "🔧 Building Undertext System..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    print_status "Checking dependencies..."
    
    # Check for Rust
    if ! command -v cargo &> /dev/null; then
        print_error "Rust/Cargo not found. Please install Rust: https://rustup.rs/"
        exit 1
    fi
    
    # Check for GCC
    if ! command -v gcc &> /dev/null; then
        print_error "GCC not found. Please install GCC."
        exit 1
    fi
    
    # Check for OpenSSL development headers
    if ! pkg-config --exists openssl; then
        print_warning "OpenSSL development headers not found. Installing..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y libssl-dev
        elif command -v yum &> /dev/null; then
            sudo yum install -y openssl-devel
        elif command -v brew &> /dev/null; then
            brew install openssl
        else
            print_error "Please install OpenSSL development headers manually."
            exit 1
        fi
    fi
    
    print_status "Dependencies check completed."
}

# Build Rust backend
build_backend() {
    print_status "Building Rust backend server..."
    cd undertext-server
    
    # Install SQLx CLI if not present
    if ! command -v sqlx &> /dev/null; then
        print_status "Installing SQLx CLI..."
        cargo install sqlx-cli --no-default-features --features sqlite
    fi
    
    # Build the project
    cargo build --release
    
    if [ $? -eq 0 ]; then
        print_status "Backend build completed successfully."
    else
        print_error "Backend build failed."
        exit 1
    fi
    
    cd ..
}

# Build C encoder tools
build_encoder() {
    print_status "Building C encoder tools..."
    cd encoder
    
    # Check for required headers
    if [ ! -f /usr/include/linux/videodev2.h ]; then
        print_warning "Video4Linux2 headers not found. Installing..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y libv4l-dev
        elif command -v yum &> /dev/null; then
            sudo yum install -y v4l-utils-devel
        else
            print_warning "Please install Video4Linux2 development headers manually."
        fi
    fi
    
    make clean
    make
    
    if [ $? -eq 0 ]; then
        print_status "Encoder tools build completed successfully."
    else
        print_error "Encoder tools build failed."
        exit 1
    fi
    
    cd ..
}

# Build VLC plugin
build_vlc_plugin() {
    print_status "Building VLC plugin..."
    cd client
    
    # Check if VLC development headers are available
    if [ ! -d /usr/include/vlc ]; then
        print_warning "VLC development headers not found."
        print_warning "Please install VLC development package:"
        print_warning "  Ubuntu/Debian: sudo apt-get install libvlc-dev"
        print_warning "  CentOS/RHEL: sudo yum install vlc-devel"
        print_warning "  macOS: brew install vlc"
        print_warning "Skipping VLC plugin build..."
        return 0
    fi
    
    # Compile VLC plugin
    gcc -shared -fPIC -o libundertext_plugin.so \
        -I/usr/include/vlc \
        -I/usr/include/vlc/plugins \
        vlc-undertext-plugin.c \
        -lvlc -lssl -lcrypto -ljson-c
    
    if [ $? -eq 0 ]; then
        print_status "VLC plugin build completed successfully."
    else
        print_warning "VLC plugin build failed. Continuing without plugin..."
    fi
    
    cd ..
}

# Create installation directories
create_dirs() {
    print_status "Creating installation directories..."
    sudo mkdir -p /usr/local/bin/undertext
    sudo mkdir -p /usr/local/lib/vlc/plugins
    sudo mkdir -p /etc/undertext
    sudo mkdir -p /var/log/undertext
}

# Install components
install_components() {
    print_status "Installing components..."
    
    # Install backend
    sudo cp undertext-server/target/release/undertext-server /usr/local/bin/undertext/
    sudo cp undertext-server/env.example /etc/undertext/
    
    # Install encoder tools
    sudo cp encoder/sdi_vanc_injector /usr/local/bin/undertext/
    sudo cp encoder/subtitle_encoder /usr/local/bin/undertext/
    
    # Install VLC plugin if built
    if [ -f client/libundertext_plugin.so ]; then
        sudo cp client/libundertext_plugin.so /usr/local/lib/vlc/plugins/
    fi
    
    # Set permissions
    sudo chmod +x /usr/local/bin/undertext/*
    sudo chown -R root:root /usr/local/bin/undertext
    sudo chown -R root:root /etc/undertext
    
    print_status "Installation completed."
}

# Create systemd service
create_service() {
    print_status "Creating systemd service..."
    
    cat > /tmp/undertext-server.service << EOF
[Unit]
Description=Undertext Subtitle Server
After=network.target

[Service]
Type=simple
User=undertext
Group=undertext
WorkingDirectory=/usr/local/bin/undertext
ExecStart=/usr/local/bin/undertext/undertext-server
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF
    
    sudo cp /tmp/undertext-server.service /etc/systemd/system/
    sudo systemctl daemon-reload
    
    # Create user if it doesn't exist
    if ! id "undertext" &>/dev/null; then
        sudo useradd -r -s /bin/false undertext
    fi
    
    print_status "Systemd service created. Enable with: sudo systemctl enable undertext-server"
}

# Main build process
main() {
    print_status "Starting Undertext build process..."
    
    check_dependencies
    build_backend
    build_encoder
    build_vlc_plugin
    
    if [ "$1" = "--install" ]; then
        create_dirs
        install_components
        create_service
        print_status "Build and installation completed successfully!"
        print_status "Next steps:"
        print_status "1. Copy /etc/undertext/env.example to /etc/undertext/.env"
        print_status "2. Edit /etc/undertext/.env with your configuration"
        print_status "3. Start the service: sudo systemctl start undertext-server"
    else
        print_status "Build completed successfully!"
        print_status "Run with --install to install system-wide"
    fi
}

# Run main function
main "$@" 