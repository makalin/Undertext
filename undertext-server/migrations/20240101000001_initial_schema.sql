-- Create users table
CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

-- Create sessions table
CREATE TABLE sessions (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    access_token TEXT UNIQUE NOT NULL,
    refresh_token TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create decryption_keys table
CREATE TABLE decryption_keys (
    id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    key_data TEXT NOT NULL,
    iv TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_sessions_access_token ON sessions(access_token);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_decryption_keys_session_id ON decryption_keys(session_id);
CREATE INDEX idx_decryption_keys_expires_at ON decryption_keys(expires_at);
CREATE INDEX idx_decryption_keys_stream_id ON decryption_keys(stream_id); 