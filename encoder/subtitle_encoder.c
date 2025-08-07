#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX_SUBTITLE_LENGTH 1024
#define MAX_LINE_LENGTH 256
#define ENCRYPTION_KEY_SIZE 32
#define IV_SIZE 12

typedef struct {
    uint32_t timestamp;
    uint16_t duration;
    uint16_t text_length;
    char text[MAX_SUBTITLE_LENGTH];
} subtitle_entry_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t entry_count;
    uint32_t total_size;
} subtitle_header_t;

// Generate random encryption key
int generate_encryption_key(unsigned char *key, size_t key_len) {
    if (RAND_bytes(key, key_len) != 1) {
        fprintf(stderr, "Failed to generate random key\n");
        return -1;
    }
    return 0;
}

// Encrypt subtitle data using AES-256-GCM
int encrypt_subtitle_data(const unsigned char *plaintext, size_t plaintext_len,
                         const unsigned char *key, const unsigned char *iv,
                         unsigned char *ciphertext, size_t *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create cipher context\n");
        return -1;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        fprintf(stderr, "Failed to initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "Failed to encrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    *ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "Failed to finalize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    *ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// Parse SRT subtitle file
int parse_srt_file(const char *filename, subtitle_entry_t **entries, int *entry_count) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open SRT file");
        return -1;
    }
    
    char line[MAX_LINE_LENGTH];
    int count = 0;
    int capacity = 100;
    
    *entries = malloc(capacity * sizeof(subtitle_entry_t));
    if (!*entries) {
        fclose(fp);
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        // Skip empty lines
        if (strlen(line) <= 1) continue;
        
        // Parse subtitle number
        int subtitle_num = atoi(line);
        if (subtitle_num <= 0) continue;
        
        // Read timestamp line
        if (!fgets(line, sizeof(line), fp)) break;
        
        // Parse timestamp (format: 00:00:00,000 --> 00:00:00,000)
        int h1, m1, s1, ms1, h2, m2, s2, ms2;
        if (sscanf(line, "%d:%d:%d,%d --> %d:%d:%d,%d",
                   &h1, &m1, &s1, &ms1, &h2, &m2, &s2, &ms2) != 8) {
            continue;
        }
        
        uint32_t start_time = h1 * 3600000 + m1 * 60000 + s1 * 1000 + ms1;
        uint32_t end_time = h2 * 3600000 + m2 * 60000 + s2 * 1000 + ms2;
        uint16_t duration = end_time - start_time;
        
        // Read subtitle text
        char text[MAX_SUBTITLE_LENGTH] = "";
        while (fgets(line, sizeof(line), fp) && strlen(line) > 1) {
            strncat(text, line, sizeof(text) - strlen(text) - 1);
        }
        
        // Remove trailing newlines
        char *newline = strchr(text, '\n');
        if (newline) *newline = '\0';
        
        // Add entry
        if (count >= capacity) {
            capacity *= 2;
            subtitle_entry_t *new_entries = realloc(*entries, capacity * sizeof(subtitle_entry_t));
            if (!new_entries) {
                free(*entries);
                fclose(fp);
                return -1;
            }
            *entries = new_entries;
        }
        
        (*entries)[count].timestamp = start_time;
        (*entries)[count].duration = duration;
        (*entries)[count].text_length = strlen(text);
        strncpy((*entries)[count].text, text, MAX_SUBTITLE_LENGTH - 1);
        (*entries)[count].text[MAX_SUBTITLE_LENGTH - 1] = '\0';
        
        count++;
    }
    
    fclose(fp);
    *entry_count = count;
    return 0;
}

// Write encrypted subtitle data
int write_encrypted_subtitles(const char *output_file, const subtitle_entry_t *entries,
                             int entry_count, const unsigned char *key, const unsigned char *iv) {
    FILE *fp = fopen(output_file, "wb");
    if (!fp) {
        perror("Failed to create output file");
        return -1;
    }
    
    // Calculate total size
    size_t total_size = sizeof(subtitle_header_t);
    for (int i = 0; i < entry_count; i++) {
        total_size += sizeof(subtitle_entry_t);
    }
    
    // Write header
    subtitle_header_t header = {
        .magic = 0x554E4452,  // "UNDR"
        .version = 1,
        .entry_count = entry_count,
        .total_size = total_size
    };
    
    fwrite(&header, sizeof(header), 1, fp);
    
    // Write entries
    for (int i = 0; i < entry_count; i++) {
        fwrite(&entries[i], sizeof(subtitle_entry_t), 1, fp);
    }
    
    // Write encryption key and IV
    fwrite(key, ENCRYPTION_KEY_SIZE, 1, fp);
    fwrite(iv, IV_SIZE, 1, fp);
    
    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input.srt> <output.bin>\n", argv[0]);
        return 1;
    }
    
    // Parse SRT file
    subtitle_entry_t *entries;
    int entry_count;
    
    if (parse_srt_file(argv[1], &entries, &entry_count) < 0) {
        return 1;
    }
    
    printf("Parsed %d subtitle entries\n", entry_count);
    
    // Generate encryption key and IV
    unsigned char key[ENCRYPTION_KEY_SIZE];
    unsigned char iv[IV_SIZE];
    
    if (generate_encryption_key(key, ENCRYPTION_KEY_SIZE) < 0) {
        free(entries);
        return 1;
    }
    
    if (generate_encryption_key(iv, IV_SIZE) < 0) {
        free(entries);
        return 1;
    }
    
    // Write encrypted subtitle data
    if (write_encrypted_subtitles(argv[2], entries, entry_count, key, iv) < 0) {
        free(entries);
        return 1;
    }
    
    printf("Successfully encoded subtitles to %s\n", argv[2]);
    printf("Encryption key: ");
    for (int i = 0; i < ENCRYPTION_KEY_SIZE; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    
    free(entries);
    return 0;
} 