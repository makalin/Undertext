#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/videodev2.h>
#include <errno.h>

#define VANC_MAGIC 0x554E4452  // "UNDR"
#define MAX_VANC_SIZE 4096
#define SDI_LINE_LENGTH 1920
#define VANC_START_LINE 10

typedef struct {
    uint32_t magic;
    uint16_t data_length;
    uint16_t sequence;
    uint8_t data[MAX_VANC_SIZE];
    uint32_t checksum;
} vanc_packet_t;

typedef struct {
    int fd;
    int width;
    int height;
    int frame_rate;
    uint8_t *frame_buffer;
    size_t frame_size;
} sdi_context_t;

// Calculate CRC32 checksum
uint32_t calculate_crc32(const uint8_t *data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    const uint32_t polynomial = 0xEDB88320;
    
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ polynomial;
            } else {
                crc >>= 1;
            }
        }
    }
    
    return ~crc;
}

// Initialize SDI context
int sdi_init(sdi_context_t *ctx, const char *device_path) {
    ctx->fd = open(device_path, O_RDWR);
    if (ctx->fd < 0) {
        perror("Failed to open SDI device");
        return -1;
    }
    
    // Get device capabilities
    struct v4l2_capability cap;
    if (ioctl(ctx->fd, VIDIOC_QUERYCAP, &cap) < 0) {
        perror("Failed to query device capabilities");
        close(ctx->fd);
        return -1;
    }
    
    // Set video format
    struct v4l2_format fmt;
    memset(&fmt, 0, sizeof(fmt));
    fmt.type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
    
    if (ioctl(ctx->fd, VIDIOC_G_FMT, &fmt) < 0) {
        perror("Failed to get video format");
        close(ctx->fd);
        return -1;
    }
    
    ctx->width = fmt.fmt.pix.width;
    ctx->height = fmt.fmt.pix.height;
    ctx->frame_size = ctx->width * ctx->height * 2; // YUV422
    
    // Allocate frame buffer
    ctx->frame_buffer = malloc(ctx->frame_size);
    if (!ctx->frame_buffer) {
        perror("Failed to allocate frame buffer");
        close(ctx->fd);
        return -1;
    }
    
    return 0;
}

// Inject VANC data into SDI frame
int inject_vanc_data(sdi_context_t *ctx, const uint8_t *subtitle_data, size_t data_length) {
    if (data_length > MAX_VANC_SIZE) {
        fprintf(stderr, "Subtitle data too large for VANC space\n");
        return -1;
    }
    
    // Create VANC packet
    vanc_packet_t packet;
    packet.magic = VANC_MAGIC;
    packet.data_length = htons(data_length);
    packet.sequence = htons(0); // Will be incremented per frame
    
    memcpy(packet.data, subtitle_data, data_length);
    
    // Calculate checksum
    packet.checksum = calculate_crc32((uint8_t*)&packet, 
                                     sizeof(packet) - sizeof(packet.checksum));
    
    // Inject into VANC space (least significant bits)
    size_t packet_size = sizeof(packet);
    size_t vanc_offset = VANC_START_LINE * ctx->width * 2;
    
    for (size_t i = 0; i < packet_size; i++) {
        uint8_t byte = ((uint8_t*)&packet)[i];
        
        // Inject into LSB of Y component
        for (int bit = 0; bit < 8; bit++) {
            size_t pixel_offset = vanc_offset + (i * 8 + bit) * 2;
            if (pixel_offset < ctx->frame_size) {
                // Clear LSB and set new bit
                ctx->frame_buffer[pixel_offset] &= 0xFE;
                ctx->frame_buffer[pixel_offset] |= ((byte >> bit) & 0x01);
            }
        }
    }
    
    return 0;
}

// Write frame to SDI device
int write_sdi_frame(sdi_context_t *ctx) {
    ssize_t written = write(ctx->fd, ctx->frame_buffer, ctx->frame_size);
    if (written != ctx->frame_size) {
        perror("Failed to write complete frame");
        return -1;
    }
    
    return 0;
}

// Main encoding function
int encode_subtitle_to_sdi(const char *device_path, const char *subtitle_file) {
    sdi_context_t ctx;
    
    // Initialize SDI context
    if (sdi_init(&ctx, device_path) < 0) {
        return -1;
    }
    
    // Read subtitle data
    FILE *subtitle_fp = fopen(subtitle_file, "rb");
    if (!subtitle_fp) {
        perror("Failed to open subtitle file");
        free(ctx.frame_buffer);
        close(ctx.fd);
        return -1;
    }
    
    // Get file size
    fseek(subtitle_fp, 0, SEEK_END);
    size_t subtitle_size = ftell(subtitle_fp);
    fseek(subtitle_fp, 0, SEEK_SET);
    
    // Read subtitle data
    uint8_t *subtitle_data = malloc(subtitle_size);
    if (!subtitle_data) {
        perror("Failed to allocate subtitle buffer");
        fclose(subtitle_fp);
        free(ctx.frame_buffer);
        close(ctx.fd);
        return -1;
    }
    
    fread(subtitle_data, 1, subtitle_size, subtitle_fp);
    fclose(subtitle_fp);
    
    // Inject VANC data
    if (inject_vanc_data(&ctx, subtitle_data, subtitle_size) < 0) {
        free(subtitle_data);
        free(ctx.frame_buffer);
        close(ctx.fd);
        return -1;
    }
    
    // Write frame
    if (write_sdi_frame(&ctx) < 0) {
        free(subtitle_data);
        free(ctx.frame_buffer);
        close(ctx.fd);
        return -1;
    }
    
    printf("Successfully encoded subtitle data into SDI stream\n");
    
    // Cleanup
    free(subtitle_data);
    free(ctx.frame_buffer);
    close(ctx.fd);
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <sdi_device> <subtitle_file>\n", argv[0]);
        return 1;
    }
    
    return encode_subtitle_to_sdi(argv[1], argv[2]);
} 