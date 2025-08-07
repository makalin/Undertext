CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS = 
LIBS = -lm

TARGETS = sdi_vanc_injector subtitle_encoder
SOURCES = sdi_vanc_injector.c subtitle_encoder.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean install

all: $(TARGETS)

sdi_vanc_injector: sdi_vanc_injector.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

subtitle_encoder: subtitle_encoder.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGETS) $(OBJECTS)

install: $(TARGETS)
	install -m 755 sdi_vanc_injector /usr/local/bin/
	install -m 755 subtitle_encoder /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/sdi_vanc_injector
	rm -f /usr/local/bin/subtitle_encoder 