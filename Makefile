# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra

# Target binary
BIN = netshark

# Source file
SRC = src/main.c

# Default target
all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(BIN)

# Clean up build artifacts
clean:
	rm -f $(BIN)

.PHONY: all clean
