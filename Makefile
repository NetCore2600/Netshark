# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude

# Directories
SRC_DIR = src
BUILD_DIR = build
BIN = netshark

# Find all .c files recursively
SRC = $(addprefix $(SRC_DIR)/, main.c init.c utils.c) \
	  $(addprefix $(SRC_DIR)/handlers/, ethernet_handler.c arp_handler.c ftp_handler.c http_handler.c tcp_handler.c udp_handler.c) \
	  $(addprefix $(SRC_DIR)/parsers/, ftp_parser.c http_parser.c tcp_parser.c udp_parser.c)
OBJ = $(SRC:%.c=$(BUILD_DIR)/%.o)



# Create necessary folders for object files
$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Default target
all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

# Clean up build artifacts
clean:
	rm -rf $(BUILD_DIR) $(BIN)

.PHONY: all clean
