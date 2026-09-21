CC := cc
CFLAGS := -Wall -Wextra -O2 -std=gnu11
LDFLAGS := -pthread

BUILD_DIR := build
TARGET := port-scanner
GUI_TARGET := port-scanner-gui

GTK_CFLAGS := $(shell pkg-config --cflags gtk+-3.0 2>/dev/null)
GTK_LIBS := $(shell pkg-config --libs gtk+-3.0 2>/dev/null)

.PHONY: all gui clean

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/cli $(BUILD_DIR)/gui

# --- CLI ---

$(TARGET): $(BUILD_DIR)/cli/main.o $(BUILD_DIR)/cli/scanner.o
	$(CC) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/cli/main.o: src/main.c src/scanner.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/cli/scanner.o: src/scanner.c src/scanner.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# --- GUI (GTK 3, requires libgtk-3-dev / pkg-config gtk+-3.0) ---

gui: $(GUI_TARGET)

$(GUI_TARGET): $(BUILD_DIR)/gui/gui_main.o $(BUILD_DIR)/gui/scanner.o
	$(CC) $^ -o $@ $(LDFLAGS) $(GTK_LIBS)

$(BUILD_DIR)/gui/gui_main.o: gui/gui_main.c src/scanner.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -I src -c $< -o $@

$(BUILD_DIR)/gui/scanner.o: src/scanner.c src/scanner.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET) $(GUI_TARGET)
