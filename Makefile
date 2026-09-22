CC := cc
CFLAGS := -Wall -Wextra -O2 -std=gnu11
LDFLAGS := -pthread

BUILD_DIR := build
TARGET := port-scanner
GUI_TARGET := port-scanner-gui

GTK_CFLAGS := $(shell pkg-config --cflags gtk+-3.0 2>/dev/null)
GTK_LIBS := $(shell pkg-config --libs gtk+-3.0 2>/dev/null)

MINGW_CC := x86_64-w64-mingw32-gcc
WIN_TARGET := port-scanner.exe
WIN_GUI_TARGET := port-scanner-gui.exe

.PHONY: all gui clean windows windows-cli windows-gui

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

# --- Windows (cross-compiled with mingw-w64; produces standalone .exe
# files that only depend on standard Windows system DLLs) ---

windows: windows-cli windows-gui

windows-cli: $(WIN_TARGET)

$(WIN_TARGET): windows/main_win.c windows/scanner_win.c windows/scanner_win.h
	$(MINGW_CC) $(CFLAGS) windows/main_win.c windows/scanner_win.c -o $@ -lws2_32

windows-gui: $(WIN_GUI_TARGET)

$(WIN_GUI_TARGET): windows/gui_win_main.c windows/scanner_win.c windows/scanner_win.h
	$(MINGW_CC) $(CFLAGS) -municode -mwindows windows/gui_win_main.c windows/scanner_win.c -o $@ -lws2_32 -lcomctl32

clean:
	rm -rf $(BUILD_DIR) $(TARGET) $(GUI_TARGET) $(WIN_TARGET) $(WIN_GUI_TARGET)
