CC := cc
CFLAGS := -Wall -Wextra -O2 -std=gnu11
LDFLAGS := -pthread

BUILD_DIR := build
TARGET := port-scanner
GUI_TARGET := port-scanner-gui
TEST_TARGET := $(BUILD_DIR)/run-tests

GTK_CFLAGS := $(shell pkg-config --cflags gtk+-3.0 2>/dev/null)
GTK_LIBS := $(shell pkg-config --libs gtk+-3.0 2>/dev/null)

MINGW_CC := x86_64-w64-mingw32-gcc
WIN_TARGET := port-scanner.exe
WIN_GUI_TARGET := port-scanner-gui.exe

CLI_SRCS := main.c scanner.c targets.c discovery.c export.c advisories.c history.c
CLI_OBJS := $(addprefix $(BUILD_DIR)/cli/,$(CLI_SRCS:.c=.o))

.PHONY: all gui clean windows windows-cli windows-gui test

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/cli $(BUILD_DIR)/gui

# --- CLI ---

$(TARGET): $(CLI_OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/cli/%.o: src/%.c src/*.h | $(BUILD_DIR)
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

# --- Tests ---

TEST_SRCS := tests/test_main.c src/scanner.c src/targets.c src/export.c src/advisories.c src/history.c

test: $(TEST_TARGET)
	$(TEST_TARGET)

$(TEST_TARGET): $(TEST_SRCS) src/*.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I src $(TEST_SRCS) -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR) $(TARGET) $(GUI_TARGET) $(WIN_TARGET) $(WIN_GUI_TARGET)
