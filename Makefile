# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++11 -O3 -march=native -Wall -Wextra -I./include

# Linker flags
LDFLAGS = -lpthread

# Directories
SRC_DIR = src
INC_DIR = include
BIN_DIR = bin
OBJ_DIR = obj

# Files
SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
OBJECTS = $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SOURCES))
TARGET = $(BIN_DIR)/udp_stat_test

# Default target
all: $(TARGET)

# Create output directories
$(OBJ_DIR) $(BIN_DIR):
	mkdir -p $@

# Link executable
$(TARGET): $(OBJ_DIR) $(BIN_DIR) $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean generated files
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Run executable
run: $(TARGET)
	./$(TARGET)

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGET)

.PHONY: all clean run debug