CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -g -Iinclude
LDFLAGS := -pthread

BIN_DIR := bin
BUILD_DIR := build

COMMON_SRCS := \
	src/aes.cpp \
	src/chat.cpp \
	src/chat_select.cpp \
	src/des.cpp \
	src/key_exchange.cpp \
	src/rsa.cpp \
	src/rsa_des_chat.cpp \
	src/tcp.cpp \
	src/tdes.cpp \
	src/utils.cpp

CHAT_SRCS := \
	src/main.cpp \
	$(COMMON_SRCS)

RSA_CHAT_SRCS := \
	src/rsa_chat_main.cpp \
	$(COMMON_SRCS)

TEST_DES_SRCS := \
	test/test_des.cpp \
	src/des.cpp \
	src/utils.cpp

TEST_TDES_SRCS := \
	test/test_tdes.cpp \
	src/des.cpp \
	src/tdes.cpp \
	src/utils.cpp

TEST_AES_SRCS := \
	test/test_aes.cpp \
	src/aes.cpp \
	src/utils.cpp

TEST_RSA_SRCS := \
	test/test_rsa.cpp \
	src/rsa.cpp \
	src/utils.cpp

TEST_KEY_EXCHANGE_SRCS := \
	test/test_key_exchange.cpp \
	src/key_exchange.cpp \
	src/rsa.cpp \
	src/tcp.cpp \
	src/utils.cpp

.PHONY: all clean test_all dirs lab2

all: dirs \
	$(BIN_DIR)/chat \
	$(BIN_DIR)/rsa_chat \
	$(BIN_DIR)/test_des \
	$(BIN_DIR)/test_tdes \
	$(BIN_DIR)/test_aes \
	$(BIN_DIR)/test_rsa \
	$(BIN_DIR)/test_key_exchange

lab2: dirs \
	$(BIN_DIR)/rsa_chat \
	$(BIN_DIR)/test_rsa \
	$(BIN_DIR)/test_key_exchange

dirs:
	mkdir -p $(BIN_DIR) $(BUILD_DIR)

$(BIN_DIR)/chat: $(CHAT_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/rsa_chat: $(RSA_CHAT_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/test_des: $(TEST_DES_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/test_tdes: $(TEST_TDES_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/test_aes: $(TEST_AES_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/test_rsa: $(TEST_RSA_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/test_key_exchange: $(TEST_KEY_EXCHANGE_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

test_all: all
	./$(BIN_DIR)/test_des
	./$(BIN_DIR)/test_tdes
	./$(BIN_DIR)/test_aes
	./$(BIN_DIR)/test_rsa
	./$(BIN_DIR)/test_key_exchange

clean:
	rm -rf $(BIN_DIR) $(BUILD_DIR)
