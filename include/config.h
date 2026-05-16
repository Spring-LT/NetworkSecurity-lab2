#pragma once

#include <cstddef>
#include <cstdint>

namespace secure_chat
{
    // =========================
    // 全局常量
    // =========================
    constexpr int DEFAULT_PORT = 8888;
    constexpr int MIN_PORT = 1024;
    constexpr int MAX_PORT = 65535;

    constexpr std::size_t BUFFER_SIZE = 1024;
    constexpr std::size_t LENGTH_HEADER_SIZE = 4;

    constexpr std::size_t DES_BLOCK_SIZE = 8;
    constexpr std::size_t DES_KEY_SIZE = 8;

    // 3DES 扩展中使用两个 8 字节密钥，格式约定为：key1:key2
    constexpr std::size_t TDES_SINGLE_KEY_SIZE = 8;

    constexpr std::size_t AES_BLOCK_SIZE = 16;
    constexpr std::size_t AES_KEY_SIZE = 16;

    // 为了和教材示例保持风格一致，DES 提供一个默认演示密钥
    constexpr const char* DEFAULT_DES_KEY = "benbenmi";

    // =========================
    // 枚举
    // =========================
    enum class AlgorithmType
    {
        DES = 1,
        TDES = 2,
        AES128 = 3
    };

    enum class RunMode
    {
        SERVER = 1,
        CLIENT = 2
    };

    enum class StatusCode
    {
        SUCCESS = 0,
        ERROR_INVALID_ARGUMENT = -1,
        ERROR_RUNTIME = -2
    };

} // namespace secure_chat
