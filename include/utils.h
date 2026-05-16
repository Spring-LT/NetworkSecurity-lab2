#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

#include "config.h"

namespace secure_chat
{
    // =========================
    // 字符串工具
    // =========================
    std::string trim(const std::string& s);
    std::string trimNewline(const std::string& s);
    std::string toLower(const std::string& s);

    /**
     * @brief 从标准输入读取一行
     * @param prompt 提示文本
     * @param allowEmpty 是否允许空输入
     * @return 成功返回读取到的行（不含尾部 \r/\n）；EOF/错误返回空字符串
     */
    std::string promptLine(const std::string& prompt, bool allowEmpty = false);

    // =========================
    // 字节工具
    // =========================
    std::vector<unsigned char> stringToBytes(const std::string& s);
    std::string bytesToString(const std::vector<unsigned char>& data);

    void printHex(const std::vector<unsigned char>& data, std::ostream& os);
    void printHex(const std::vector<unsigned char>& data);

    // =========================
    // 字节序工具
    // =========================
    std::uint32_t hostToNetwork32(std::uint32_t value);
    std::uint32_t networkToHost32(std::uint32_t value);

    // =========================
    // 聊天辅助
    // =========================
    bool isQuitCommand(const std::string& s);

    // =========================
    // 解析与校验
    // =========================
    bool parsePort(const std::string& s, int& port);
    bool parseAlgorithm(const std::string& s, AlgorithmType& algorithm);
    bool parseRunMode(const std::string& s, RunMode& mode);

    std::string algorithmToString(AlgorithmType algorithm);
    std::string runModeToString(RunMode mode);

    std::string keyRequirementHint(AlgorithmType algorithm);
    bool validateKeyForAlgorithm(const std::string& key,
                                 AlgorithmType algorithm,
                                 std::string* reason = nullptr);

} // namespace secure_chat
