#include "utils.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace secure_chat
{
    namespace
    {
        bool isSpaceChar(unsigned char ch)
        {
            return std::isspace(ch) != 0;
        }
    } // namespace

    std::string trim(const std::string& s)
    {
        std::size_t begin = 0;
        while (begin < s.size() && isSpaceChar(static_cast<unsigned char>(s[begin])))
        {
            ++begin;
        }

        if (begin == s.size())
        {
            return "";
        }

        std::size_t end = s.size();
        while (end > begin && isSpaceChar(static_cast<unsigned char>(s[end - 1])))
        {
            --end;
        }

        return s.substr(begin, end - begin);
    }

    std::string trimNewline(const std::string& s)
    {
        std::size_t end = s.size();
        while (end > 0 && (s[end - 1] == '\n' || s[end - 1] == '\r'))
        {
            --end;
        }
        return s.substr(0, end);
    }

    std::string toLower(const std::string& s)
    {
        std::string result = s;
        std::transform(result.begin(),
                       result.end(),
                       result.begin(),
                       [](unsigned char ch)
                       {
                           return static_cast<char>(std::tolower(ch));
                       });
        return result;
    }

    std::string promptLine(const std::string& prompt, bool allowEmpty)
    {
        while (true)
        {
            std::cout << prompt;
            std::string line;
            if (!std::getline(std::cin, line))
            {
                // 输入流异常或 EOF，返回空字符串交由上层处理
                return "";
            }

            line = trimNewline(line);
            if (allowEmpty || !trim(line).empty())
            {
                return line;
            }

            std::cout << "[WARN] 输入不能为空，请重新输入。\n";
        }
    }

    std::vector<unsigned char> stringToBytes(const std::string& s)
    {
        return std::vector<unsigned char>(s.begin(), s.end());
    }

    std::string bytesToString(const std::vector<unsigned char>& data)
    {
        return std::string(data.begin(), data.end());
    }

    void printHex(const std::vector<unsigned char>& data, std::ostream& os)
    {
        os << std::hex << std::setfill('0');
        for (std::size_t i = 0; i < data.size(); ++i)
        {
            os << std::setw(2) << static_cast<unsigned int>(data[i]);
            if (i + 1 != data.size())
            {
                os << ' ';
            }
        }
        os << std::dec;
    }

    void printHex(const std::vector<unsigned char>& data)
    {
        printHex(data, std::cout);
    }

    std::uint32_t hostToNetwork32(std::uint32_t value)
    {
        return htonl(value);
    }

    std::uint32_t networkToHost32(std::uint32_t value)
    {
        return ntohl(value);
    }

    bool isQuitCommand(const std::string& s)
    {
        const std::string normalized = toLower(trim(s));
        return normalized == "quit";
    }

    bool parsePort(const std::string& s, int& port)
    {
        try
        {
            std::size_t pos = 0;
            long value = std::stol(trim(s), &pos, 10);
            if (pos != trim(s).size())
            {
                return false;
            }

            if (value < MIN_PORT || value > MAX_PORT)
            {
                return false;
            }

            port = static_cast<int>(value);
            return true;
        }
        catch (const std::exception&)
        {
            return false;
        }
    }

    bool parseAlgorithm(const std::string& s, AlgorithmType& algorithm)
    {
        const std::string value = toLower(trim(s));

        if (value == "1" || value == "des")
        {
            algorithm = AlgorithmType::DES;
            return true;
        }

        if (value == "2" || value == "3des" || value == "tdes")
        {
            algorithm = AlgorithmType::TDES;
            return true;
        }

        if (value == "3" || value == "aes" || value == "aes128" || value == "aes-128")
        {
            algorithm = AlgorithmType::AES128;
            return true;
        }

        return false;
    }

    bool parseRunMode(const std::string& s, RunMode& mode)
    {
        const std::string value = toLower(trim(s));

        if (value == "1" || value == "s" || value == "server")
        {
            mode = RunMode::SERVER;
            return true;
        }

        if (value == "2" || value == "c" || value == "client")
        {
            mode = RunMode::CLIENT;
            return true;
        }

        return false;
    }

    std::string algorithmToString(AlgorithmType algorithm)
    {
        switch (algorithm)
        {
            case AlgorithmType::DES:
                return "DES";
            case AlgorithmType::TDES:
                return "3DES";
            case AlgorithmType::AES128:
                return "AES-128";
            default:
                return "UNKNOWN";
        }
    }

    std::string runModeToString(RunMode mode)
    {
        switch (mode)
        {
            case RunMode::SERVER:
                return "Server";
            case RunMode::CLIENT:
                return "Client";
            default:
                return "Unknown";
        }
    }

    std::string keyRequirementHint(AlgorithmType algorithm)
    {
        switch (algorithm)
        {
            case AlgorithmType::DES:
                return "DES 需要 8 个字符长度的密钥，例如：benbenmi";
            case AlgorithmType::TDES:
                return "3DES 需要两个 8 字节密钥，格式：key1:key2，例如：12345678:abcdefgh";
            case AlgorithmType::AES128:
                return "AES-128 需要 16 个字符长度的密钥，例如：1234567890abcdef";
            default:
                return "未知算法密钥要求";
        }
    }

    bool validateKeyForAlgorithm(const std::string& key,
                                 AlgorithmType algorithm,
                                 std::string* reason)
    {
        auto setReason = [reason](const std::string& msg)
        {
            if (reason != nullptr)
            {
                *reason = msg;
            }
        };

        switch (algorithm)
        {
            case AlgorithmType::DES:
            {
                if (key.size() != DES_KEY_SIZE)
                {
                    setReason("DES 密钥长度必须恰好为 8 个字符。");
                    return false;
                }
                return true;
            }

            case AlgorithmType::TDES:
            {
                const std::size_t pos = key.find(':');
                if (pos == std::string::npos)
                {
                    setReason("3DES 密钥格式必须为 key1:key2。");
                    return false;
                }

                const std::string key1 = key.substr(0, pos);
                const std::string key2 = key.substr(pos + 1);

                if (key1.size() != TDES_SINGLE_KEY_SIZE || key2.size() != TDES_SINGLE_KEY_SIZE)
                {
                    setReason("3DES 的 key1 和 key2 必须都恰好为 8 个字符。");
                    return false;
                }

                return true;
            }

            case AlgorithmType::AES128:
            {
                if (key.size() != AES_KEY_SIZE)
                {
                    setReason("AES-128 密钥长度必须恰好为 16 个字符。");
                    return false;
                }
                return true;
            }

            default:
            {
                setReason("未知算法类型。");
                return false;
            }
        }
    }

} // namespace secure_chat
