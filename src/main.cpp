#include <exception>
#include <iostream>
#include <string>
#include <vector>

#include "chat.h"
#include "config.h"
#include "utils.h"

namespace secure_chat
{
    namespace
    {
        struct AppOptions
        {
            bool useCommandLineMode = false;
            bool showHelp = false;

            bool modeSpecified = false;
            bool algorithmSpecified = false;
            bool portSpecified = false;
            bool keySpecified = false;
            bool ipSpecified = false;

            RunMode mode = RunMode::SERVER;
            AlgorithmType algorithm = AlgorithmType::DES;
            int port = DEFAULT_PORT;
            std::string key;
            std::string serverIp;
        };

        void printBanner()
        {
            std::cout << "=============================================\n";
            std::cout << "  Secure TCP Chat Program\n";
            std::cout << "  Course Experiment: DES-based TCP Chat\n";
            std::cout << "=============================================\n";
        }

        void printHelp(const char* programName)
        {
            std::cout << "Usage:\n";
            std::cout << "  " << programName << "                         # 交互模式\n";
            std::cout << "  " << programName << " -m server -a des -p 8888 -k benbenmi\n";
            std::cout << "  " << programName << " -m client -a des -i 127.0.0.1 -p 8888 -k benbenmi\n";
            std::cout << "\n";
            std::cout << "Options:\n";
            std::cout << "  -m, --mode         server | client | s | c\n";
            std::cout << "  -a, --algorithm    des | 3des | aes\n";
            std::cout << "  -i, --ip           server ip (client mode only)\n";
            std::cout << "  -p, --port         port number (" << MIN_PORT << "-" << MAX_PORT << ")\n";
            std::cout << "  -k, --key          encryption key\n";
            std::cout << "  -h, --help         show help\n";
            std::cout << "\n";
            std::cout << "Key requirements:\n";
            std::cout << "  DES     : " << keyRequirementHint(AlgorithmType::DES) << "\n";
            std::cout << "  3DES    : " << keyRequirementHint(AlgorithmType::TDES) << "\n";
            std::cout << "  AES-128 : " << keyRequirementHint(AlgorithmType::AES128) << "\n";
        }

        void printInteractiveMenus()
        {
            std::cout << "\nPlease choose run mode:\n";
            std::cout << "  1. Server\n";
            std::cout << "  2. Client\n";
            std::cout << "\nPlease choose algorithm:\n";
            std::cout << "  1. DES     (main experiment requirement)\n";
            std::cout << "  2. 3DES    (extension)\n";
            std::cout << "  3. AES-128 (extension)\n";
            std::cout << "\n";
        }

        bool parseCommandLine(int argc, char* argv[], AppOptions& options, std::string& error)
        {
            if (argc <= 1)
            {
                options.useCommandLineMode = false;
                return true;
            }

            options.useCommandLineMode = true;

            for (int i = 1; i < argc; ++i)
            {
                const std::string arg = argv[i];

                if (arg == "-h" || arg == "--help")
                {
                    options.showHelp = true;
                    return true;
                }
                else if (arg == "-m" || arg == "--mode")
                {
                    if (i + 1 >= argc)
                    {
                        error = "缺少 mode 参数值。";
                        return false;
                    }

                    RunMode mode;
                    if (!parseRunMode(argv[++i], mode))
                    {
                        error = "无效的 mode 参数，必须是 server/client/s/c。";
                        return false;
                    }

                    options.mode = mode;
                    options.modeSpecified = true;
                }
                else if (arg == "-a" || arg == "--algorithm")
                {
                    if (i + 1 >= argc)
                    {
                        error = "缺少 algorithm 参数值。";
                        return false;
                    }

                    AlgorithmType algorithm;
                    if (!parseAlgorithm(argv[++i], algorithm))
                    {
                        error = "无效的 algorithm 参数，必须是 des / 3des / aes。";
                        return false;
                    }

                    options.algorithm = algorithm;
                    options.algorithmSpecified = true;
                }
                else if (arg == "-i" || arg == "--ip")
                {
                    if (i + 1 >= argc)
                    {
                        error = "缺少 ip 参数值。";
                        return false;
                    }

                    options.serverIp = trim(argv[++i]);
                    options.ipSpecified = true;
                }
                else if (arg == "-p" || arg == "--port")
                {
                    if (i + 1 >= argc)
                    {
                        error = "缺少 port 参数值。";
                        return false;
                    }

                    int port = 0;
                    if (!parsePort(argv[++i], port))
                    {
                        error = "无效的端口号。";
                        return false;
                    }

                    options.port = port;
                    options.portSpecified = true;
                }
                else if (arg == "-k" || arg == "--key")
                {
                    if (i + 1 >= argc)
                    {
                        error = "缺少 key 参数值。";
                        return false;
                    }

                    options.key = argv[++i];
                    options.keySpecified = true;
                }
                else
                {
                    error = "无法识别的参数: " + arg;
                    return false;
                }
            }

            return true;
        }

        bool fillOptionsInteractively(AppOptions& options)
        {
            printInteractiveMenus();

            while (true)
            {
                const std::string modeInput = promptLine("Client or Server? (1/2 or s/c): ");
                if (modeInput.empty())
                {
                    std::cout << "[ERROR] 读取模式输入失败。\n";
                    return false;
                }

                RunMode mode;
                if (parseRunMode(modeInput, mode))
                {
                    options.mode = mode;
                    options.modeSpecified = true;
                    break;
                }

                std::cout << "[WARN] 无效输入，请输入 1/2/s/c/server/client。\n";
            }

            while (true)
            {
                const std::string algInput = promptLine("Select algorithm (1=DES, 2=3DES, 3=AES-128): ");
                if (algInput.empty())
                {
                    std::cout << "[ERROR] 读取算法输入失败。\n";
                    return false;
                }

                AlgorithmType algorithm;
                if (parseAlgorithm(algInput, algorithm))
                {
                    options.algorithm = algorithm;
                    options.algorithmSpecified = true;
                    break;
                }

                std::cout << "[WARN] 无效输入，请输入 1/2/3 或 des/3des/aes。\n";
            }

            while (true)
            {
                const std::string portPrompt =
                    "Please input port (default " + std::to_string(DEFAULT_PORT) + "): ";
                const std::string portInput = promptLine(portPrompt, true);

                if (trim(portInput).empty())
                {
                    options.port = DEFAULT_PORT;
                    options.portSpecified = true;
                    break;
                }

                int port = 0;
                if (parsePort(portInput, port))
                {
                    options.port = port;
                    options.portSpecified = true;
                    break;
                }

                std::cout << "[WARN] 端口号无效，请输入 " << MIN_PORT << "-" << MAX_PORT << " 之间的整数。\n";
            }

            while (true)
            {
                std::cout << keyRequirementHint(options.algorithm) << "\n";

                std::string keyPrompt = "Please input key";
                if (options.algorithm == AlgorithmType::DES)
                {
                    keyPrompt += " (press Enter to use default: ";
                    keyPrompt += DEFAULT_DES_KEY;
                    keyPrompt += ")";
                }
                keyPrompt += ": ";

                std::string keyInput = promptLine(keyPrompt, true);

                if (trim(keyInput).empty() && options.algorithm == AlgorithmType::DES)
                {
                    options.key = DEFAULT_DES_KEY;
                    options.keySpecified = true;
                    break;
                }

                std::string reason;
                if (validateKeyForAlgorithm(keyInput, options.algorithm, &reason))
                {
                    options.key = keyInput;
                    options.keySpecified = true;
                    break;
                }

                std::cout << "[WARN] 密钥无效: " << reason << "\n";
            }

            if (options.mode == RunMode::CLIENT)
            {
                while (true)
                {
                    const std::string ipInput = promptLine("Please input the server address: ");
                    if (trim(ipInput).empty())
                    {
                        std::cout << "[WARN] 服务端 IP 不能为空。\n";
                        continue;
                    }

                    options.serverIp = trim(ipInput);
                    options.ipSpecified = true;
                    break;
                }
            }

            return true;
        }

        bool validateFinalOptions(const AppOptions& options, std::string& error)
        {
            if (!options.modeSpecified)
            {
                error = "运行模式未指定。";
                return false;
            }

            if (!options.algorithmSpecified && options.useCommandLineMode)
            {
                error = "命令行模式下必须显式指定算法。";
                return false;
            }

            if (!options.portSpecified && options.useCommandLineMode)
            {
                error = "命令行模式下必须显式指定端口。";
                return false;
            }

            if (!options.keySpecified && options.useCommandLineMode)
            {
                error = "命令行模式下必须显式指定密钥。";
                return false;
            }

            if (options.mode == RunMode::CLIENT && trim(options.serverIp).empty())
            {
                error = "客户端模式必须提供服务端 IP 地址。";
                return false;
            }

            std::string reason;
            if (!validateKeyForAlgorithm(options.key, options.algorithm, &reason))
            {
                error = "密钥校验失败: " + reason;
                return false;
            }

            if (options.port < MIN_PORT || options.port > MAX_PORT)
            {
                error = "端口号超出合法范围。";
                return false;
            }

            return true;
        }

        void printSummary(const AppOptions& options)
        {
            std::cout << "\n========== Configuration Summary ==========\n";
            std::cout << "Mode      : " << runModeToString(options.mode) << "\n";
            std::cout << "Algorithm : " << algorithmToString(options.algorithm) << "\n";
            std::cout << "Port      : " << options.port << "\n";
            if (options.mode == RunMode::CLIENT)
            {
                std::cout << "Server IP : " << options.serverIp << "\n";
            }
            std::cout << "Key       : [hidden for display safety]\n";
            std::cout << "===========================================\n\n";
        }

        int runApplication(const AppOptions& options)
        {
            printSummary(options);

            if (options.mode == RunMode::SERVER)
            {
                std::cout << "[INFO] Starting server...\n";
                runServer(options.port, options.key, options.algorithm);
            }
            else
            {
                std::cout << "[INFO] Starting client...\n";
                runClient(options.serverIp, options.port, options.key, options.algorithm);
            }

            return static_cast<int>(StatusCode::SUCCESS);
        }

    } // namespace
} // namespace secure_chat

int main(int argc, char* argv[])
{
    using namespace secure_chat;

    printBanner();

    AppOptions options;
    std::string error;

    if (!parseCommandLine(argc, argv, options, error))
    {
        std::cerr << "[ERROR] 参数解析失败: " << error << "\n\n";
        printHelp(argv[0]);
        return static_cast<int>(StatusCode::ERROR_INVALID_ARGUMENT);
    }

    if (options.showHelp)
    {
        printHelp(argv[0]);
        return static_cast<int>(StatusCode::SUCCESS);
    }

    if (!options.useCommandLineMode)
    {
        if (!fillOptionsInteractively(options))
        {
            std::cerr << "[ERROR] 交互输入失败。\n";
            return static_cast<int>(StatusCode::ERROR_RUNTIME);
        }
    }

    if (!validateFinalOptions(options, error))
    {
        std::cerr << "[ERROR] 配置无效: " << error << "\n";
        return static_cast<int>(StatusCode::ERROR_INVALID_ARGUMENT);
    }

    try
    {
        return runApplication(options);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[ERROR] 程序运行异常: " << ex.what() << "\n";
        return static_cast<int>(StatusCode::ERROR_RUNTIME);
    }
    catch (...)
    {
        std::cerr << "[ERROR] 程序发生未知异常。\n";
        return static_cast<int>(StatusCode::ERROR_RUNTIME);
    }
}
