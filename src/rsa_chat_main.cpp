#include <exception>
#include <iostream>
#include <string>

#include "config.h"
#include "rsa_des_chat.h"
#include "utils.h"

namespace secure_chat
{
    namespace
    {
        struct Lab2Options
        {
            bool showHelp = false;
            bool modeSpecified = false;
            bool portSpecified = false;
            bool ipSpecified = false;
            bool ioSpecified = false;

            RunMode mode = RunMode::SERVER;
            int port = DEFAULT_PORT;
            std::string serverIp;
            ChatIoModel ioModel = ChatIoModel::SELECT;
        };

        void printBanner()
        {
            std::cout << "=============================================\n";
            std::cout << "  Secure TCP Chat Program - Lab2 RSA-DES\n";
            std::cout << "  RSA distributes DES session key automatically\n";
            std::cout << "=============================================\n";
        }

        void printHelp(const char* programName)
        {
            std::cout << "Usage:\n";
            std::cout << "  " << programName << " -m server -p 9004\n";
            std::cout << "  " << programName << " -m client -i 127.0.0.1 -p 9004\n";
            std::cout << "  " << programName << " -m server -p 9004 --io select\n";
            std::cout << "  " << programName << " -m client -i 127.0.0.1 -p 9004 --io select\n";
            std::cout << "\nOptions:\n";
            std::cout << "  -m, --mode       server | client | s | c\n";
            std::cout << "  -i, --ip         server ip, only required in client mode\n";
            std::cout << "  -p, --port       port number (" << MIN_PORT << "-" << MAX_PORT << ")\n";
            std::cout << "      --io         select | fork, default: select\n";
            std::cout << "  -h, --help       show help\n";
            std::cout << "\nImportant:\n";
            std::cout << "  This Lab2 program does not require -k/--key.\n";
            std::cout << "  The client generates an 8-byte DES session key automatically.\n";
        }

        bool parseCommandLine(int argc,
                              char* argv[],
                              Lab2Options& options,
                              std::string& error)
        {
            // 1. 逐项读取命令行参数。
            // 2. 对 mode、ip、port、io 分别解析。
            // 3. 实验二不接受 -k，因为 DES 密钥必须自动生成。
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
                else if (arg == "--io")
                {
                    if (i + 1 >= argc)
                    {
                        error = "缺少 io 参数值。";
                        return false;
                    }

                    ChatIoModel model;
                    if (!parseChatIoModel(argv[++i], model))
                    {
                        error = "无效的 io 参数，必须是 select 或 fork。";
                        return false;
                    }

                    options.ioModel = model;
                    options.ioSpecified = true;
                }
                else if (arg == "-k" || arg == "--key")
                {
                    error = "实验二自动密钥分配程序不允许手工输入 -k/--key。";
                    return false;
                }
                else
                {
                    error = "无法识别的参数: " + arg;
                    return false;
                }
            }

            return true;
        }

        bool validateOptions(const Lab2Options& options, std::string& error)
        {
            // 1. mode 必须指定。
            if (!options.modeSpecified)
            {
                error = "必须通过 -m/--mode 指定 server 或 client。";
                return false;
            }

            // 2. port 必须指定。
            if (!options.portSpecified)
            {
                error = "必须通过 -p/--port 指定端口号。";
                return false;
            }

            // 3. client 模式必须指定服务端 IP。
            if (options.mode == RunMode::CLIENT && trim(options.serverIp).empty())
            {
                error = "客户端模式必须通过 -i/--ip 指定服务端 IP。";
                return false;
            }

            // 4. port 必须在合法范围内。
            if (options.port < MIN_PORT || options.port > MAX_PORT)
            {
                error = "端口号超出合法范围。";
                return false;
            }

            return true;
        }

        void printSummary(const Lab2Options& options)
        {
            std::cout << "\n========== Lab2 Configuration Summary ==========\n";
            std::cout << "Mode      : " << runModeToString(options.mode) << "\n";
            std::cout << "Port      : " << options.port << "\n";

            if (options.mode == RunMode::CLIENT)
            {
                std::cout << "Server IP : " << options.serverIp << "\n";
            }

            std::cout << "Algorithm : DES after RSA key exchange\n";
            std::cout << "Key       : generated automatically [hidden]\n";
            std::cout << "IO Model  : " << chatIoModelToString(options.ioModel) << "\n";
            std::cout << "================================================\n\n";
        }

        int runApplication(const Lab2Options& options)
        {
            printSummary(options);

            if (options.mode == RunMode::SERVER)
            {
                std::cout << "[INFO] Starting Lab2 RSA-DES server...\n";
                runRsaDesServer(options.port, options.ioModel);
            }
            else
            {
                std::cout << "[INFO] Starting Lab2 RSA-DES client...\n";
                runRsaDesClient(options.serverIp, options.port, options.ioModel);
            }

            return static_cast<int>(StatusCode::SUCCESS);
        }

    } // namespace
} // namespace secure_chat

int main(int argc, char* argv[])
{
    using namespace secure_chat;

    printBanner();

    Lab2Options options;
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

    if (!validateOptions(options, error))
    {
        std::cerr << "[ERROR] 配置无效: " << error << "\n\n";
        printHelp(argv[0]);
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
