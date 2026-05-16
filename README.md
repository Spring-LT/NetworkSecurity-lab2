# exp_rsa_des_chat2.0

Linux 下基于 **RSA 自动分配 DES 会话密钥** 的 TCP 一对一加密聊天程序。

本项目是在第一次实验“基于 DES 加密的 TCP 聊天程序”基础上的二次扩展：

- **实验二主线**：服务端生成 RSA 公私钥，客户端自动生成 8 字节 DES 会话密钥，并使用服务端 RSA 公钥加密发送；服务端使用 RSA 私钥解密后，双方使用协商得到的 DES 会话密钥进行全双工加密聊天。
- **实验一保留功能**：仍保留原 `chat` 程序，支持手动密钥模式下的 DES / 3DES(EDE) / AES-128 加密聊天。
- **扩展提高**：新增基于 `select()` 的单进程全双工通信模型，同时保留原 `fork()` 全双工模型，便于对比验证。

> 说明：本项目用于网络安全技术课程实验与原理演示。当前 RSA 参数规模、DES 算法和 ECB 模式均不适合真实生产环境；真实安全通信应使用更大密钥、标准填充、认证加密模式以及身份认证机制。

---

## 1. 当前功能概览

### 1.1 实验二新增能力

| 功能 | 完成情况 |
|---|---|
| RSA 公私钥生成 | 服务端启动连接后自动生成 RSA 公钥/私钥 |
| RSA 公钥分发 | 服务端仅发送公钥 `(e, n)`，私钥保留在本地 |
| DES 会话密钥自动生成 | 客户端自动生成 8 字节 DES 会话密钥，不再要求用户输入 `-k` |
| RSA 加密分发 DES 密钥 | 客户端将 DES 密钥拆成 4 个 16 bit 分组并分别用 RSA 公钥加密 |
| DES 加密聊天 | 密钥交换完成后复用第一次实验 DES 加密聊天逻辑 |
| 全双工通信 | 支持 `fork()` 与 `select()` 两种模型 |
| 透明加解密 | 用户输入和屏幕显示为明文，网络传输为密文 |
| 单元 / 集成测试 | 新增 `test_rsa` 和 `test_key_exchange` |

### 1.2 保留的实验一能力

| 功能 | 说明 |
|---|---|
| DES | 自实现 DES，支持字符串分组、补位、加密和解密 |
| 3DES(EDE) | 基于 DES raw blocks 的 3DES 扩展 |
| AES-128 | 自实现 AES-128，ECB + PKCS#7，用于扩展演示 |
| TCP 封包 | `[4 bytes length] + [body]`，解决粘包、拆包和二进制密文传输问题 |
| benchmark | 保留 DES / 3DES / AES 性能测试脚本 |

---

## 2. 项目结构

```text
.
├── Makefile
├── include/
│   ├── aes.h                 # AES-128 对外接口（实验一扩展）
│   ├── chat.h                # 原聊天模块接口（fork 版本）
│   ├── chat_select.h         # 新增：select 全双工聊天接口
│   ├── config.h              # 全局常量、枚举、运行模式等
│   ├── des.h                 # DES 对外接口
│   ├── key_exchange.h        # 新增：RSA-DES 密钥交换接口
│   ├── rsa.h                 # 新增：RSA 算法接口
│   ├── rsa_des_chat.h        # 新增：实验二服务端/客户端主流程接口
│   ├── tcp.h                 # TCP socket 与封包接口
│   ├── tdes.h                # 3DES(EDE) 对外接口
│   └── utils.h               # 字符串、参数解析、密钥校验等工具
├── src/
│   ├── aes.cpp               # AES-128 实现
│   ├── chat.cpp              # 原 fork 全双工聊天逻辑
│   ├── chat_select.cpp       # 新增：select 单进程全双工聊天逻辑
│   ├── des.cpp               # DES 实现
│   ├── key_exchange.cpp      # 新增：RSA 公钥包、DES 密钥密文包收发
│   ├── main.cpp              # 原实验一 chat 程序入口
│   ├── rsa.cpp               # 新增：RSA 密钥生成、快速模幂、模逆元等
│   ├── rsa_chat_main.cpp     # 新增：实验二 rsa_chat 程序入口
│   ├── rsa_des_chat.cpp      # 新增：RSA-DES 服务端/客户端主控流程
│   ├── tcp.cpp               # TCP 建连、sendAll/recvAll、sendPacket/recvPacket
│   ├── tdes.cpp              # 3DES(EDE) 实现
│   └── utils.cpp             # 工具函数实现
├── test/
│   ├── test_aes.cpp          # AES 单元测试
│   ├── test_des.cpp          # DES 单元测试
│   ├── test_key_exchange.cpp # 新增：RSA-DES 自动密钥交换测试
│   ├── test_rsa.cpp          # 新增：RSA 单元测试
│   └── test_tdes.cpp         # 3DES 单元测试
├── benchmark/
│   └── benchmark_crypto.cpp  # DES / 3DES / AES 性能测试
├── scripts/
│   ├── run_benchmark.sh      # 实验一算法性能测试脚本
│   └── run_lab2_demo.sh      # 新增：实验二运行提示脚本
├── bin/                      # 编译产物（make 后生成）
└── build/                    # 中间文件目录（make 后生成）
```

---

## 3. 构建方法

### 3.1 构建全部目标

```bash
make
```

默认生成：

```text
bin/chat
bin/rsa_chat
bin/test_des
bin/test_tdes
bin/test_aes
bin/test_rsa
bin/test_key_exchange
```

### 3.2 仅构建实验二目标

```bash
make lab2
```

生成：

```text
bin/rsa_chat
bin/test_rsa
bin/test_key_exchange
```

### 3.3 运行全部测试

```bash
make test_all
```

等价于依次运行：

```bash
./bin/test_des
./bin/test_tdes
./bin/test_aes
./bin/test_rsa
./bin/test_key_exchange
```

### 3.4 清理编译产物

```bash
make clean
```

---

## 4. 实验二：RSA 自动分配 DES 会话密钥聊天程序

实验二主程序为：

```bash
./bin/rsa_chat
```

与第一次实验不同，`rsa_chat` 不需要用户手动输入 DES 密钥。DES 会话密钥由客户端自动生成，并通过 RSA 公钥加密发送给服务端。

### 4.1 命令行参数

```text
-m, --mode      运行模式：server / client / s / c
-i, --ip        服务端 IP，仅 client 模式需要
-p, --port      端口号
--io            全双工通信模型：select / fork
-h, --help      查看帮助
```

推荐默认使用 `select` 模型：

```bash
--io select
```

如需对比第一次实验的全双工实现方式，可以使用：

```bash
--io fork
```

### 4.2 使用 select 模型运行

打开两个终端。

终端 A：启动服务端。

```bash
./bin/rsa_chat -m server -p 9004 --io select
```

终端 B：启动客户端。

```bash
./bin/rsa_chat -m client -i 127.0.0.1 -p 9004 --io select
```

连接建立后，程序会自动完成：

```text
1. 服务端生成 RSA 公私钥
2. 服务端发送 RSA 公钥
3. 客户端自动生成 DES 会话密钥
4. 客户端使用 RSA 公钥加密 DES 会话密钥
5. 服务端使用 RSA 私钥解密 DES 会话密钥
6. 双方进入 DES 加密聊天
```

### 4.3 使用 fork 模型运行

终端 A：

```bash
./bin/rsa_chat -m server -p 9005 --io fork
```

终端 B：

```bash
./bin/rsa_chat -m client -i 127.0.0.1 -p 9005 --io fork
```

该模式保留第一次实验中父子进程分离发送/接收的全双工思路。

### 4.4 聊天与退出

连接成功后，双方直接输入聊天内容即可。

```text
hello server
hello client
Network Security Lab2
RSA distributes DES key automatically
```

任意一端输入：

```text
quit
```

程序会将 `quit` 按普通聊天消息进行 DES 加密发送，对端解密识别后退出聊天循环。

---

## 5. 实验二测试方法

### 5.1 RSA 单元测试

```bash
./bin/test_rsa
```

主要验证：

- `gcd64()`
- `modInverse()`
- `modPow()`
- Miller-Rabin 素性测试
- RSA 整数加解密
- DES 会话密钥的 RSA 加解密恢复

期望结果：所有测试项均 `[PASS]`，最终 `failed = 0`。

### 5.2 RSA-DES 自动密钥交换测试

```bash
./bin/test_key_exchange
```

该测试使用 `socketpair()` 在本机模拟服务端和客户端，验证完整握手流程：

```text
服务端生成 RSA 密钥对
服务端发送 RSA 公钥
客户端生成 DES 会话密钥
客户端用 RSA 公钥加密 DES 密钥
服务端用 RSA 私钥解密 DES 密钥
双方最终 DES 会话密钥一致
```

期望结果：所有测试项均 `[PASS]`，最终 `failed = 0`。

---

## 6. 实验一原聊天程序仍可使用

原程序入口仍为：

```bash
./bin/chat
```

该程序用于手动指定密钥的 DES / 3DES / AES-128 加密聊天。

### 6.1 DES

终端 A：

```bash
./bin/chat -m server -a des -p 9001 -k benbenmi
```

终端 B：

```bash
./bin/chat -m client -a des -i 127.0.0.1 -p 9001 -k benbenmi
```

### 6.2 3DES

终端 A：

```bash
./bin/chat -m server -a 3des -p 9002 -k 12345678:abcdefgh
```

终端 B：

```bash
./bin/chat -m client -a 3des -i 127.0.0.1 -p 9002 -k 12345678:abcdefgh
```

### 6.3 AES-128

终端 A：

```bash
./bin/chat -m server -a aes -p 9003 -k 1234567890abcdef
```

终端 B：

```bash
./bin/chat -m client -a aes -i 127.0.0.1 -p 9003 -k 1234567890abcdef
```

### 6.4 手动密钥要求

| 算法 | 密钥要求 | 示例 |
|---|---|---|
| DES | 8 字节 | `benbenmi` |
| 3DES(EDE) | 两个 8 字节密钥，用 `:` 分隔 | `12345678:abcdefgh` |
| AES-128 | 16 字节 | `1234567890abcdef` |

---

## 7. 安全性说明与后续改进

当前项目已经完整体现 RSA-DES 混合加密通信的基本思想，但仍属于课程实验级实现。

主要局限：

- RSA 使用教学规模参数，不能抵抗真实攻击。
- DES 密钥长度较短，现代安全强度不足。
- RSA 加密为裸 RSA 分组演示，未使用 OAEP 等标准填充。
- 聊天阶段未加入 HMAC 或认证加密，无法严格检测篡改。
- RSA 公钥缺少证书或指纹校验，理论上可能受到中间人攻击。
- DES / 3DES / AES 扩展中使用 ECB 模式，仅适合实验演示。

后续可改进方向：

- 使用 GMP / OpenSSL BN 等大整数库，将 RSA 提升到 2048 bit 或更高。
- 使用 RSA-OAEP 保护会话密钥。
- 使用 AES-128 / AES-256 替代 DES。
- 使用 CBC / CTR / GCM 等更安全的工作模式，并引入 IV。
- 使用 HMAC 或 AES-GCM 增加消息完整性和认证。
- 引入证书、数字签名或公钥指纹校验，防止中间人攻击。


