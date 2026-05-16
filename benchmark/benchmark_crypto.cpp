#include "aes.h"
#include "des.h"
#include "tdes.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef BENCH_TARGET_MIB
#define BENCH_TARGET_MIB 1
#endif

#ifndef BENCH_MIN_ITERS
#define BENCH_MIN_ITERS 8
#endif

using Clock = std::chrono::steady_clock;
using secure_chat::AES128;
using secure_chat::DES;
using secure_chat::TripleDES;

struct Result
{
    std::string algorithm;
    std::size_t messageSize = 0;
    std::size_t iterations = 0;
    double encryptMs = 0.0;
    double decryptMs = 0.0;
    double encUsPerOp = 0.0;
    double decUsPerOp = 0.0;
    double encMiBs = 0.0;
    double decMiBs = 0.0;
    double roundtripMiBs = 0.0;
};

class Cipher
{
public:
    virtual ~Cipher() = default;
    virtual bool setKey(const std::string& key) = 0;
    virtual std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext) const = 0;
    virtual std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext) const = 0;
};

class DESCipher final : public Cipher
{
public:
    bool setKey(const std::string& key) override { return des_.setKey(key); }
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext) const override
    {
        return des_.encrypt(plaintext);
    }
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext) const override
    {
        return des_.decrypt(ciphertext);
    }

private:
    DES des_;
};

class TDESCipher final : public Cipher
{
public:
    bool setKey(const std::string& key) override { return tdes_.setKey(key); }
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext) const override
    {
        return tdes_.encrypt(plaintext);
    }
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext) const override
    {
        return tdes_.decrypt(ciphertext);
    }

private:
    TripleDES tdes_;
};

class AESCipher final : public Cipher
{
public:
    bool setKey(const std::string& key) override { return aes_.setKey(key); }
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext) const override
    {
        return aes_.encrypt(plaintext);
    }
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext) const override
    {
        return aes_.decrypt(ciphertext);
    }

private:
    AES128 aes_;
};

static std::unique_ptr<Cipher> makeCipher(const std::string& algorithm)
{
    if (algorithm == "DES")
    {
        return std::make_unique<DESCipher>();
    }
    if (algorithm == "3DES")
    {
        return std::make_unique<TDESCipher>();
    }
    if (algorithm == "AES-128")
    {
        return std::make_unique<AESCipher>();
    }
    return nullptr;
}

static std::string keyFor(const std::string& algorithm)
{
    if (algorithm == "DES")
    {
        return "benbenmi";
    }
    if (algorithm == "3DES")
    {
        return "12345678:abcdefgh";
    }
    return "1234567890abcdef";
}

static std::vector<unsigned char> makePayload(std::size_t n)
{
    static const std::string alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>/?";

    std::vector<unsigned char> out;
    out.reserve(n);

    for (std::size_t i = 0; i < n; ++i)
    {
        out.push_back(static_cast<unsigned char>(alphabet[i % alphabet.size()]));
    }

    return out;
}

static Result runBenchmark(const std::string& algorithm,
                           std::size_t messageSize,
                           std::size_t iterations)
{
    auto cipher = makeCipher(algorithm);
    if (!cipher)
    {
        throw std::runtime_error("Unknown algorithm: " + algorithm);
    }

    if (!cipher->setKey(keyFor(algorithm)))
    {
        throw std::runtime_error("setKey failed: " + algorithm);
    }

    const std::vector<unsigned char> plaintext = makePayload(messageSize);
    const std::vector<unsigned char> probeCipher = cipher->encrypt(plaintext);
    const std::vector<unsigned char> probePlain = cipher->decrypt(probeCipher);

    if (probePlain != plaintext)
    {
        throw std::runtime_error("Round-trip verification failed: " + algorithm);
    }

    volatile std::size_t sink = 0;

    for (int i = 0; i < 3; ++i)
    {
        const auto warm = cipher->encrypt(plaintext);
        sink += warm.size();
    }

    std::vector<unsigned char> lastCipher;
    const auto encStart = Clock::now();
    for (std::size_t i = 0; i < iterations; ++i)
    {
        lastCipher = cipher->encrypt(plaintext);
        sink += lastCipher[0];
    }
    const auto encEnd = Clock::now();

    std::vector<unsigned char> lastPlain;
    const auto decStart = Clock::now();
    for (std::size_t i = 0; i < iterations; ++i)
    {
        lastPlain = cipher->decrypt(lastCipher);
        sink += lastPlain[0];
    }
    const auto decEnd = Clock::now();

    if (lastPlain != plaintext)
    {
        throw std::runtime_error("Final verification failed: " + algorithm);
    }

    const double encryptMs =
        std::chrono::duration<double, std::milli>(encEnd - encStart).count();
    const double decryptMs =
        std::chrono::duration<double, std::milli>(decEnd - decStart).count();

    const double totalMiB =
        (static_cast<double>(messageSize) * static_cast<double>(iterations)) /
        (1024.0 * 1024.0);

    Result r;
    r.algorithm = algorithm;
    r.messageSize = messageSize;
    r.iterations = iterations;
    r.encryptMs = encryptMs;
    r.decryptMs = decryptMs;
    r.encUsPerOp = encryptMs * 1000.0 / static_cast<double>(iterations);
    r.decUsPerOp = decryptMs * 1000.0 / static_cast<double>(iterations);
    r.encMiBs = totalMiB / (encryptMs / 1000.0);
    r.decMiBs = totalMiB / (decryptMs / 1000.0);
    r.roundtripMiBs = (2.0 * totalMiB) / ((encryptMs + decryptMs) / 1000.0);

    if (sink == 42)
    {
        std::cerr << "";
    }

    return r;
}

static void writeCsv(const std::string& path, const std::vector<Result>& results)
{
    std::ofstream out(path);
    out << "algorithm,message_size,iterations,encrypt_ms,decrypt_ms,"
           "enc_us_per_op,dec_us_per_op,enc_mib_s,dec_mib_s,roundtrip_mib_s\n";

    out << std::fixed << std::setprecision(3);
    for (const auto& r : results)
    {
        out << r.algorithm << ','
            << r.messageSize << ','
            << r.iterations << ','
            << r.encryptMs << ','
            << r.decryptMs << ','
            << r.encUsPerOp << ','
            << r.decUsPerOp << ','
            << r.encMiBs << ','
            << r.decMiBs << ','
            << r.roundtripMiBs << '\n';
    }
}

int main()
{
    const std::vector<std::string> algorithms = {"DES", "3DES", "AES-128"};
    const std::vector<std::size_t> sizes = {64, 1024, 65536};

    const std::size_t targetBytes =
        static_cast<std::size_t>(BENCH_TARGET_MIB) * 1024ull * 1024ull;
    const std::size_t minIterations = static_cast<std::size_t>(BENCH_MIN_ITERS);

    std::vector<Result> results;

    for (const auto& alg : algorithms)
    {
        for (const auto size : sizes)
        {
            const std::size_t iterations =
                std::max(minIterations, targetBytes / size);

            const Result r = runBenchmark(alg, size, iterations);
            results.push_back(r);

            std::cout << std::fixed << std::setprecision(2)
                      << "[OK] " << alg
                      << " size=" << size
                      << " iter=" << iterations
                      << " enc=" << r.encUsPerOp << " us/op"
                      << " dec=" << r.decUsPerOp << " us/op"
                      << " roundtrip=" << r.roundtripMiBs << " MiB/s"
                      << '\n';
        }
    }

    writeCsv("report/benchmark_results.csv", results);

    std::cout << "[DONE] CSV written to report/benchmark_results.csv\n";
    return 0;
}
