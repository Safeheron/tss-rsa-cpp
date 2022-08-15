#include <benchmark/benchmark.h>
#include "gtest/gtest.h"
#include "crypto-bn/bn.h"
#include "../src/crypto-tss-rsa/tss_rsa.h"
#include "exception/safeheron_exceptions.h"
using safeheron::bignum::BN;
using safeheron::tss_rsa::RSAPrivateKeyShare;
using safeheron::tss_rsa::RSAPublicKey;
using safeheron::tss_rsa::RSAKeyMeta;
using safeheron::tss_rsa::RSASigShare;
using safeheron::tss_rsa::KeyGenParam;


void BM_generateRandom(benchmark::State& state, int key_bits_length, int l, int k);
void BM_generateEx(benchmark::State& state, int key_bits_length, int l, int k);

void BM_generateSig(benchmark::State& state);
void BM_combineSig(benchmark::State& state);
void BM_verifySig(benchmark::State& state);

std::vector< std::vector<RSAPrivateKeyShare>> priv_arr;
std::vector<RSAPublicKey> pub;
std::vector<RSAKeyMeta> key_meta;
std::vector< std::vector<RSASigShare>> sig_arr;
std::vector<BN> sig;

std::vector<KeyGenParam> param;
std::string doc[] = {"hello world, 1",
                 "hello world, 2",
                 "hello world, 3",
                 "hello world, 4",
                 "hello world, 5",
                 "hello world, 6",
                 "hello world, 7",
                 "hello world, 8",
                 "hello world, 9",
                 "hello world, 10"
                };

void BM_generateRandom(benchmark::State& state, int key_bits_length, int l, int k) {
    priv_arr.resize(state.max_iterations);
    pub.resize(state.max_iterations);
    key_meta.resize(state.max_iterations);
    sig_arr.resize(state.max_iterations);
    sig.resize(state.max_iterations);
    int count = 0;
    for (auto _ : state) {
        priv_arr[count].clear();
        safeheron::tss_rsa::GenerateKey(key_bits_length, l, k, priv_arr[count], pub[count], key_meta[count]);
        count++;
    }
}

void BM_generateEx(benchmark::State& state, int key_bits_length, int l, int k) {
    priv_arr.resize(state.max_iterations);
    pub.resize(state.max_iterations);
    key_meta.resize(state.max_iterations);
    sig_arr.resize(state.max_iterations);
    sig.resize(state.max_iterations);
    int count = 0;
    for (auto _ : state) {
        priv_arr[count].clear();
        safeheron::tss_rsa::GenerateKeyEx(key_bits_length, l, k, param[count], priv_arr[count], pub[count], key_meta[count]);
        count++;
    }
}

void BM_generateSig(benchmark::State& state) {
    for (auto _: state) {
        for (size_t i = 0; i < priv_arr.size(); i++) {
            sig_arr[i].clear();
            for (size_t j = 0; j < priv_arr[i].size(); j++) {
                sig_arr[i].emplace_back(priv_arr[i][j].Sign(doc[i], key_meta[i], pub[i]));
            }
        }
    }
}

void BM_combineSig(benchmark::State& state) {
    for (auto _ : state) {
        for(size_t i = 0; i < sig_arr.size(); i++) {
            CombineSignaturesWithoutValidation(doc[i], sig_arr[i], pub[i], key_meta[i], sig[i]);
        }
    }
}

void BM_verifySig(benchmark::State& state) {
    for (auto _ : state) {
        for(size_t i = 0; i < sig.size(); i++) {
            pub[i].VerifySignature(doc[i], sig[i]);
        }
    }
    for(size_t i = 0; i < sig.size(); i++) {
        EXPECT_TRUE(pub[i].VerifySignature(doc[i], sig[i]));
    }
}

int main(int argc, char** argv) {
    benchmark::Initialize(&argc, argv);
    int n_key_pairs = 10;
    // Generate "n_key_pairs" key pairs: n_key_pairs = 10
    ::benchmark::RegisterBenchmark("BM_generateRandom", &BM_generateRandom, 4096, 5, 3)->Iterations(n_key_pairs)->Unit(benchmark::kSecond);
    // Generate 10 * "n_key_pairs" signature shares
    ::benchmark::RegisterBenchmark("BM_generateSig", &BM_generateSig)->Iterations(10)->Unit(benchmark::kSecond);
    // Combine 10 * "n_key_pairs" signatures
    ::benchmark::RegisterBenchmark("BM_combineSig", &BM_combineSig)->Iterations(10)->Unit(benchmark::kSecond);
    // Verify 10 * "n_key_pairs" signatures
    ::benchmark::RegisterBenchmark("BM_verifySig", &BM_verifySig)->Iterations(10)->Unit(benchmark::kSecond);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

