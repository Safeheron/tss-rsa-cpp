# tss-rsa-cpp

![img](doc/logo.png)

This software implements a library for tss-rsa according to paper [Practical Threshold Signatures](https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf).

The library comes with serialize/deserialize support to be used in higher level code to implement networking.

# Prerequisites

- [OpenSSL](https://github.com/openssl/openssl#documentation). See the [OpenSSL Installation Instructions](./doc/OpenSSL-Installation.md)
- [Protocol Buffers](https://github.com/protocolbuffers/protobuf.git). See the [Protocol Buffers Installation Instructions](./doc/Protocol-Buffers-Installation.md)
- [crypto-suites-cpp](https://github.com/safeheron/crypto-suites-cpp.git). See the [crypto-suites-cpp Installation Instructions](https://github.com/safeheron/crypto-suites-cpp/blob/main/README.md#build-and-install). **Version v0.8.0 or later required**.

# Build and Install

Linux and Mac are supported now.  After obtaining the Source, have a look at the installation script.

```shell
git clone https://github.com/safeheron/tss-rsa-cpp.git
cd tss-rsa-cpp
mkdir build && cd build
# Run "cmake .. -DOPENSSL_ROOT_DIR=Your-Root-Directory-of-OPENSSL" instead of the command below on Mac OS.
cmake .. -DENABLE_TESTS=ON
# Add the path to the LD_LIBRARY_PATH environment variable on Mac OS; Ignore it on Linux
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib/
make
make test
sudo make install
```

More platforms such as Windows would be supported soon.


# To start using crypto-tss-rsa-cpp

## CMake

CMake is your best option. It supports building on Linux, MacOS and Windows (soon) but also has a good chance of working on other platforms (no promises!). cmake has good support for crosscompiling and can be used for targeting the Android platform.

To build crypto-tss-rsa-cpp from source, follow the BUILDING guide.

The canonical way to discover dependencies in CMake is the find_package command.

```shell
project(XXXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(SafeheronCryptoSuites REQUIRED)
find_package(CryptoTSSRSA REQUIRED)

add_executable(${PROJECT_NAME} XXXX.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC
        ${SafeheronCryptoSuites_INCLUDE_DIRS}
        ${CryptoTSSRSA_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
        )

target_link_libraries(${PROJECT_NAME} PUBLIC
        SafeheronCryptoSuites
        CryptoTSSRSA
        OpenSSL::Crypto
        ${PROTOBUF_LINK_LIBRARIES}
        pthread )
```

# Usage

It's an example where the key length is 1024, the number of parties is 3 and threshold is 2.
```c++
#include "crypto-bn/bn.h"
#include "exception/safeheron_exceptions.h"
#include "crypto-tss-rsa/tss_rsa.h"
#include "crypto-encode/hex.h"

using safeheron::bignum::BN;
using safeheron::tss_rsa::RSAPrivateKeyShare;
using safeheron::tss_rsa::RSAPublicKey;
using safeheron::tss_rsa::RSAKeyMeta;
using safeheron::tss_rsa::RSASigShare;
using safeheron::tss_rsa::KeyGenParam;
using safeheron::exception::LocatedException;
using safeheron::exception::OpensslException;
using safeheron::exception::BadAllocException;
using safeheron::exception::RandomSourceException;

int main(int argc, char **argv) {
    std::string json_str;
    std::string doc("12345678123456781234567812345678");

    // Key Generation
    int key_bits_length = 1024;
    int k = 2;
    int l = 3;
    std::vector<RSAPrivateKeyShare> priv_arr;
    RSAPublicKey pub;
    RSAKeyMeta key_meta;
    bool status = safeheron::tss_rsa::GenerateKey(key_bits_length, l, k, priv_arr, pub, key_meta);
    key_meta.ToJsonString(json_str);
    std::cout << "key meta data: " << json_str << std::endl;

    pub.ToJsonString(json_str);
    std::cout << "public key: " << json_str << std::endl;

    priv_arr[0].ToJsonString(json_str);
    std::cout << "private key share 1: " << json_str << std::endl;
    priv_arr[2].ToJsonString(json_str);
    std::cout << "private key share 3: "  << json_str << std::endl;

    // Prepare
    std::string doc_pss = safeheron::tss_rsa::EncodeEMSA_PSS(doc, key_bits_length, safeheron::tss_rsa::SaltLength::AutoLength);
    std::cout << "doc_pss: " << safeheron::encode::hex::EncodeToHex(doc) << std::endl;
    // Party 1 sign.
    RSASigShare sig_share0 = priv_arr[0].Sign(doc_pss, key_meta, pub);
    sig_share0.ToJsonString(json_str);
    std::cout << "signature share 1: " << json_str << std::endl;
    // Party 3 sign.
    RSASigShare sig_share2 = priv_arr[2].Sign(doc_pss, key_meta, pub);
    sig_share2.ToJsonString(json_str);
    std::cout << "signature share 3: " <<  json_str << std::endl;

    // Combine signatures
    // Distributed signature
    std::vector<RSASigShare> sig_share_arr;
    for(int i = 0; i < l; i++) {
        sig_share_arr.emplace_back(priv_arr[i].Sign(doc_pss, key_meta, pub));
    }
    BN sig;
    bool ok = safeheron::tss_rsa::CombineSignatures(doc_pss, sig_share_arr, pub, key_meta, sig);
    std::cout << "succeed to sign: " << ok <<std::endl;
    std::cout << "signature: " << sig.Inspect() <<std::endl;

    // Verify the final signature.
    std::cout << "Verify Pss: " << safeheron::tss_rsa::VerifyEMSA_PSS(doc, key_bits_length, safeheron::tss_rsa::SaltLength::AutoLength, doc_pss) << std::endl;
    std::cout << "Verify Sig: " << pub.VerifySignature(doc_pss, sig) << std::endl;
    return 0;
}
```

Here is the CMakeList.txt:

```shell
project(example)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # depend on pkg-config, this looks for opencv.pc file

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(SafeheronCryptoSuites REQUIRED)
find_package(CryptoTSSRSA REQUIRED)

add_executable(${PROJECT_NAME} example.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC
        ${SafeheronCryptoSuites_INCLUDE_DIRS}
        ${CryptoTSSRSA_INCLUDE_DIRS}
        /usr/local/include  # This directory is included default on linux but not on Mac os
        )

# This directory is included default on linux but not on Mac os
target_link_directories(${PROJECT_NAME} PUBLIC /usr/local/lib)

target_link_libraries(${PROJECT_NAME} PUBLIC
        SafeheronCryptoSuites
        CryptoTSSRSA
        pthread )
```

Compile and run:
```shell
key meta data: {
 "k": 2,
 "l": 3,
 "vkv": "8ED8215F7D39F2E99CB3496BA2CB0067A0F1AA56F127E4BC082C51C1836A2CC530A6CDA9F901B1B0016B80198587D75C3D4450FDE024DED2E32890F9C49851F8639142BE728FE80F1E79104191127F272A02EB3DFB09404C7BFDBA5091C1A5060279751CE05A8E63DCA9CA58D7CF7D26C30A9006FC39F02E6F2FDA9723D173B8",
 "vku": "1B4DB8D5D24998ED478FC8176928792AF6E745D12335F8C8A5C370ACA878D56CE0A3DD795A94F45A981B687402702E576D6FADBA9A3F2D36B200E03B2B104BABFA7CA4A61FCA58F433A3A6EFF2C6008E9C162F0CA3F9ADBA7FBFB3EF3E8B51EDD142AA1A90CD372D4F1EC1066A964751D73CD4B5A9927FB91BC8B5BCAA4F3706",
 "vkiArr": [
  "61F68722827C825BCB85A0F11073E1D6A7B134C7603CF05EEE860FE201E3283C8691E3CF5BFA49947F812D2B11C47CB30013852DB627AD1AF826BC6EC80CADBC423B90785ACE04EAD9B88E1FDBD2C81F8D719ABE1811FC72752BD9D75AA5B10EF3AF95E6F45A008BEC490BACCB4019163781BB11D75B77CB5D70856F2248A09A",
  "9A25D52AF4315DD1E4FAEFADDD9BEAF08CA527624F0F194E072F29FF59FF287FA47A01F756C7BC636037576444D9D6AAF100D4414C8A5501890F37D2B01ECC6C8445BA37790AC036735F08015D2BCE3514D2690974F38FB92E4DCC08503AFC0247ECF2BF4EE852EB38C8AC663BBD3D6D0E8E0E270EAAE18093A86AB2E98C88C1",
  "4EA9A346EF90CC3648FC29F6F8A3A1B20FB98993CE963888B261E8B3B9B232D8E07D29A2BFE0CD080FCFB2651EBC65B18736A8E322138BB66A6A3273EB121B326FF96D3AA9DF9ACF180C09E84A8F617D5C68423D6194B035790AD11B061A96AFE8625B1D627A937156DD4217305057E33065A0D6A7CBF03C8AA0F011C6FD8F31"
 ]
}

public key: {
 "n": "B2D23D376399C330099E0AA90C3F60629207A19DEE38F1EF539CE05F112AD913999A8BCC02C76E5A38715957D3821880B2DE8CEA04DACB954A8F0FADD15335F03F838B6E9D2F1F04C8E0417778C7F6FB2E826E86C4005314622E8EF5CD22C34CCFC39CE0E0ED3B5FE561876236B997826B808CAC74CEF85B6500F966A920BF21",
 "e": "010001"
}

private key share 1: {
 "i": 1,
 "si": "15DD717AE30E8AEF57E3219CA93461EC1440DEA96EA03E32CF175399CD9E500FE492F704D93A867243DCE961E690DB72D4579E919DBBC8FA5996E8E184490B93F281D5B61A560A67FF8E3148DC29B9AA31D3952C849B9360A8CF28FF03872C0DBC8C874E7D76E00024796330E8CC93816336244A031BD74BC2662AD34154F89D"
}

private key share 3: {
 "i": 3,
 "si": "01F5EA9194C0106CF2CE550E8D172801DC0FA222EDE0F837DB4466FD5D5E07E185760C7685D66DA1CEDA7017D26DAADC855BC84DF169FFBFED25DB58BAFBB917B597DC05C832982E654440918DCF4311658B5882538A7E1E0228CCC2B22D5253AF60DD396D36EA0049EABE764F978B4C089DA651B2A02D9B1017DEA7D90930F0"
}

doc_pss: 3132333435363738313233343536373831323334353637383132333435363738
signature share 1: {
 "index": 1,
 "sigShare": "88035FA7A0DDB3B069B03014D30B3F99AA0D54F8B6F6321A92EE44EC1EB13BF0E0B73A7C77D00963038146E0F5986FF7D066DC085682AA7E8B9F6A5D50ADA6DCCBF03BE7BBBA15C5C6550B2245C7CAAAD0497C9E1846CB741AEB72F71F5072C36956B33B3C2E220EE2DE20FA7B02A4F20D3968CBBC92F8E73CC994C64576C73D",
 "z": "6FF7D51C86AB18BA574313F11FE954838103696F3D2A31DAB201DCC3B14BEA6ED05653AEFDF74C9E9824B0ADE0DC2A469145E8B5BCC41256F640C461DE9EB4C94A2B2ED3936260CD2E2708E08AD839A73BFEB0B38BDE4BBA5B4F79E6CE3374326536BC551AEE3FA7D0AFC53DE2BBC6F08EB39FDD6DCDFA0CDDA06B9FED65314088619F11443D2430D0724DC78E5E88FEEE8C6D2E28BC323C1458A5B8B084CA391BE2CC8AC23FB9BE6F29E062E9C3852A8C0DB7EBB00FD055D730014099B0CA38",
 "c": "CCDC81B31872E41FF8DAFA3FF099151189EA177F68388BC2CFC1375A5B1753D3"
}

signature share 3: {
 "index": 3,
 "sigShare": "6CF8C5F0E85B1AEAE500497AF286063BBFE6D205C5EF4EB707A65DB33BCDE08A1256C9BF7F312CABC19302937CE964E6826BE2286A9F603096C00313ABFCDD299FC018DF888C84749CEC40B0F4BE377076838BFDCE30A74FB52A3469C0D23A93B195E8136DBCA870376F1F0F6FC6EFA832F0795B699CAC73CF57536E1132F420",
 "z": "F1C1771809F9ED2AC1C83EB0BF4B3A9D1CC074614973EC16BC2A16A9DB022DF3361C34C4E2ACF1006298291577A44C850B7DEAD01911237593027F85655E56211F6CF9A156624809A27674CCD4640E82F83A06CE95340A19C1C376CA47B45350DC9CC0980F626F16B77E3C927D3BDB0DCA0EA0AAA31A279FFCBA58B78871F758B098BCF913F2D5BF1C7867043A30E1D6F7ADC3663E2F90C483CD6827F255B153AEC41337918E59DF696F49C78522AB13FA59F2CE17FC23090F3FC91633DE6B09",
 "c": "A60DC74DD10358DBE478EB6AB9B0B6FCD00ABDE4271C1A4F4BB415934C84A242"
}

succeed to sign: 1
signature: 88E8287CECF9BB25F9B62CE997B0AB5BD21791EAA6DD3F1FAD64AEDF366C80D1A3081D83E2873354BDB3339A9099D143C59BFD60BBAE792D4EA3B5F8C29ADFCA575BB2ADAF411EA76E77018E7EA56B95D165CA896376A46A88B076DBF9AE813B08C2A2690C820DC06EF0D25513BB13608EACBCCD85AC5C9F1F0EAD636362E4C1
Verify Pss: 1
Verify Sig: 1
```

# Benchmark
You need to install a benchmark framework call "Benchmark" to run benchmark .
Refer to https://benchmark.docsforge.com/master/getting-started/#installation to install "Benchmark".

Compile and run benchmark:

```c++
cd crypto-tss-rsa-cpp
mkdir build && cd build
cmake .. -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@1.1 -DENABLE_TESTS=ON -DENABLE_BENCHMARK=ON
make        
./test/tss-rsa-benchmark-test
```

# Performance Comparison between tss-rsa-cpp and tcrsa
Both tss-rsa-cpp and tcrsa are implementations of Victor Shoup's paper (Practical Threshold Signatures) . This paper introduces an efficient threshold signature scheme. The following is an efficiency analysis of these two implementations, which use C++ and go respectively.
Runtime Environment：os: linux; arch: amd64; cpu: 2 X 2499.99MHz
Parameters Initialization: n(RSA-module bits) = 4096, L(participants counter) = 5, K(threshold) = 3
The threshold signature scheme can be divided into the following four steps, which are, in order, secret key shares generation, signature shares generation, merging the signature shares into a complete signature and finally verifying the correctness of the signature. The following is the benchmark results of the above four processes for tss-rsa-cpp and tcrsa.

Table1 tss-rsa-cpp benchmark

| --- |Key Shares Gen	|Sig Shares Gen	|Sig Shares Combine |Sig Verification |	Total time |
| --- | --- | --- | --- | --- | --- |
|Runtime/it	|35.3s|	0.25s |	0.0033s	| 0.0001s |	35.55s |
|iterations |10	  | 100	| 100	| 100 |	- |
|Total time |353s |	25s	| 0.33s	| 0.01s |	- |

Table2 tcrsa benchmark

| --- |Key Shares Gen	|Sig Shares Gen	|Sig Shares Combine |Sig Verification |	Total time |
| --- | --- | --- | --- | --- | --- |
| Runtime/it	|1673.92s	|0.87s	|0.0017s	|0.0002s	|1674.79s |
| iterations	|10	|100	|100	|100	| - |
| Total time	|16739.2s	|87s	|0.17s	|0.02s | - |

Comparing the above two tables, it can be seen that when runtime environment and parameter values are the same, the efficiency of the tss-rsa-cpp and tcrsa libraries is mainly reflected by the process of generating secret key shares. For tss-rsa-cpp, it only takes 35.3s to perform one round of secret key shares generation, while tcrsa needs 1673.92s, which is about 47.4 times that of the former. Further, the signature shares generation of tss-rsa-cpp is also about 2.5 times faster than that of tcrsa. Eventually, it takes a total of 35.55s for tss-rsa-cpp to perform a complete signature generation and verification, and 1674.79s for tcrsa to complete the same process. We can see that the time tcrsa required is about 47 times as long as tss-rsa-cpp required.

Table1.3 tss-rsa, tcrsa Running time Comparison

| --- |Key Shares Gen	|Sig Shares Gen	|Sig Shares Combine |Sig Verification |	Total time |
| --- | --- | --- | --- | --- | --- |
|tss-rsa	|35.3s	|0.25s	|0.0033s	|0.0001s	|35.55s |
|tcrsa	|1673.92s	|0.87s	|0.0017s	|0.0002s	|1674.79s |

# Reference

##### [1] [Practical Threshold Signatures](https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf)
##### [2] [Description of TSS-RSA Signature Algorithm](./doc/Description_of_TSS_RSA_Signature_Algorithm.md)

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.
