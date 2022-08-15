#include "gtest/gtest.h"
#include "crypto-bn/bn.h"
#include "crypto-bn/rand.h"
#include "exception/safeheron_exceptions.h"
#include "crypto-tss-rsa/tss_rsa.h"

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

TEST(TSS_RSA, KeyGen2_3_Sign_3_3) {
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
    EXPECT_TRUE(status);
    key_meta.ToJsonString(json_str);
    std::cout << "key meta data: " << json_str << std::endl;

    pub.ToJsonString(json_str);
    std::cout << "public key: " << json_str << std::endl;

    priv_arr[0].ToJsonString(json_str);
    std::cout << "private key share 1: " << json_str << std::endl;
    priv_arr[1].ToJsonString(json_str);
    std::cout << "private key share 2: "  << json_str << std::endl;
    priv_arr[2].ToJsonString(json_str);
    std::cout << "private key share 3: "  << json_str << std::endl;

    // Party 1 sign.
    RSASigShare sig_share0 = priv_arr[0].Sign(doc, key_meta, pub);
    sig_share0.ToJsonString(json_str);
    std::cout << "signature share 1: " << json_str << std::endl;
    // Party 2 sign.
    RSASigShare sig_share1 = priv_arr[1].Sign(doc, key_meta, pub);
    sig_share1.ToJsonString(json_str);
    std::cout << "signature share 2: " <<  json_str << std::endl;
    // Party 3 sign.
    RSASigShare sig_share2 = priv_arr[2].Sign(doc, key_meta, pub);
    sig_share2.ToJsonString(json_str);
    std::cout << "signature share 3: " <<  json_str << std::endl;

    // Combine signatures
    // Distributed signature
    std::vector<RSASigShare> sig_share_arr;
    sig_share_arr.push_back(sig_share0);
    sig_share_arr.push_back(sig_share1);
    sig_share_arr.push_back(sig_share2);
    BN sig;
    status = safeheron::tss_rsa::CombineSignaturesWithoutValidation(doc, sig_share_arr, pub, key_meta, sig);
    EXPECT_TRUE(status);
    std::cout << "final signature = 0x" << sig.Inspect() << std::endl;

    // Verify the final signature.
    EXPECT_TRUE(pub.VerifySignature(doc, sig));
}


TEST(TSS_RSA, KeyGenEx2_3_Sign_3_3) {
    std::string json_str;
    std::string doc("12345678123456781234567812345678");

    KeyGenParam param(0,
                      BN("E4AAECAA632881A60D11813CC8379980C673BEFB959F44AA14BB15F141ADBE9E6B25FA3A8715435427B10AA608946D0A7B68A4F75BDC376E12010F813F480007", 16),
                      BN("C32F913ECDF403DB94B07A8D02AF2934A882226F3535E6436A6A2392A2C390E525D4531D6EFF2028AE8E16F856E0945348E007EDAC43B4CE9BE5E68D76E93E63", 16),
                      BN("77268D1F347AB0EE48741FBFFD3A052154B8FC614C0FD357F5D0E7B4119D24A4EC47FFFE68DD9BB097D2D7848B08070AEEB25C99EDAA95387F71D8589209973E538D4BC9E693963E485097EB0B8AE8ACD84A13385EC1DBEB070ABAB02E322C247DE70944B17CF3109CBF3DABAB9C66C579706C00CF719314F83A48224FF16DC9", 16),
                        BN("1E7989EBD93507193CE394263F7C32F434E67F1750A367EC725495899BEF99EBC8FCF41148B82D66BB03BAAA25625DD12B29BAA3B43807C15988278E4BD0E64BBCC133B5583431A48BB58BA188CFBDEA1B6170EDAA4D0B1E0AA0D4CCACDB3A66A7DE6A6AC31CB14B802F45AEB4FDBD9B3D621B9BE88050749A093A382EF914C1", 16));

    // Key Generation
    int key_bits_length = 1024;
    int k = 2;
    int l = 3;
    std::vector<RSAPrivateKeyShare> priv_arr;
    RSAPublicKey pub;
    RSAKeyMeta key_meta;
    bool status = safeheron::tss_rsa::GenerateKeyEx(key_bits_length, l, k, param, priv_arr, pub, key_meta);
    EXPECT_TRUE(status);
    key_meta.ToJsonString(json_str);
    std::cout << "key meta data: " << json_str << std::endl;

    pub.ToJsonString(json_str);
    std::cout << "public key: " << json_str << std::endl;

    priv_arr[0].ToJsonString(json_str);
    std::cout << "private key share 1: " << json_str << std::endl;
    priv_arr[1].ToJsonString(json_str);
    std::cout << "private key share 2: " << json_str << std::endl;
    priv_arr[2].ToJsonString(json_str);
    std::cout << "private key share 3: " << json_str << std::endl;

    // Party 1 sign.
    RSASigShare sig_share0 = priv_arr[0].Sign(doc, key_meta, pub);
    sig_share0.ToJsonString(json_str);
    std::cout << "signature share 1: " << json_str << std::endl;
    // Party 2 sign.
    RSASigShare sig_share1 = priv_arr[1].Sign(doc, key_meta, pub);
    sig_share1.ToJsonString(json_str);
    std::cout << "signature share 2: " << json_str << std::endl;
    // Party 3 sign.
    RSASigShare sig_share2 = priv_arr[2].Sign(doc, key_meta, pub);
    sig_share2.ToJsonString(json_str);
    std::cout << "signature share 3: " << json_str << std::endl;

    // Combine signatures
    // Distributed signature
    std::vector<RSASigShare> sig_share_arr;
    sig_share_arr.push_back(sig_share0);
    sig_share_arr.push_back(sig_share1);
    sig_share_arr.push_back(sig_share2);
    BN sig;
    status = safeheron::tss_rsa::CombineSignatures(doc ,sig_share_arr, pub, key_meta, sig);
    EXPECT_TRUE(status);
    std::cout << "final signature = 0x" << sig.Inspect() << std::endl;

    // Verify the final signature.
    EXPECT_TRUE(pub.VerifySignature(doc, sig));
}

TEST(TSS_RSA, KeyGenEx2_3_Sign_2_3) {
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
    EXPECT_TRUE(status);
    key_meta.ToJsonString(json_str);
    std::cout << "key meta data: " << json_str << std::endl;

    pub.ToJsonString(json_str);
    std::cout << "public key: " << json_str << std::endl;

    priv_arr[0].ToJsonString(json_str);
    std::cout << "private key share 1: " << json_str << std::endl;
    priv_arr[2].ToJsonString(json_str);
    std::cout << "private key share 3: "  << json_str << std::endl;

    // Party 1 sign.
    RSASigShare sig_share0 = priv_arr[0].Sign(doc, key_meta, pub);
    sig_share0.ToJsonString(json_str);
    std::cout << "signature share 1: " << json_str << std::endl;
    // Party 3 sign.
    RSASigShare sig_share2 = priv_arr[2].Sign(doc, key_meta, pub);
    sig_share2.ToJsonString(json_str);
    std::cout << "signature share 3: " <<  json_str << std::endl;

    // Combine signatures
    // Distributed signature
    std::vector<RSASigShare> sig_share_arr;
    sig_share_arr.push_back(sig_share0);
    sig_share_arr.push_back(sig_share2);
    BN sig;
    status = safeheron::tss_rsa::CombineSignatures(doc, sig_share_arr, pub, key_meta, sig);
    EXPECT_TRUE(status);
    std::cout << "final signature = 0x" << sig.Inspect() << std::endl;

    // Verify the final signature.
    EXPECT_TRUE(pub.VerifySignature(doc, sig));
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
