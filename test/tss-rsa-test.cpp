#include "gtest/gtest.h"
#include "crypto-bn/bn.h"
#include "crypto-bn/rand.h"
#include "exception/safeheron_exceptions.h"
#include "../src/crypto-tss-rsa/tss_rsa.h"
#include "../src/crypto-tss-rsa/emsa_pss.h"
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

TEST(TSS_RSA, PSS) {
    std::string doc = "hello world";
    KeyGenParam param(0,
                      BN("E4AAECAA632881A60D11813CC8379980C673BEFB959F44AA14BB15F141ADBE9E6B25FA3A8715435427B10AA608946D0A7B68A4F75BDC376E12010F813F480007", 16),
                      BN("C32F913ECDF403DB94B07A8D02AF2934A882226F3535E6436A6A2392A2C390E525D4531D6EFF2028AE8E16F856E0945348E007EDAC43B4CE9BE5E68D76E93E63", 16),
                      BN("77268D1F347AB0EE48741FBFFD3A052154B8FC614C0FD357F5D0E7B4119D24A4EC47FFFE68DD9BB097D2D7848B08070AEEB25C99EDAA95387F71D8589209973E538D4BC9E693963E485097EB0B8AE8ACD84A13385EC1DBEB070ABAB02E322C247DE70944B17CF3109CBF3DABAB9C66C579706C00CF719314F83A48224FF16DC9", 16),
                      BN("1E7989EBD93507193CE394263F7C32F434E67F1750A367EC725495899BEF99EBC8FCF41148B82D66BB03BAAA25625DD12B29BAA3B43807C15988278E4BD0E64BBCC133B5583431A48BB58BA188CFBDEA1B6170EDAA4D0B1E0AA0D4CCACDB3A66A7DE6A6AC31CB14B802F45AEB4FDBD9B3D621B9BE88050749A093A382EF914C1", 16));

    // Key Generation
    int key_bits_length = 1024;
    int k = 2;
    int l = 3;

    RSAKeyMeta key_meta;
    RSAPublicKey pub;
    std::vector<RSAPrivateKeyShare> priv_arr;
    std::vector<RSASigShare> sig_arr;
    BN sig;
    safeheron::tss_rsa::GenerateKeyEx(key_bits_length, l, k, param, priv_arr, pub, key_meta);
    std::cout << "pub.n: " << pub.n().Inspect() << std::endl;
    std::cout << "pub.e: " << pub.e().Inspect() << std::endl;

    // Prepare EMSA_PSS
    std::string doc_pss = safeheron::tss_rsa::EncodeEMSA_PSS(doc, key_bits_length,
                                                         safeheron::tss_rsa::SaltLength::AutoLength);
    std::cout << "doc_pss: " << safeheron::encode::hex::EncodeToHex(doc_pss) << std::endl;

    // Sign
    for(int i = 0; i < l; i++) {
        sig_arr.emplace_back(priv_arr[i].Sign(doc_pss, key_meta, pub));
    }

    // Combine
    safeheron::tss_rsa::CombineSignatures(doc_pss, sig_arr, pub, key_meta, sig);

    // Verify EMSA_PSS
    EXPECT_TRUE(safeheron::tss_rsa::VerifyEMSA_PSS(doc, key_bits_length, safeheron::tss_rsa::SaltLength::AutoLength, doc_pss));
    std::cout << "signature: " << sig.Inspect() <<std::endl;
    // Verify Signature
    EXPECT_TRUE(pub.VerifySignature(doc_pss, sig));
}

TEST(TSS_RSA_4096, PSS) {
    std::string doc = "hello world";

    // Key Generation
    int key_bits_length = 4096;
    int k = 2;
    int l = 3;

    RSAKeyMeta key_meta;
    RSAPublicKey pub;
    std::vector<RSAPrivateKeyShare> priv_arr;
    std::vector<RSASigShare> sig_arr;
    BN sig;
    safeheron::tss_rsa::GenerateKey(key_bits_length, l, k, priv_arr, pub, key_meta);
    std::cout << "pub.n: " << pub.n().Inspect() << std::endl;
    std::cout << "pub.e: " << pub.e().Inspect() << std::endl;

    // Prepare EMSA_PSS
    std::string doc_pss = safeheron::tss_rsa::EncodeEMSA_PSS(doc, key_bits_length,
                                                             safeheron::tss_rsa::SaltLength::AutoLength);
    std::cout << "doc_pss: " << safeheron::encode::hex::EncodeToHex(doc_pss) << std::endl;

    // Sign
    for(int i = 0; i < l; i++) {
        sig_arr.emplace_back(priv_arr[i].Sign(doc_pss, key_meta, pub));
    }

    // Combine
    safeheron::tss_rsa::CombineSignatures(doc_pss, sig_arr, pub, key_meta, sig);

    // Verify EMSA_PSS
    EXPECT_TRUE(safeheron::tss_rsa::VerifyEMSA_PSS(doc, key_bits_length, safeheron::tss_rsa::SaltLength::AutoLength, doc_pss));
    std::cout << "signature: " << sig.Inspect() <<std::endl;
    // Verify Signature
    EXPECT_TRUE(pub.VerifySignature(doc_pss, sig));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
