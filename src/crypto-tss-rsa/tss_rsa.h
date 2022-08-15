#ifndef SAFEHERON_TSS_RSA_H
#define SAFEHERON_TSS_RSA_H

#include "RSAPrivateKeyShare.h"
#include "RSAPublicKey.h"
#include "RSASigShare.h"
#include "RSAKeyMeta.h"
#include "KeyGenParam.h"
#include "emsa_pss.h"
#include <vector>

namespace safeheron {
namespace tss_rsa {

/**
 * Generate private key shares, public key, key meta data.
 *
 * @param[in] key_bits_length: 2048, 3072, 4096 is advised.
 * @param[in] l: total number of private key shares.
 * @param[in] k: threshold, k < l and k >= (l/2+1)
 * @param[out] private_key_share_arr: shares of private key.
 * @param[out] public_key: public key.
 * @param[out] key_meta: key meta data.
 * @return true on success, false on error.
 */
bool GenerateKey(size_t key_bits_length, int l, int k,
                 std::vector<RSAPrivateKeyShare> &private_key_share_arr,
                 RSAPublicKey &public_key,
                 RSAKeyMeta &key_meta);

/**
 * Generate private key shares, public key, key meta data with specified parameters.
 *
 * @param[in] key_bits_length: 2048, 3072, 4096 is advised.
 * @param[in] l: total number of private key shares.
 * @param[in] k: threshold, k < l and k >= (l/2+1)
 * @param[in] param: specified parameters.
 * @param[out] private_key_share_arr: shares of private key.
 * @param[out] public_key: public key.
 * @param[out] key_meta: key meta data.
 * @return true on success, false on error.
 */
bool GenerateKeyEx(size_t key_bits_length, int l, int k,
                   const KeyGenParam &param,
                   std::vector<RSAPrivateKeyShare> &private_key_share_arr,
                   RSAPublicKey &public_key,
                   RSAKeyMeta &key_meta);

/**
 * Combine all the shares of signature to make a real signature.
 * @param[in] doc: doc
 * @param[in] sig_arr : the shares of signature.
 * @param[in] public_key: public key.
 * @param[in] key_meta: key meta data.
 * @param[out] out_sig: a real signature.
 * @return true on success, false on error.
 */
bool CombineSignatures(const std::string &doc,
                       const std::vector<RSASigShare> &sig_arr,
                       const RSAPublicKey &public_key,
                       const RSAKeyMeta &key_meta,
                       safeheron::bignum::BN &out_sig);


/**
 * Combine all the shares of signature without validation on signature shares to make a real signature.
 * @note The function "CombineSignaturesWithoutValidation" is very fast. It's about 50 times faster than "CombineSignatures".
 * @param[in] doc: doc
 * @param[in] sig_arr : the shares of signature.
 * @param[in] public_key: public key.
 * @param[in] key_meta: key meta data.
 * @param[out] out_sig: a real signature.
 * @return true on success, false on error.
 */
bool CombineSignaturesWithoutValidation(const std::string &doc,
                                        const std::vector<RSASigShare> &sig_arr,
                                        const RSAPublicKey &public_key,
                                        const RSAKeyMeta &key_meta,
                                        safeheron::bignum::BN &out_sig);


};
};


#endif //SAFEHERON_TSS_RSA_H