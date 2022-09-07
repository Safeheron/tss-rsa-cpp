#ifndef SAFEHERON_RSA_PRIVATE_KEY_SHARE_H
#define SAFEHERON_RSA_PRIVATE_KEY_SHARE_H

#include <vector>
#include "crypto-bn/bn.h"
#include "RSAKeyMeta.h"
#include "RSAPrivateKeyShare.h"
#include "RSAPublicKey.h"
#include "RSASigShare.h"
#include "proto_gen/tss_rsa.pb.switch.h"

namespace safeheron {
namespace tss_rsa{

class RSAPrivateKeyShare{
public:
    /**
     * Constructor.
     * @param[in] i index of party
     * @param[in] si secret share of party i
     */
    RSAPrivateKeyShare(int i, const safeheron::bignum::BN &si);

public:
    const bignum::BN &si() const;
    void set_si(const bignum::BN &si);

    int i() const;
    void set_i(int i);

    /**
     * Sign the message and create the signature share.
     * @param[in] doc message to sign.
     * @param[in] key_meta meta data of key
     * @param[in] public_key public key
     * @return a RSASigShare object.
     */
    RSASigShare Sign(const std::string &doc,
                     const safeheron::tss_rsa::RSAKeyMeta &key_meta,
                     const safeheron::tss_rsa::RSAPublicKey &public_key);

    /**
     * Convert this object into a protobuf object.
     * @param[out] proof
     * @return true on success, false on error.
     */
    bool ToProtoObject(safeheron::proto::RSAPrivateKeyShare &proof) const;

    /**
     * Convert a protobuf object into this object.
     * @param[in] proof
     * @return true on success, false on error.
     */
    bool FromProtoObject(const safeheron::proto::RSAPrivateKeyShare &proof);

    /**
     * Convert this object into a base64 string.
     * @param[out] base64
     * @return true on success, false on error.
     */
    bool ToBase64(std::string& base64) const;

    /**
     * Convert a base64 string into this object.
     * @param[in] base64
     * @return true on success, false on error.
     */
    bool FromBase64(const std::string& base64);

    /**
     * Convert this object into a json string.
     * @param[out] json_str
     * @return true on success, false on error.
     */
    bool ToJsonString(std::string &json_str) const;

    /**
     * Convert a json string into this object.
     * @param[in] json_str
     * @return true on success, false on error.
     */
    bool FromJsonString(const std::string &json_str);

private:
    /**
     * Sign the message and create the signature share.
     * @param x a BN object which indicate the message to sign.
     * @param key_meta meta data of key
     * @param public_key public key
     * @return a RSASigShare object.
     */
    RSASigShare InternalSign(const safeheron::bignum::BN &x,
                             const safeheron::tss_rsa::RSAKeyMeta &key_meta,
                             const safeheron::tss_rsa::RSAPublicKey &public_key);

private:
    int i_;   /**< index of party. */
    safeheron::bignum::BN si_;  /**< secret share of party i. */
};

};
};

#endif //SAFEHERON_RSA_PRIVATE_KEY_SHARE_H