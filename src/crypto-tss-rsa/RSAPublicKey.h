#ifndef SAFEHERON_RSA_PUBLIC_KEY_H
#define SAFEHERON_RSA_PUBLIC_KEY_H

#include "crypto-bn/bn.h"
#include "tss_rsa.pb.h"


namespace safeheron {
namespace tss_rsa{


class RSAPublicKey{
public:
    /**
     * Constructor.
     */
    RSAPublicKey(){}

    /**
     * Constructor.
     * @param[in] n n=pq
     * @param[in] e a prime
     */
    RSAPublicKey(const safeheron::bignum::BN &n, const safeheron::bignum::BN &e);

    /**
     * Verify the signature.
     * @param[in] doc
     * @param[in] sig
     * @return true on success, false on error.
     */
    bool VerifySignature(const std::string &doc, const safeheron::bignum::BN &sig);

    const bignum::BN &n() const;
    void set_n(const bignum::BN &n);

    const bignum::BN &e() const;
    void set_e(const bignum::BN &e);

    /**
     * Convert this object into a protobuf object.
     * @param[out] proof
     * @return true on success, false on error.
     */
    bool ToProtoObject(safeheron::proto::RSAPublicKey &proof) const;

    /**
     * Convert a protobuf object into this object.
     * @param[in] proof
     * @return true on success, false on error.
     */
    bool FromProtoObject(const safeheron::proto::RSAPublicKey &proof);

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
     * Verify the signature.
     * @param[in] x
     * @param[in] sig
     * @return true on success, false on error.
     */
    bool InternalVerifySignature(const safeheron::bignum::BN &x, const safeheron::bignum::BN &sig);
private:
    safeheron::bignum::BN n_;
    safeheron::bignum::BN e_;
};


};
};

#endif //SAFEHERON_RSA_PUBLIC_KEY_H