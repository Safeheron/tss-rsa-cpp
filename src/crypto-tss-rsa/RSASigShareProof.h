#ifndef SAFEHERON_RSA_SIGNATURE_SHARE_PROOF_H
#define SAFEHERON_RSA_SIGNATURE_SHARE_PROOF_H

#include "crypto-bn/bn.h"
#include "proto_gen/tss_rsa.pb.switch.h"


namespace safeheron {
namespace tss_rsa{

class RSASigShareProof{
public:
    /**
     * Constructor.
     */
    RSASigShareProof();

    /**
     * Constructor.
     * @param[in] z a parameter of the proof
     * @param[in] c a parameter of the proof
     */
    RSASigShareProof(const bignum::BN &z, const bignum::BN &c);

    const bignum::BN &z() const;

    void set_z(const bignum::BN &z);

    const bignum::BN &c() const;

    void set_c(const bignum::BN &c);

    /**
     * Create a proof of the signature share.
     * @param[in] si secret share of party i
     * @param[in] vkv validation key
     * @param[in] vki validation key of party i
     * @param[in] x x which represents the message
     * @param[in] n n = pq
     * @param[in] sig_i signature share of party i
     */
    void Prove(const safeheron::bignum::BN &si,
               const safeheron::bignum::BN &vkv,
               const safeheron::bignum::BN &vki,
               const safeheron::bignum::BN &x,
               const safeheron::bignum::BN &n,
               const safeheron::bignum::BN &sig_i);

    /**
     * Verify the proof of the signature share.
     * @param[in] vkv validation key
     * @param[in] vki validation key of party i
     * @param[in] x x which represents the message
     * @param[in] n n = pq
     * @param[in] sig_i signature share of party i
     * @return true on success, false on error.
     */
    bool Verify(const safeheron::bignum::BN &vkv,
                const safeheron::bignum::BN &vki,
                const safeheron::bignum::BN &x,
                const safeheron::bignum::BN &n,
                const safeheron::bignum::BN &sig_i);

    /**
     * Convert this object into a protobuf object.
     * @param[out] proof
     * @return true on success, false on error.
     */
    bool ToProtoObject(safeheron::proto::RSASigShareProof &proof) const;

    /**
     * Convert a protobuf object into this object.
     * @param[in] proof
     * @return true on success, false on error.
     */
    bool FromProtoObject(const safeheron::proto::RSASigShareProof &proof);

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
    safeheron::bignum::BN z_;
    safeheron::bignum::BN c_;
};


};
};

#endif //SAFEHERON_RSA_SIGNATURE_SHARE_PROOF_H