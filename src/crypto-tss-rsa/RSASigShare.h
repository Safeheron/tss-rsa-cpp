#ifndef SAFEHERON_RSA_KEY_SHARE_H
#define SAFEHERON_RSA_KEY_SHARE_H

#include <vector>
#include "crypto-bn/bn.h"
#include "tss_rsa.pb.h"

namespace safeheron {
namespace tss_rsa{

class RSASigShare{
public:
    /**
     * Constructor.
     */
    RSASigShare();

    /**
     * Constructor.
     * @param[in] index index of party
     * @param[in] sig_share signature share
     * @param[in] z a parameter of the proof
     * @param[in] c a parameter of the proof
     */
    RSASigShare(int index,
                const safeheron::bignum::BN &sig_share,
                const safeheron::bignum::BN &z,
                const safeheron::bignum::BN &c);

    int index() const;
    void set_index(int index);

    const bignum::BN &sig_share() const;
    void set_sig_share(const bignum::BN &sig_share);

    const bignum::BN &z() const;
    void set_z(const bignum::BN &z);

    const bignum::BN &c() const;
    void set_c(const bignum::BN &c);

    /**
     * Convert this object into a protobuf object.
     * @param[out] proof
     * @return true on success, false on error.
     */
    bool ToProtoObject(safeheron::proto::RSASigShare &proof) const;

    /**
     * Convert a protobuf object into this object.
     * @param[in] proof
     * @return true on success, false on error.
     */
    bool FromProtoObject(const safeheron::proto::RSASigShare &proof);

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
    int index_;  /**< index of party */
    safeheron::bignum::BN sig_share_;  /**< signature share */
    safeheron::bignum::BN z_;  /**< a parameter of the proof */
    safeheron::bignum::BN c_;  /**< a parameter of the proof */
};

};
};

#endif //SAFEHERON_RSA_KEY_SHARE_H