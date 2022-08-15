#ifndef SAFEHERON_RSA_KEY_META_H
#define SAFEHERON_RSA_KEY_META_H

#include <vector>
#include "crypto-bn/bn.h"
#include "tss_rsa.pb.h"

namespace safeheron {
namespace tss_rsa{

class RSAKeyMeta{
public:
    /**
     * Constructor.
     */
    RSAKeyMeta(){}

    /**
     * Constructor.
     * @param[in] k threshold
     * @param[in] l number of parties
     * @param[in] vkv validation key
     * @param[in] vki_arr validation key array of all parties
     * @param[in] vku safe parameter for protocol 2
     */
    RSAKeyMeta(int k,
               int l,
               const safeheron::bignum::BN &vkv,
               const std::vector<safeheron::bignum::BN> &vki_arr,
               const safeheron::bignum::BN &vku);

    int k() const;
    void set_k(int k);

    int l() const;
    void set_l(int l);

    const bignum::BN &vkv() const;
    void set_vkv(const bignum::BN &vkv);

    const std::vector<safeheron::bignum::BN> &vki_arr() const;
    void set_vki_arr(const std::vector<safeheron::bignum::BN> &vki_arr);
    const bignum::BN &vki(size_t index) const;

    const bignum::BN &vku() const;
    void set_vku(const bignum::BN &vku);

    /**
     * Convert this object into a protobuf object.
     * @param[out] proof
     * @return true on success, false on error.
     */
    bool ToProtoObject(safeheron::proto::RSAKeyMeta &proof) const;

    /**
     * Convert a protobuf object into this object.
     * @param[in] proof
     * @return true on success, false on error.
     */
    bool FromProtoObject(const safeheron::proto::RSAKeyMeta &proof);

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
    int k_;  /**< threshold */
    int l_;  /**< number of parties */
    safeheron::bignum::BN vkv_;  /**< validation key */
    std::vector<safeheron::bignum::BN> vki_arr_;  /**< validation key array of all parties */
    safeheron::bignum::BN vku_;  /**< safe parameter for protocol 2 */

};

};
};

#endif //SAFEHERON_RSA_KEY_META_H