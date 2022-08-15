#ifndef SAFEHERON_TSS_RSA_KEY_GEN_PARAM_SHARE_H
#define SAFEHERON_TSS_RSA_KEY_GEN_PARAM_SHARE_H

#include <vector>
#include "crypto-bn/bn.h"

namespace safeheron {
namespace tss_rsa{

class KeyGenParam{
public:
    KeyGenParam();
    /**
     * Constructor
     * @param[in] e : 65537 default.
     * @param[in] p : safe prime.
     * @param[in] q : safe prime.
     * @param[in] f : f \in Z_n^*, then f^2 \in Q_n
     * @param[in] vku: vku \in Z_n^*, Jacobi(vku, n) = -1, where n = pq
     */
    KeyGenParam(int e,
                const safeheron::bignum::BN &p,
                const safeheron::bignum::BN &q,
                const safeheron::bignum::BN &f,
                const safeheron::bignum::BN &vku);

public:
    int e() const;

    void set_e(int e);

    const bignum::BN &p() const;

    void set_p(const bignum::BN &p);

    const bignum::BN &q() const;

    void set_q(const bignum::BN &q);

    const bignum::BN &f() const;

    void set_f(const bignum::BN &f);

    const bignum::BN &vku() const;

    void set_vku(const bignum::BN &vku);

private:
    int e_;  /**< 65537 default */
    safeheron::bignum::BN p_;  /**< safe prime. */
    safeheron::bignum::BN q_;  /**< safe prime. */
    safeheron::bignum::BN f_;  /**< f \in Z_n^*, then f^2 \in Q_n */
    safeheron::bignum::BN vku_;  /**< vku \in Z_n^*, Jacobi(vku, n) = -1, where n = pq */
};

};
};

#endif //SAFEHERON_TSS_RSA_KEY_GEN_PARAM_SHARE_H