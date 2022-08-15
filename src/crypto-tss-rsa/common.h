#ifndef SAFEHERON_TSS_RSA_COMMON_H
#define SAFEHERON_TSS_RSA_COMMON_H

#include <vector>
#include "crypto-bn/bn.h"

namespace safeheron {
namespace tss_rsa{

/**
 * Calculate $$\lambda_{i,j}^{S}$$
 *
 * $$
 *      \lambda_{i,j}^{S} =
 *          \Delta
 *          \frac
 *              { {\textstyle \prod_{j' \in S \setminus \{j\}}^{}(i-j')} }
 *              { {\textstyle \prod_{j' \in S \setminus \{j\}}^{}(j-j')} }
 * $$
 * @param[in] i
 * @param[in] j
 * @param[in] S
 * @param[in] delta delta=l!
 * @return  $\lambda_{i,j}$
 */
static inline safeheron::bignum::BN lambda(const safeheron::bignum::BN &i,
                                           const safeheron::bignum::BN &j,
                                           const std::vector<safeheron::bignum::BN> &S,
                                           const safeheron::bignum::BN &delta){
    safeheron::bignum::BN num(1);
    safeheron::bignum::BN den(1);
    for(const auto &item : S){
        if(j != item){
            num *= (i - item);
            den *= (j - item);
        }
    }
    return delta * num / den;
}

};
};

#endif //SAFEHERON_TSS_RSA_COMMON_H