#include "tss_rsa.h"
#include "crypto-bn/rand.h"
#include "exception/located_exception.h"
#include "crypto-sss/vsss.h"
#include "crypto-hash/hash256.h"
#include "common.h"
#include "RSASigShareProof.h"

using safeheron::bignum::BN;
using safeheron::exception::LocatedException;
using safeheron::hash::CSHA256;

// Fermat fourth number
// Default e value.
const int f4 = 65537;

namespace safeheron {
namespace tss_rsa {

static bool InternalGenerateKey(size_t key_bits_length, int l, int k,
                                std::vector<RSAPrivateKeyShare> &private_key_share_arr,
                                RSAPublicKey &public_key,
                                RSAKeyMeta &key_meta,
                                KeyGenParam &param){
    const BN e(param.e());
    const BN &p = param.p();
    const BN &q = param.q();
    const BN &f = param.f();
    const BN &vku = param.vku();

    // n
    BN n = p * q;

    // m = p' * q'
    BN m = (p - 1) * (q - 1) / 4;

    // d:  de = 1 mod m
    BN d = e.InvM(m);

    // generate shares of d
    std::vector<sss::Point> share_arr;
    std::vector<BN> index_arr;
    for(int i = 1; i <= l; i++){
        index_arr.emplace_back(BN(i));
    }
    sss::vsss::MakeShares(share_arr, d, k, index_arr, m);
    BN secret;
    sss::vsss::RecoverSecret(secret, share_arr, m);
    // extra check: d == secret


    // Compute \Delta = l!
    BN delta(1);
    for(int i = 1; i <= l; i++){
        delta *= i;
    }
    BN delta_inv = delta.InvM(m);

    for(int i = 1; i <= l; i++){
        BN si = (share_arr[i-1].y * delta_inv) % m;
        private_key_share_arr.emplace_back(RSAPrivateKeyShare(i, si));
    }


    // Public key
    public_key.set_n(n);
    public_key.set_e(e);


    // Validate Key
    BN vkv = (f * f) % n;
    std::vector<BN> vki_arr;
    for(int i = 1; i <= l; i++){
        BN t_vki = vkv.PowM(private_key_share_arr[i-1].si(), n);
        vki_arr.push_back(t_vki);
    }

    // Key meta data
    key_meta.set_k(k);
    key_meta.set_l(l);
    key_meta.set_vkv(vkv);
    key_meta.set_vki_arr(vki_arr);
    key_meta.set_vku(vku);

    return true;
}


/**
 * Generate private key shares, public key, key meta data.
 *
 * @param[in] key_bits_length: 1024/2048/3072/4096.  4096 is advised.
 * @param[in] l: total number of private key shares.
 * @param[in] k: threshold, k < l and k >= (l/2+1)
 * @param[out] private_key_share_arr[out]: shares of private key.
 * @param[out] public_key[out]: public key.
 * @param[out] key_meta[out]: key meta data.
 * @return true on success, false on error.
 */
bool GenerateKey(size_t key_bits_length, int l, int k,
                 std::vector<RSAPrivateKeyShare> &private_key_share_arr,
                 RSAPublicKey &public_key,
                 RSAKeyMeta &key_meta){
    // check key_bits_length
    if( (key_bits_length != 1024) && (key_bits_length != 2048) && (key_bits_length != 3072) && (key_bits_length != 4096)){
        return false;
    }

    // check k, l
    if(l <= 1 || k <= 0 || k < (l/2+1) || k > l){
        return false;
    }

    // default value
    int e = f4;

    // p = 2p' + 1
    BN p = safeheron::rand::RandomSafePrime(key_bits_length / 2);

    // q = 2q' + 1, make sure: p != q
    BN q;
    do {
        q = safeheron::rand::RandomSafePrime(key_bits_length / 2 - 1);
    } while (p == q);

    // n = p * q
    BN n = p * q;
    BN f = safeheron::rand::RandomBNLtCoPrime(n);

    // vku
    BN vku;
    do{
        vku = safeheron::rand::RandomBNLtGcd(n);
    } while (safeheron::bignum::BN::JacobiSymbol(vku, n) != -1);

    KeyGenParam param(e, p, q, f, vku);
    return InternalGenerateKey(key_bits_length, l, k, private_key_share_arr, public_key, key_meta, param);
}


/**
 * Generate private key shares, public key, key meta data with specified parameters.
 *
 * @param[in] key_bits_length: 1024/2048/3072/4096.  4096 is advised.
 * @param[in] l: total number of private key shares.
 * @param[in] k: threshold, k < l and k >= (l/2+1)
 * @param[in] param: specified parameters.
 * @param[out] private_key_share_arr[out]: shares of private key.
 * @param[out] public_key[out]: public key.
 * @param[out] key_meta[out]: key meta data.
 * @return true on success, false on error.
 */
bool GenerateKeyEx(size_t key_bits_length, int l, int k,
                   const KeyGenParam &_param,
                   std::vector<RSAPrivateKeyShare> &private_key_share_arr,
                   RSAPublicKey &public_key,
                   RSAKeyMeta &key_meta){
    // check k, l
    if(l <= 1 || k <= 0 || k < (l/2+1) || k > l){
        return false;
    }

    // check e
    KeyGenParam param = _param;
    BN e(param.e());
    if(e == 0){
        param.set_e(f4);
    }else{
        if(!e.IsProbablyPrime()){
            return false;
        }
    }

    // check p: p = 2p' + 1
    if(param.p() == 0){
        BN p = safeheron::rand::RandomSafePrime(key_bits_length/ 2);
        param.set_p(p);
    }else{
        BN pp = (param.p() - 1)/2;
        if(!param.p().IsProbablyPrime() || !pp.IsProbablyPrime()){
            return false;
        }
    }

    // check q: q = 2q' + 1
    // make sure: q != p
    if(param.q() == 0){
        BN q;
        do {
            q = safeheron::rand::RandomSafePrime(key_bits_length / 2 - 1);
        }while (q == param.p());
        param.set_q(q);
    }else{
        BN qq = (param.q() - 1)/2;
        if(!param.q().IsProbablyPrime() || !qq.IsProbablyPrime()){
            return false;
        }
    }

    // n = pq
    BN n = param.p() * param.q();

    // check f: f < n , gcd(f, n) = 1
    if(param.f() == 0){
        BN f = safeheron::rand::RandomBNLtCoPrime(n);
        param.set_f(f);
    }else{
        const BN &f = param.f();
        if(f <= 0 || f >= n || f.Gcd(n) != 1){
            return false;
        }
    }

    // check vku: vku < n , gcd(vku, n) = 1, jacobi(vku, n) == -1
    if(param.vku() == 0){
        BN vku;
        do{
            vku = safeheron::rand::RandomBNLtGcd(n);
        } while (safeheron::bignum::BN::JacobiSymbol(vku, n) != -1);
        param.set_vku(vku);
    }else{
        const BN &vku = param.vku();
        if(vku <= 0 || vku >= n || vku.Gcd(n) != 1 || BN::JacobiSymbol(vku, n) != -1){
            return false;
        }
    }

    return InternalGenerateKey(key_bits_length, l, k, private_key_share_arr, public_key, key_meta, param);
}


/**
 * Combine all the shares of signature to make a real signature.
 * @param[in] x: a big number related to prepared hash
 * @param[in] sig_arr : the shares of signature.
 * @param[in] public_key: public key.
 * @param[in] key_meta: key meta data.
 * @param[out] out_sig: a real signature.
 * @return true on success, false on error.
 */
bool InternalCombineSignatures(const safeheron::bignum::BN &_x,
                               const std::vector<RSASigShare> &sig_arr,
                               const RSAPublicKey &public_key,
                               const RSAKeyMeta &key_meta,
                               const bool validate_sig,
                               safeheron::bignum::BN &out_sig){
    // e' is always set to 4.
    BN ep(4);

    // x = m    , if (m, n) == 1
    // x = m*u^e, if (m, n) == -1
    BN x = _x;
    int jacobi_m_n = BN::JacobiSymbol(x, public_key.n());
    if( jacobi_m_n == -1){
        x = (x * key_meta.vku().PowM(public_key.e(), public_key.n())) % public_key.n();
    }

    // Validate signature share
    if(validate_sig) {
        bool is_valid_sig = true;
        for (const auto &sig: sig_arr) {
            RSASigShareProof proof(sig.z(), sig.c());
            is_valid_sig &= proof.Verify(key_meta.vkv(), key_meta.vki(sig.index() - 1), x, public_key.n(),
                                         sig.sig_share());
            if (!is_valid_sig) return false;
        }
    }

    // Compute \Delta = l!
    BN delta(1);
    for(int i = 1; i <= key_meta.l(); i++){
        delta *= i;
    }

    // S is a subset of (1, ... ,l)
    std::vector<BN> S;
    for(const auto &item : sig_arr){
        S.emplace_back(BN(item.index()));
    }

    // w = x_{i_1}^{2 \lambda_{0,i_1}^S} \dots	x_{i_k}^{2 \lambda_{0,i_k}^S} \pmod n
    BN w(1);
    for(const auto &item : sig_arr){
        BN lam = lambda(BN(0), BN(item.index()), S, delta);
        w = (w * item.sig_share().PowM(lam * 2, public_key.n())) % public_key.n();
    }

    // y = w^a x^b \pmod n
    BN d, a, b;
    BN::ExtendedEuclidean(ep, public_key.e(), a, b, d);
    BN y = w.PowM(a, public_key.n()) * x.PowM(b, public_key.n()) % public_key.n();
    if (jacobi_m_n == -1) {
        y = (y * key_meta.vku().InvM(public_key.n())) % public_key.n();
    }
    out_sig = y;
    return true;
}

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
                       safeheron::bignum::BN &out_sig){
    BN x = BN::FromBytesBE(doc);
    return InternalCombineSignatures(x, sig_arr, public_key, key_meta, true, out_sig);
}

/**
 * Combine all the shares of signature without validation on signature shares to make a real signature.
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
                                        safeheron::bignum::BN &out_sig){
    BN x = BN::FromBytesBE(doc);
    return InternalCombineSignatures(x, sig_arr, public_key, key_meta, false, out_sig);
}

};
};
