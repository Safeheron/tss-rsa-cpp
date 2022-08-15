/*
 * The EMSA_PSS encoding method references the EMSA-PSS encoding scheme according to RFC 3447
 * See RFC 3447, Section 9.1 : https://datatracker.ietf.org/doc/html/rfc3447#section-9.1
 * The SaltLength value references the implementation of go
 * See: https://github.com/golang/go/blob/master/src/crypto/rsa/pss.go
 */

#ifndef SAFEHERON_TSS_RSA_EMSA_PSS_H
#define SAFEHERON_TSS_RSA_EMSA_PSS_H

#include "crypto-bn/bn.h"
#include "crypto-bn/rand.h"

namespace safeheron {
    namespace tss_rsa {
        enum class SaltLength {
            AutoLength,
            EqualToHash
        };
        /**
         * Mask generation function
         * Refer to https://datatracker.ietf.org/doc/html/rfc3447#appendix-B.2.1
         * @param seed
         * @param seedLen
         * @param maskLen
         * @return MGF1 bytes.
         */
        std::string MGF1(const uint8_t *seed, size_t seedLen, size_t maskLen);

        /**
         * EMSA-PSS-Encode
         * Refer to https://datatracker.ietf.org/doc/html/rfc3447#section-9.1.1
         * @param m
         * @param keyBits
         * @param saltLength
         * @return Encoding result.
         */
        std::string EncodeEMSA_PSS(const std::string &m, int keyBits, SaltLength saltLength);

        /**
         * EMSA-PSS-VERIFY
         * Refer to https://datatracker.ietf.org/doc/html/rfc3447#section-9.1.2
         * @param m
         * @param keyBits
         * @param saltLength
         * @param emsa_pss
         * @return
         */
        bool VerifyEMSA_PSS(const std::string &m, int keyBits, SaltLength saltLength, const std::string &emsa_pss);

    }
}



#endif //SAFEHERON_TSS_RSA_EMSA_PSS_H
