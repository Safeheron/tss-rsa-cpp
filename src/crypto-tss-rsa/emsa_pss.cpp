#include "emsa_pss.h"
#include <cstring>
#include <memory>
#include "crypto-bn/bn.h"
#include "crypto-bn/rand.h"
#include "exception/located_exception.h"
#include "crypto-hash/sha256.h"

using std::string;
using safeheron::hash::CSHA256;
using safeheron::exception::LocatedException;
namespace safeheron {
    namespace tss_rsa {

        std::string MGF1(const uint8_t *seed, size_t seedLen, size_t maskLen) {
            string mask;
            // Allocate CSHA256::OUTPUT_SIZE-1 more bytes.
            mask.reserve(maskLen + CSHA256::OUTPUT_SIZE - 1);
            for(size_t i = 0; i < (maskLen + CSHA256::OUTPUT_SIZE -1) / CSHA256::OUTPUT_SIZE; i++) {
                uint8_t cnt[4];
                cnt[0] = (unsigned char)((i >> 24) & 255);
                cnt[1] = (unsigned char)((i >> 16) & 255);
                cnt[2] = (unsigned char)((i >> 8)) & 255;
                cnt[3] = (unsigned char)(i & 255);

                uint8_t digest[CSHA256::OUTPUT_SIZE];
                CSHA256 sha256;
                sha256.Write(seed, seedLen);
                sha256.Write(cnt, 4);
                sha256.Finalize(digest);

                mask.append(reinterpret_cast<const char *>(digest), CSHA256::OUTPUT_SIZE);
            }
            return mask.substr(0, maskLen);
        }

        std::string EncodeEMSA_PSS(const std::string &m, int keyBits, SaltLength saltLength) {
            size_t emBits = keyBits - 1;

            size_t emLen = (emBits + 7) / 8;

            // check emLen
            if(emLen < CSHA256::OUTPUT_SIZE + 2) {
                throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "emLen < CSHA256::OUTPUT_SIZE + 2");
            }

            size_t sLen;
            switch (saltLength) {
                case SaltLength::AutoLength:
                {
                    sLen =  emLen - 2 - CSHA256::OUTPUT_SIZE;
                    break;
                }
                case SaltLength::EqualToHash:
                default:
                {
                    sLen = CSHA256::OUTPUT_SIZE;
                    break;
                }
            }

            // 2.  Let mHash = Hash(M), an octet string of length hLen.
            uint8_t mHash[CSHA256::OUTPUT_SIZE];
            CSHA256 sha256;
            sha256.Write(reinterpret_cast<const uint8_t *>(m.c_str()), m.length());
            sha256.Finalize(mHash);

            // 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.
            if(emLen < CSHA256::OUTPUT_SIZE + sLen + 2) {
                throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "emLen error: KeyBitLength is too short.");
            }

            // 4.  Generate a random octet string salt of length sLen; if sLen = 0, then salt is the empty string.
            std::unique_ptr<uint8_t[]> salt(new uint8_t[sLen]);
            if(sLen > 0) safeheron::rand::RandomBytes(salt.get(), sLen);

            // 5.  Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
            //     M' is an octet string of length 8 + hLen + sLen with eight initial zero octets.
            // 6.  Let H = Hash(M'), an octet string of length hLen.
            uint8_t padding1[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

            uint8_t H[CSHA256::OUTPUT_SIZE];
            sha256.Reset();
            sha256.Write(padding1, 8);
            sha256.Write(mHash, CSHA256::OUTPUT_SIZE);
            sha256.Write(salt.get(), sLen);
            sha256.Finalize(H);

            // 7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
            //     zero octets.  The length of PS may be 0.
            //
            // 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
            //       emLen - hLen - 1.
            string DB;
            DB.reserve(emLen - CSHA256::OUTPUT_SIZE - 1);
            size_t PSLen = emLen - CSHA256::OUTPUT_SIZE - sLen - 2;
            DB.append(PSLen, 0x00);
            DB.append(1, 0x01);
            DB.append(reinterpret_cast<const char *>(salt.get()), sLen);

            // 9.  Let dbMask = MGF(H, emLen - hLen - 1).  mask generation function
            string dbMask = MGF1(H, CSHA256::OUTPUT_SIZE, emLen - CSHA256::OUTPUT_SIZE - 1);

            // 10. Let maskedDB = DB \xor dbMask.
            string maskedDB;
            maskedDB.reserve(emLen - CSHA256::OUTPUT_SIZE - 1);
            for(size_t i = 0; i < emLen - CSHA256::OUTPUT_SIZE - 1; i++) {
                maskedDB.append(1, DB[i] ^ dbMask[i]);
            }

            // 11. Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero.
            uint8_t c = 255;
            for(size_t i = 0; i < emLen * 8 -emBits; i++) {
                c = c >> 1;
            }
            maskedDB[0] &= (char)c;

            // 12. Let EM = maskedDB || H || 0xbc.
            string em;
            em.reserve(emLen);
            em.append(maskedDB);
            em.append(reinterpret_cast<const char *>(H), CSHA256::OUTPUT_SIZE);
            em.append(1, (char)0xbc);
            return em;
        }

        bool VerifyEMSA_PSS(const std::string &m, int keyBits, SaltLength saltLength, const std::string &em) {
            size_t emBits = keyBits - 1;
            size_t emLen = (emBits + 7) / 8;
            if(em.length() != emLen) {
                // error: inconsistent
                return false;
            }

            // check emLen
            if(emLen < CSHA256::OUTPUT_SIZE + 2) {
                return false;
            }

            size_t sLen;
            switch (saltLength) {
                case SaltLength::AutoLength:
                {
                    sLen =  emLen - 2 - CSHA256::OUTPUT_SIZE;
                    break;
                }
                case SaltLength::EqualToHash:
                default:
                {
                    sLen = CSHA256::OUTPUT_SIZE;
                    break;
                }
            }

            // 3.  If emLen < hLen + sLen + 2, output "inconsistent" and stop.
            if(emLen < CSHA256::OUTPUT_SIZE + sLen + 2) {
                // error: KeyBitLength is too short.
                return false;
            }

            // 4.  If the rightmost octet of EM does not have hexadecimal value 0xbc, output "inconsistent" and stop.
            if(em.at(em.length() - 1) != (char)0xbc) {
                // error: inconsistent.
                return false;
            }

            // 5.  Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and let H be the next hLen octets.
            const uint8_t *maskedDB = reinterpret_cast<const uint8_t *>(em.c_str());
            const uint8_t *H = maskedDB + (emLen - CSHA256::OUTPUT_SIZE - 1);

            // 6.  If the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB are not all equal to zero, output "inconsistent" and stop.
            uint8_t c = 255;
            for(size_t i = 0; i < 8 - (emLen * 8 -emBits); i++) {
                c = c << 1;
            }
            uint8_t leftmost = maskedDB[0];
            if((leftmost & c) != 0x00) {
                // error: inconsistent.
                return false;
            }

            // 7.  Let dbMask = MGF(H, emLen - hLen - 1).
            string mask = MGF1(H, CSHA256::OUTPUT_SIZE, emLen - CSHA256::OUTPUT_SIZE - 1);
            const uint8_t *dbMask = (uint8_t *) mask.c_str();

            // 8.  Let DB = maskedDB \xor dbMask.
            size_t DBLen = emLen - CSHA256::OUTPUT_SIZE - 1;
            std::unique_ptr<uint8_t[]> DB(new uint8_t[DBLen]);
            for(size_t i = 0; i < DBLen; i++) {
                DB[i] = maskedDB[i] ^ dbMask[i];
            }

            // 9.  Set the leftmost 8emLen - emBits bits of the leftmost octet in DB to zero.
            c = 255;
            for(size_t i = 0; i < emLen * 8 -emBits; i++) {
                c = c >> 1;
            }
            DB[0] &= c;

            // 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
            //    or if the octet at position emLen - hLen - sLen - 1 (the leftmost
            //    position is "position 1") does not have hexadecimal value 0x01,
            //    output "inconsistent" and stop.
            int PS_len = emLen - CSHA256::OUTPUT_SIZE - sLen - 2;
            const uint8_t * PS = DB.get();
            for(int i = 0; i < PS_len; i++) {
                if(PS[i] != 0x00) {
                    // error: inconsistent.
                    return false;
                }
            }

            uint8_t left_padding = DB[emLen - CSHA256::OUTPUT_SIZE - sLen - 2];
            if(left_padding != (unsigned char)0x01) {
                // error: inconsistent.
                return false;
            }

            // 11.  Let salt be the last sLen octets of DB.
            uint8_t padding1[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            const uint8_t *solt = DB.get() + (emLen - CSHA256::OUTPUT_SIZE - 1 - sLen);

            uint8_t mHash[CSHA256::OUTPUT_SIZE];
            CSHA256 sha256;
            sha256.Write(reinterpret_cast<const uint8_t *>(m.c_str()), m.length());
            sha256.Finalize(mHash);

            // 12.  Let
            //          M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
            //      M' is an octet string of length 8 + hLen + sLen with eight initial zero octets.
            // 13. Let H' = Hash(M'), an octet string of length hLen.
            uint8_t HPrime[CSHA256::OUTPUT_SIZE];
            sha256.Reset();
            sha256.Write(padding1, 8);
            sha256.Write(mHash, CSHA256::OUTPUT_SIZE);
            sha256.Write(solt, sLen);
            sha256.Finalize(HPrime);

            // 14. If H = H', output "consistent." Otherwise, output "inconsistent."
            if(strncmp((char*)H, (char*)HPrime, CSHA256::OUTPUT_SIZE) == 0) {
                return true;
            } else {
                return false;
            }
        }

    }
}
