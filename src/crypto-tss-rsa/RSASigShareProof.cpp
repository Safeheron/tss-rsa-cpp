#include "RSASigShareProof.h"
#include <cassert>
#include <google/protobuf/util/json_util.h>
#include "exception/safeheron_exceptions.h"
#include "crypto-bn/rand.h"
#include "crypto-hash/sha256.h"
#include "crypto-encode/base64.h"

using std::string;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;
using safeheron::bignum::BN;
using safeheron::exception::LocatedException;
using safeheron::exception::OpensslException;
using safeheron::exception::BadAllocException;
using safeheron::exception::RandomSourceException;
using safeheron::hash::CSHA256;

namespace safeheron {
namespace tss_rsa{

// Output length of SHA256 is 256
static int L1 = 256;

RSASigShareProof::RSASigShareProof() : z_(bignum::BN::ZERO), c_(bignum::BN::ZERO) {}

RSASigShareProof::RSASigShareProof(const bignum::BN &z, const bignum::BN &c) : z_(z), c_(c) {}

const bignum::BN &RSASigShareProof::z() const {
    return z_;
}

void RSASigShareProof::set_z(const bignum::BN &z) {
    z_ = z;
}

const bignum::BN &RSASigShareProof::c() const {
    return c_;
}

void RSASigShareProof::set_c(const bignum::BN &c) {
    c_ = c;
}

void RSASigShareProof::Prove(const safeheron::bignum::BN &si,
                             const safeheron::bignum::BN &v,
                             const safeheron::bignum::BN &vi,
                             const safeheron::bignum::BN &x,
                             const safeheron::bignum::BN &n,
                             const safeheron::bignum::BN &sig_i){
    // sample random r in (0, 2^(L(N) + 2*L1 + 1) )
    BN upper_bound = BN::TWO << (n.BitLength() + L1 * 2);
    BN r = safeheron::rand::RandomBNLt(upper_bound);
    // v' = v^r
    BN vp = v.PowM(r, n);
    // x_tilde = x^4
    BN x_tilde = x.PowM(BN::FOUR, n);
    // x' = x_tilde^r
    BN xp = x_tilde.PowM(r, n);
    // sig^2
    BN sig2 = sig_i.PowM(BN::TWO, n);

    // c = H(v, x_tilde, vi, x^2, v', x')
    uint8_t digest[CSHA256::OUTPUT_SIZE];
    CSHA256 sha256;
    std::string buf;
    v.ToBytesBE(buf);         sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    x_tilde.ToBytesBE(buf);   sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    vi.ToBytesBE(buf);        sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    sig2.ToBytesBE(buf);      sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    vp.ToBytesBE(buf);        sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    xp.ToBytesBE(buf);        sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    sha256.Finalize(digest);
    BN c = BN::FromBytesBE(digest, CSHA256::OUTPUT_SIZE);

    // z = si * c + r
    BN z = si * c + r;

    z_ = z;
    c_ = c;
}

bool RSASigShareProof::Verify(const safeheron::bignum::BN &v,
                              const safeheron::bignum::BN &vi,
                              const safeheron::bignum::BN &x,
                              const safeheron::bignum::BN &n,
                              const safeheron::bignum::BN &sig_i){
    // v' = v^z * vi^(-c)  mod n
    BN vp = ( v.PowM(z_, n) * vi.PowM(c_ * (-1), n) ) % n;
    // x_tilde = x^4  mod n
    BN x_tilde = x.PowM(BN::FOUR, n);
    // x' = x_tilde^z * x^(-2c)  mod n
    BN xp = ( x_tilde.PowM(z_, n) * sig_i.PowM(c_ * (-2), n) ) % n;
    // sig^2  mod n
    BN sig2 = sig_i.PowM(BN::TWO, n);

    // c = H(v, x_tilde, vi, x^2, v', x')
    uint8_t digest[CSHA256::OUTPUT_SIZE];
    CSHA256 sha256;
    std::string buf;
    v.ToBytesBE(buf);         sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    x_tilde.ToBytesBE(buf);   sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    vi.ToBytesBE(buf);        sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    sig2.ToBytesBE(buf);      sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    vp.ToBytesBE(buf);        sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    xp.ToBytesBE(buf);        sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    sha256.Finalize(digest);
    BN c = BN::FromBytesBE(digest, CSHA256::OUTPUT_SIZE);

    // check c == c_
    return c == c_;
}

bool RSASigShareProof::ToProtoObject(proto::RSASigShareProof &proof) const {
    bool ok = true;

    std::string str;
    z_.ToHexStr(str);
    proof.mutable_z()->assign(str);

    c_.ToHexStr(str);
    proof.mutable_c()->assign(str);

    return true;
}

bool RSASigShareProof::FromProtoObject(const proto::RSASigShareProof &proof) {
    bool ok = true;

    z_ = BN::FromHexStr(proof.z());
    c_ = BN::FromHexStr(proof.c());

    return true;
}

typedef RSASigShareProof TheClass;
typedef safeheron::proto::RSASigShareProof ProtoObject;

bool TheClass::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::RSASigShareProof proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool TheClass::FromBase64(const string &b64) {
    bool ok = true;

    string data = encode::base64::DecodeFromBase64(b64);

    safeheron::proto::RSASigShareProof proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool TheClass::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    ProtoObject proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}


bool TheClass::FromJsonString(const string &json_str) {
    ProtoObject proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}


}
}
