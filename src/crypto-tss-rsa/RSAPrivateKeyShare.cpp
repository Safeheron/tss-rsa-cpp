#include "RSAPrivateKeyShare.h"
#include "RSASigShare.h"
#include "RSASigShareProof.h"
#include "common.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-encode/base64.h"
#include "crypto-hash/hash256.h"

using std::string;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;
using safeheron::bignum::BN;
using safeheron::hash::CSHA256;

namespace safeheron {
namespace tss_rsa{

RSAPrivateKeyShare::RSAPrivateKeyShare(int i,
                                       const safeheron::bignum::BN &si){
    this->si_ = si;
    this->i_ = i;
}

const bignum::BN &RSAPrivateKeyShare::si() const {
    return si_;
}

void RSAPrivateKeyShare::set_si(const bignum::BN &s) {
    si_ = s;
}

int RSAPrivateKeyShare::i() const {
    return i_;
}

void RSAPrivateKeyShare::set_i(int i) {
    i_ = i;
}

RSASigShare RSAPrivateKeyShare::InternalSign(const safeheron::bignum::BN &_x,
                                             const safeheron::tss_rsa::RSAKeyMeta &key_meta,
                                             const safeheron::tss_rsa::RSAPublicKey &public_key){
    // x = x*u^e, if (m, n) == -1
    BN x = _x;
    if(BN::JacobiSymbol(x, public_key.n()) == -1){
        x = (x * key_meta.vku().PowM(public_key.e(), public_key.n())) % public_key.n();
    }

    // x_i = x^{2 * s_i}
    BN xi = x.PowM(si_ * 2, public_key.n());

    RSASigShareProof proof;
    proof.Prove(si_, key_meta.vkv(), key_meta.vki(i_-1), x, public_key.n(), xi);


    return {i_, xi, proof.z(), proof.c()};
}

RSASigShare RSAPrivateKeyShare::Sign(const std::string &doc,
                                     const safeheron::tss_rsa::RSAKeyMeta &key_meta,
                                     const safeheron::tss_rsa::RSAPublicKey &public_key){
    BN x = BN::FromBytesBE(doc);
    return InternalSign(x, key_meta, public_key);
}

bool RSAPrivateKeyShare::ToProtoObject(proto::RSAPrivateKeyShare &proof) const {
    bool ok = true;

    if(i_ == 0) return false;
    proof.set_i(i_);

    std::string str;
    si_.ToHexStr(str);
    proof.mutable_si()->assign(str);

    return true;
}

bool RSAPrivateKeyShare::FromProtoObject(const proto::RSAPrivateKeyShare &proof) {
    bool ok = true;

    i_ = proof.i();
    if(i_ == 0) return false;

    si_ = BN::FromHexStr(proof.si());

    return true;
}

typedef RSAPrivateKeyShare TheClass;
typedef safeheron::proto::RSAPrivateKeyShare ProtoObject;

bool TheClass::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::RSAPrivateKeyShare proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool TheClass::FromBase64(const string &b64) {
    bool ok = true;

    string data = encode::base64::DecodeFromBase64(b64);

    safeheron::proto::RSAPrivateKeyShare proto_object;
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

};
};
