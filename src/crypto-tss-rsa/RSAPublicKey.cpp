#include "RSAPublicKey.h"
#include "exception/safeheron_exceptions.h"
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
using safeheron::exception::LocatedException;
using safeheron::exception::OpensslException;
using safeheron::exception::BadAllocException;
using safeheron::exception::RandomSourceException;
using safeheron::hash::CSHA256;


namespace safeheron {
namespace tss_rsa{


RSAPublicKey::RSAPublicKey(const safeheron::bignum::BN &n, const safeheron::bignum::BN &e){
    this->n_ = n;
    this->e_ = e;
}

bool RSAPublicKey::InternalVerifySignature(const safeheron::bignum::BN &x, const safeheron::bignum::BN &sig) {
    // check y^e = x  mod n, where y = sig
    return sig.PowM(e_, n_) == (x % n_);
}

bool RSAPublicKey::VerifySignature(const string &doc, const safeheron::bignum::BN &sig){
    BN x = BN::FromBytesBE(doc);
    return InternalVerifySignature(x, sig);
}

const bignum::BN &RSAPublicKey::n() const {
    return n_;
}

void RSAPublicKey::set_n(const bignum::BN &n) {
    n_ = n;
}

const bignum::BN &RSAPublicKey::e() const {
    return e_;
}

void RSAPublicKey::set_e(const bignum::BN &e) {
    e_ = e;
}

bool RSAPublicKey::ToProtoObject(proto::RSAPublicKey &proof) const {
    bool ok = true;

    std::string str;
    n_.ToHexStr(str);
    proof.mutable_n()->assign(str);

    e_.ToHexStr(str);
    proof.mutable_e()->assign(str);

    return true;
}

bool RSAPublicKey::FromProtoObject(const proto::RSAPublicKey &proof) {
    bool ok = true;

    n_ = BN::FromHexStr(proof.n());
    e_ = BN::FromHexStr(proof.e());

    return true;
}

typedef RSAPublicKey TheClass;
typedef safeheron::proto::RSAPublicKey ProtoObject;

bool TheClass::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::RSAPublicKey proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool TheClass::FromBase64(const string &b64) {
    bool ok = true;

    string data = encode::base64::DecodeFromBase64(b64);

    safeheron::proto::RSAPublicKey proto_object;
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
