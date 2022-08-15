#include "RSASigShare.h"
#include <google/protobuf/util/json_util.h>
#include "crypto-encode/base64.h"

using std::string;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;
using safeheron::bignum::BN;

namespace safeheron {
namespace tss_rsa{

RSASigShare::RSASigShare(): index_(0), sig_share_(bignum::BN::ZERO), z_(bignum::BN::ZERO), c_(bignum::BN::ZERO){}

RSASigShare::RSASigShare(int index,
                         const safeheron::bignum::BN &sig_share,
                         const safeheron::bignum::BN &z,
                         const safeheron::bignum::BN &c){
    this->index_ = index;
    this->sig_share_ = sig_share;
    this->z_ = z;
    this->c_ = c;
}

int RSASigShare::index() const {
    return index_;
}

void RSASigShare::set_index(int index) {
    index_ = index;
}

const bignum::BN &RSASigShare::sig_share() const {
    return sig_share_;
}

void RSASigShare::set_sig_share(const bignum::BN &sig_share) {
    sig_share_ = sig_share;
}

const bignum::BN &RSASigShare::z() const {
    return z_;
}

void RSASigShare::set_z(const bignum::BN &z) {
    z_ = z;
}

const bignum::BN &RSASigShare::c() const {
    return c_;
}

void RSASigShare::set_c(const bignum::BN &c) {
    c_ = c;
}

bool RSASigShare::ToProtoObject(proto::RSASigShare &proof) const {
    bool ok = true;

    if(index_ == 0) return false;
    proof.set_index(index_);

    std::string str;
    sig_share_.ToHexStr(str);
    proof.mutable_sig_share()->assign(str);

    z_.ToHexStr(str);
    proof.mutable_z()->assign(str);

    c_.ToHexStr(str);
    proof.mutable_c()->assign(str);

    return true;
}

bool RSASigShare::FromProtoObject(const proto::RSASigShare &proof) {
    bool ok = true;

    index_ = proof.index();
    if(index_ == 0) return false;

    sig_share_ = BN::FromHexStr(proof.sig_share());

    z_ = BN::FromHexStr(proof.z());

    c_ = BN::FromHexStr(proof.c());

    return true;
}

typedef RSASigShare TheClass;
typedef safeheron::proto::RSASigShare ProtoObject;

bool TheClass::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::RSASigShare proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool TheClass::FromBase64(const string &b64) {
    bool ok = true;

    string data = encode::base64::DecodeFromBase64(b64);

    safeheron::proto::RSASigShare proto_object;
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
