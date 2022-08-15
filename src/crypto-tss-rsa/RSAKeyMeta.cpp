#include "RSAKeyMeta.h"
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

RSAKeyMeta::RSAKeyMeta(int k,
           int l,
           const safeheron::bignum::BN &vkv,
           const std::vector<safeheron::bignum::BN> &vki_arr,
           const safeheron::bignum::BN &vku){
    this->k_ = k;
    this->l_ = l;
    this->vkv_ = vkv;
    this->vki_arr_.insert(this->vki_arr_.begin(), vki_arr.begin(), vki_arr.end());
    this->vku_ = vku;
}

int RSAKeyMeta::k() const {
    return k_;
}

void RSAKeyMeta::set_k(int k) {
    k_ = k;
}

int RSAKeyMeta::l() const {
    return l_;
}

void RSAKeyMeta::set_l(int l) {
    l_ = l;
}

const bignum::BN &RSAKeyMeta::vkv() const {
    return vkv_;
}

void RSAKeyMeta::set_vkv(const bignum::BN &vkv) {
    vkv_ = vkv;
}

const std::vector<safeheron::bignum::BN> &RSAKeyMeta::vki_arr() const {
    return vki_arr_;
}

void RSAKeyMeta::set_vki_arr(const std::vector<safeheron::bignum::BN> &vki_arr) {
    this->vki_arr_.clear();
    this->vki_arr_.insert(this->vki_arr_.begin(), vki_arr.begin(), vki_arr.end());
}

const safeheron::bignum::BN &RSAKeyMeta::vki(size_t index) const {
    return vki_arr_.at(index);
}

const bignum::BN &RSAKeyMeta::vku() const {
    return vku_;
}

void RSAKeyMeta::set_vku(const bignum::BN &vku) {
    vku_ = vku;
}

bool RSAKeyMeta::ToProtoObject(proto::RSAKeyMeta &proof) const {
    bool ok = true;

    if(k_ < 2) return false;
    proof.set_k(k_);

    if(l_ < 2) return false;
    proof.set_l(l_);

    std::string str;
    vkv_.ToHexStr(str);
    proof.mutable_vkv()->assign(str);

    vku_.ToHexStr(str);
    proof.mutable_vku()->assign(str);

    for(size_t i = 0; i < vki_arr_.size(); ++i){
        vki_arr_[i].ToHexStr(str);
        proof.add_vki_arr(str);
    }
    return true;
}

bool RSAKeyMeta::FromProtoObject(const proto::RSAKeyMeta &proof) {
    bool ok = true;

    k_ = proof.k();
    if(k_ == 0) return false;

    l_ = proof.l();
    if(l_ == 0) return false;

    vkv_ = BN::FromHexStr(proof.vkv());

    vku_ = BN::FromHexStr(proof.vku());

    for(int i = 0; i < proof.vki_arr_size(); ++i){
        BN alpha = BN::FromHexStr(proof.vki_arr(i));
        vki_arr_.push_back(alpha);
    }
    return true;
}

typedef RSAKeyMeta TheClass;
typedef safeheron::proto::RSAKeyMeta ProtoObject;

bool TheClass::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    safeheron::proto::RSAKeyMeta proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool TheClass::FromBase64(const string &b64) {
    bool ok = true;

    string data = encode::base64::DecodeFromBase64(b64);

    safeheron::proto::RSAKeyMeta proto_object;
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
