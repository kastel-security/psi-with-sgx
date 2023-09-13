#include "IASReport.h"
#include <iostream>
#include <istream>
#include "UtilityFunctions.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"

#ifdef ENCLAVE
#include "LogSgx.h"
#else
#include "LogBase.h"
using namespace util;
#include <jsoncpp/json/json.h>
#endif

IASReport::IASReport(string json, string signature) : response(json), response_signature(signature){
#ifndef ENCLAVE
    Json::Value empty;
    Json::Value root;
    Json::Reader reader;
    bool parsingSuccessful = reader.parse(json.c_str(), json.c_str() + json.size(), root);

    if (!parsingSuccessful) {
        Log("Failed to parse JSON string from IAS");
        throw runtime_error("parsing response from IAS failed.");
    }

    id = root.get("id", empty ).asString();
    timestamp = root.get("timestamp", empty ).asString();
    idPseudonym = root.get("epidPseudonym", empty ).asString();
    isvEnclaveQuoteStatus = root.get("isvEnclaveQuoteStatus", empty).asString();
    // Log("epid: %s", idPseudonym.c_str());
    // Log("time: %s", timestamp.c_str());
    Log("QuoteStatus: %s", isvEnclaveQuoteStatus.c_str());
    string body_enc = root.get("isvEnclaveQuoteBody", empty).asString();
#else
    string start_marker = "\"isvEnclaveQuoteBody\":\"";
    auto pos = json.find(start_marker);
    pos += start_marker.size();
    auto end = json.find("\"", pos);
    auto body_enc = json.substr(pos, end-pos);
#endif
    auto body_str = Base64decode(body_enc);
    if(body_str.size() != sizeof(report_body) + 0x30){
        Log("%d != %d.", body_str.size(), sizeof(report_body) + 0x30);
        throw runtime_error("wrong isvEnclaveQuoteBody size");
    }
    report_body = *reinterpret_cast<const decltype(report_body)*>(body_str.data() + 0x30);
    // Log("Body: %d; %d", std::to_string(report_body.isv_ext_prod_id[0]), std::to_string(report_body.report_data.d[0])); 
}

const static string verifyKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFi\n"
    "aGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhk\n"
    "KWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQj\n"
    "lytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwn\n"
    "XnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KA\n"
    "XJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4\n"
    "tQIDAQAB\n"
    "-----END PUBLIC KEY-----";

void IASReport::verify(const sgx_report_data_t report_data){
    uint8_t sum = 0;
    for(uint8_t i = 0; i < sizeof(report_data); i++){
        sum |= report_data.d[i] ^ report_body.report_data.d[i];
    }
    if(sum != 0){
        Log("hash does not match.");
        throw runtime_error("report_data does not match.");
    }

    unsigned char hash_value[32] = {};
    sha256 hash;
    hash << response;
    hash.hash(hash_value);
    string sig = Base64decode(response_signature);
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE] = {};
    if(sig.size() > sizeof(buf)) {
      throw runtime_error("signature too large");
    }
    copy(begin(sig), end(sig), buf);

    int ret;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if ( (ret = mbedtls_pk_parse_public_key( &pk,
                 reinterpret_cast<const unsigned char*>(verifyKey.c_str()), verifyKey.size() + 1 )) != 0 ){
        Log("pk_parse_public_key failed:   -0x%x.", -ret);
        throw std::runtime_error("pk_parse_public_key");
    }

    mbedtls_rsa_context *rsa = reinterpret_cast<mbedtls_rsa_context *>(pk.pk_ctx);
    if ( ( ret = mbedtls_rsa_pkcs1_verify( rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 20, hash_value, buf ) ) != 0 ) {
        Log("pkcs1_verify failed:   -0x%x.", -ret);
        throw std::runtime_error("pkcs1_verify");
    }
    Log("IAS Report Signature validated.");
}
