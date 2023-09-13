#ifndef WEBSERVICE_H
#define WEBSERVICE_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <curl/curl.h>
#include <iostream>

#include "LogBase.h"
#include "UtilityFunctions.h"
#include "IASReport.h"

using namespace std;
using namespace util;

enum IAS {
    sigrl,
    report
};

struct attestation_verification_report_t {
    string report_id;
    string isv_enclave_quote_status;
    string timestamp;
};

struct attestation_evidence_payload_t {
    string isv_enclave_quote;
};

struct ias_response_header_t {
    int response_status;
    int content_length;
    std::string request_id;
    std::string report_signature;
};

struct ias_response_container_t {
    char *p_response;
    size_t size;
};

static int REQUEST_ID_MAX_LEN = 32;
static vector<pair<string, string>> retrieved_sigrl;

class WebService {

public:
    static WebService* getInstance();
    virtual ~WebService();
    bool getSigRL(string gid, string *sigrl);
    std::unique_ptr<IASReport> verifyQuote(uint8_t *quote, uint8_t *pseManifest, uint8_t *nonce);

private:
    WebService();
    bool sendToIAS(string url, IAS type, string payload,
                   struct curl_slist *headers,
                   ias_response_container_t *ias_response_container,
                   ias_response_header_t *response_header);

    string createJSONforIAS(uint8_t *quote, uint8_t *pseManifest, uint8_t *nonce);

private:
    static thread_local WebService* instance;
    CURL *curl;
};

#endif



