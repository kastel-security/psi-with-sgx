#include "WebService.h"
#include "../GeneralSettings.h"
#include <stdexcept>
#include <jsoncpp/json/json.h>
#include <chrono>
#include <string.h>

thread_local WebService* WebService::instance = NULL;

WebService::WebService() {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();

    if (curl) {
        Log("Curl initialized successfully");
        if(Settings::curl_verbose) {
            curl_easy_setopt( curl, CURLOPT_VERBOSE, 1L );
        }

        curl_easy_setopt( curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
        curl_easy_setopt( curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        curl_easy_setopt( curl, CURLOPT_NOPROGRESS, 1L);
    } else
        Log("Curl init error", log::error);
}

WebService::~WebService() {
    if (curl)
        curl_easy_cleanup(curl);
}


WebService* WebService::getInstance() {
    if (instance == NULL) {
        instance = new WebService();
    }

    return instance;
}

string WebService::createJSONforIAS(uint8_t *quote, uint8_t *pseManifest, uint8_t *nonce) {
    Json::Value request;

    request["isvEnclaveQuote"] = Base64encodeUint8(quote, 1116);
//    request["pseManifest"] = Base64encodeUint8(quote, 256);		//only needed when enclave has been signed

    return Json::FastWriter{}.write(request);
}


size_t ias_response_header_parser(void *ptr, size_t size, size_t nmemb, void *userdata) {
    int parsed_fields = 0, response_status, content_length, ret = size * nmemb;

    char *x = (char*) calloc(size+1, nmemb);
    assert(x);
    memcpy(x, ptr, size * nmemb);
    parsed_fields = sscanf( x, "HTTP/1.1 %d", &response_status );

    if (parsed_fields == 1) {
        ((ias_response_header_t *) userdata)->response_status = response_status;
        return ret;
    }

    parsed_fields = sscanf( x, "content-length: %d", &content_length );
    if (parsed_fields == 1) {
        ((ias_response_header_t *) userdata)->content_length = content_length;
        return ret;
    }

    char *p_request_id = (char*) calloc(1, REQUEST_ID_MAX_LEN);
    parsed_fields = sscanf(x, "request-id: %s", p_request_id );

    if (parsed_fields == 1) {
        std::string request_id_str( p_request_id );
        ( ( ias_response_header_t * ) userdata )->request_id = request_id_str;
        return ret;
    }

    vector<char> ias_report_signature(4096);
    parsed_fields = sscanf(x, "X-IASReport-Signature: %s", ias_report_signature.data() );

    if (parsed_fields == 1) {
        ( ( ias_response_header_t * ) userdata )->report_signature = std::string( ias_report_signature.data());
        return ret;
    }

    return ret;
}


size_t ias_reponse_body_handler( void *ptr, size_t size, size_t nmemb, void *userdata ) {
    size_t realsize = size * nmemb;
    ias_response_container_t *ias_response_container = ( ias_response_container_t * ) userdata;
    ias_response_container->p_response = (char *) realloc(ias_response_container->p_response, ias_response_container->size + realsize + 1);

    if (ias_response_container->p_response == NULL ) {
        Log("Unable to allocate extra memory", log::error);
        return 0;
    }

    memcpy( &( ias_response_container->p_response[ias_response_container->size]), ptr, realsize );
    ias_response_container->size += realsize;
    ias_response_container->p_response[ias_response_container->size] = 0;

    return realsize;
}


bool WebService::sendToIAS(string url,
                           IAS type,
                           string payload,
                           struct curl_slist *headers,
                           ias_response_container_t *ias_response_container,
                           ias_response_header_t *response_header) {

    curl_easy_setopt( curl, CURLOPT_URL, url.c_str());

    string api_key_header = string("Ocp-Apim-Subscription-Key: ") + Settings::api_key;
    headers = curl_slist_append(headers, api_key_header.c_str());

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (!payload.empty()) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    }

    ias_response_container->p_response = (char*) malloc(1);
    ias_response_container->size = 0;

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ias_response_header_parser);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, response_header);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ias_reponse_body_handler);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, ias_response_container);

    auto webRequestTimer = std::make_unique<Timer>("WebRequest");
    CURLcode res = curl_easy_perform(curl);
    webRequestTimer.reset();
    if (res != CURLE_OK) {
        Log("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        return false;
    }

    return true;
}


bool WebService::getSigRL(string gid, string *sigrl) {
    Log("Retrieving SigRL %s from IAS", gid);

    //check if the sigrl for the gid has already been retrieved once -> to save time
    for (auto x : retrieved_sigrl) {
        if (x.first == gid) {
            *sigrl = x.second;
            return false;
        }
    }

    ias_response_container_t ias_response_container = {};
    ias_response_header_t response_header = {};

    string url = Settings::ias_url + "sigrl/" + gid;

    this->sendToIAS(url, IAS::sigrl, "", NULL, &ias_response_container, &response_header);

    Log("\tResponse: %d bytes, status %d", response_header.content_length, response_header.response_status);

    if (response_header.response_status == 200) {
        if (response_header.content_length > 0) {
            string response(ias_response_container.p_response);
            *sigrl = Base64decode(response);
        }
        retrieved_sigrl.push_back({gid, *sigrl});
    } else
        return true;

    return false;
}


std::unique_ptr<IASReport> WebService::verifyQuote(uint8_t *quote, uint8_t *pseManifest, uint8_t *nonce) {
    string encoded_quote = this->createJSONforIAS(quote, pseManifest, nonce);

    ias_response_container_t ias_response_container;
    ias_response_header_t response_header;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    string payload = encoded_quote;

    string url = Settings::ias_url + "report";
    this->sendToIAS(url, IAS::report, payload, headers, &ias_response_container, &response_header);
    string response(ias_response_container.p_response);

    
    if (response_header.response_status == 200) {
    	Log("New Report.");

	    // Log("Response: %s\n", response.c_str());
        return std::make_unique<IASReport>(response, response_header.report_signature);
    } else {
        Log("Quote attestation returned status: %d", response_header.response_status);
        return nullptr;
    }
}




