#pragma once
#include <string>
#include <vector>

//#include "remote_attestation_result.h"
#include "sgx_quote.h"
#include "WebService.h"
#include "IASReport.h"

class Report {
    sgx_target_info_t qe_target_info = {};
    std::string gid_bytes;

    std::string sigRl;

    sgx_report_t _report;
    sgx_quote_nonce_t _nonce = {};

    sgx_report_t qe_report;
    std::vector<uint8_t> quote;
public:
    Report();
    Report(const std::string &quote);
    ~Report() = default;

    void fetchSigRL(WebService &ws);
    const sgx_target_info_t *target_info();
    sgx_report_t *report();
    sgx_quote_nonce_t *nonce();
    void generateQuote(std::string spid);
    const std::vector<uint8_t> &getQuote();
    std::unique_ptr<IASReport> submitReport(WebService &ws);
    void verify(sgx_report_data_t &user_data);
};
