#pragma once
#include <string>

#include "sgx_report.h"

class IASReport {
public:
    std::string id;
    std::string timestamp;
    std::string idPseudonym;
    std::string isvEnclaveQuoteStatus;

    std::string response;
    std::string response_signature;

    sgx_report_body_t report_body;
    IASReport(std::string json, std::string signature);
    void verify(const sgx_report_data_t report_data);
};
