#include "Report.h"
#include <algorithm>
#include <stdexcept>
#include "UtilityFunctions.h"
#include "LogBase.h"
#include "sgx_uae_epid.h"

Report::Report(){
    sgx_epid_group_id_t gid = {};
    sgx_status_t ret = sgx_init_quote(&qe_target_info, &gid);
    if(ret != SGX_SUCCESS) {
        printf("sgx Error code: %d\n", ret);
        throw std::runtime_error("sgx_init_quote failed");
    }
    gid_bytes = std::string{reinterpret_cast<char *>(gid), sizeof(gid)};
    std::reverse(std::begin(gid_bytes), std::end(gid_bytes));
}
Report::Report(const std::string &quote){
    this->quote.resize(quote.size());
    copy(begin(quote), end(quote), this->quote.data());

}
void Report::fetchSigRL(WebService &ws){
    if(ws.getSigRL(toHex(gid_bytes), &sigRl)){
        throw std::runtime_error("sigRL cound not be fetched");
    }
}
const sgx_target_info_t *Report::target_info(){
    return &this->qe_target_info;
}
sgx_report_t *Report::report(){
    return &this->_report;
}
sgx_quote_nonce_t *Report::nonce(){
    return &this->_nonce;
}
const std::vector<uint8_t> &Report::getQuote(){
    return this->quote;
}
void Report::generateQuote(std::string spid){
    if(this->_report.body.isv_prod_id != 1){
        Log("unexpeted sgx_prod_id_t: %d", this->_report.body.isv_prod_id);
        throw runtime_error("nothing to generate report from.");
    }
    uint32_t quote_size = 0;
    auto ret = sgx_calc_quote_size(sigRl.size() != 0 ? reinterpret_cast<const uint8_t*>(sigRl.data()) : nullptr, sigRl.size(),
        &quote_size);
    this->quote = std::vector<uint8_t>(quote_size);
    sgx_quote_t *quote = reinterpret_cast<sgx_quote_t*>(this->quote.data());
    uint8_t *spidBa;
    HexStringToByteArray(spid, &spidBa);
    ret = sgx_get_quote(&this->_report,
        SGX_UNLINKABLE_SIGNATURE,
        reinterpret_cast<sgx_spid_t *>(spidBa),
        &this->_nonce,
        sigRl.size() != 0 ? reinterpret_cast<const uint8_t*>(sigRl.data()) : nullptr, sigRl.size(),
        &this->qe_report,
        quote,
        quote_size);
    if(ret != SGX_SUCCESS){
      throw std::runtime_error("sgx_get_quote failed: "
			       + std::to_string(ret));
    }
}

void Report::verify(sgx_report_data_t &user_data){
    sgx_quote_t *quote = reinterpret_cast<sgx_quote_t*>(this->quote.data());
    sgx_report_data_t &quoted = quote->report_body.report_data;

    uint8_t sum = 0;
    for(uint8_t i = 0; i < sizeof(user_data); i++){
        sum |= user_data.d[i] ^ quoted.d[i];
    }
    if(sum != 0){
        Log("hash does not match.");
        throw runtime_error("report_data does not match.");
    }

}
std::unique_ptr<IASReport> Report::submitReport( WebService &ws) {
    sgx_quote_t *quote = reinterpret_cast<sgx_quote_t*>(this->quote.data());
    
    std::unique_ptr<IASReport> result = ws.verifyQuote(reinterpret_cast<uint8_t*>(quote), nullptr, nullptr);
    if (!result) {
        throw std::runtime_error("report verification failed");
    }
    return result;
}
