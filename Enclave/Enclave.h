#pragma once

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>


#include "LogBase.h"
#include "UtilityFunctions.h"
// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to query extended epid group id.
#include "sgx_uae_epid.h"
#include "Report.h"
#include "../GeneralSettings.h"

typedef sgx_status_t (*enclave_init_ra_callback)(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context);

typedef sgx_status_t (* enclave_ra_close_callback )(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context);
class Enclave {
public:
    Enclave(string binary);
    virtual ~Enclave();

    sgx_enclave_id_t getID();

  template<auto t, typename... Args>
  void call(Args... args){
    sgx_status_t ret = {};
    sgx_status_t outer_ret = t(getID(), &ret, args...);
    if(outer_ret != SGX_SUCCESS){
      throw std::runtime_error("SGX Call failed with: " + std::to_string(outer_ret));
    }
    if(ret != SGX_SUCCESS){
      throw std::runtime_error("SGX App failed with: " + std::to_string(ret));
    }
  }
  template<auto t, typename... Args>
  std::unique_ptr<Report> callAttested(Args... args){
    auto r = std::make_unique<Report>();
    call<t>(args..., r->target_info(), r->report());
    *r->nonce() = {1};
    r->generateQuote(Settings::spid);
    return r;
  }

private:
    sgx_enclave_id_t enclave_id;
};

class RAContext {
public:
    RAContext(shared_ptr<Enclave> enclave, enclave_init_ra_callback ra_init, enclave_ra_close_callback ra_close);
    virtual ~RAContext();
    sgx_ra_context_t getContext();

    sgx_ra_msg1_t generateMSG1(sgx_ecall_get_ga_trusted_t ra_get_ga);
    string proc_msg2(sgx_ra_msg2_t *p_msg2, uint32_t msg2_size, sgx_ecall_proc_msg2_trusted_t p_proc_msg2,
    sgx_ecall_get_msg3_trusted_t p_get_msg3);
private:
    shared_ptr<Enclave> enclave;
    enclave_ra_close_callback ra_close;
    sgx_ra_context_t context;
};





