#include "Enclave.h"

#include <iostream>
#include <string.h>

using namespace util;
using namespace std;


Enclave::Enclave(string binary)  {
    int launch_token_update = 0;
    int enclave_lost_retry_time = 1;
    sgx_launch_token_t launch_token = {0};

    memset(&launch_token, 0, sizeof(sgx_launch_token_t));
    auto status = sgx_status_t{};

    // Log("Debug: %d", SGX_DEBUG_FLAG);
    auto ret = sgx_create_enclave(binary.c_str(),
                                SGX_DEBUG_FLAG,
                                &launch_token,
                                &launch_token_update,
                                &this->enclave_id, NULL);

    if (SGX_SUCCESS != ret) {
        Log("Error, call sgx_create_enclave fail", log::error);
        print_error_message(ret);
        throw runtime_error("create_enclave failed.");
    }


    if (ret == SGX_SUCCESS) {
      // Log("Enclave created, ID: %llx", this->enclave_id);
    } else
        throw runtime_error("Enclave creation failed.");
    
    if(status){
        throw runtime_error("enclave_init_ra failed.");
    }

}

Enclave::~Enclave() {
    sgx_destroy_enclave(enclave_id);
}

sgx_enclave_id_t Enclave::getID() {
    return this->enclave_id;
}

RAContext::RAContext(shared_ptr<Enclave> enclave, enclave_init_ra_callback ra_init, enclave_ra_close_callback ra_close): enclave(enclave), ra_close(ra_close){
    sgx_status_t status;
    auto ret = ra_init(enclave->getID(),
                            &status,
                            false,
                            &this->context);
    if (SGX_SUCCESS != ret) {
        Log("Error, call ra_init fail", log::error);
        print_error_message(ret);
        throw runtime_error("ra_init failed.");
    }
}
RAContext::~RAContext(){
    auto status = sgx_status_t{};

    if (INT_MAX != context) {
        int ret = ra_close(enclave->getID(), &status, context);
        if (SGX_SUCCESS != ret || status) {
            Log("Error, call enclave_ra_close fail", log::error);
        }

        Log("Call enclave_ra_close success");
    }

}

sgx_ra_context_t RAContext::getContext() {
    return this->context;
}

sgx_ra_msg1_t RAContext::generateMSG1(sgx_ecall_get_ga_trusted_t ra_get_ga) {
    int retGIDStatus = 0;
    int count = 0;
    sgx_ra_msg1_t sgxMsg1Obj;

    while (1) {
        retGIDStatus = sgx_ra_get_msg1(getContext(),
                                       enclave->getID(),
                                       ra_get_ga,
                                       &sgxMsg1Obj);

        if (retGIDStatus == SGX_SUCCESS) {
            break;
        } else if (retGIDStatus == SGX_ERROR_BUSY) {
            if (count == 5) { //retried 5 times, so fail out
                Log("Error, sgx_ra_get_msg1 is busy - 5 retries failed", log::error);
                break;;
            } else {
                sleep(3);
                count++;
            }
        } else {    //error other than busy
            Log("Error, failed to generate MSG1", log::error);
            break;
        }
    }
    if (SGX_SUCCESS != retGIDStatus) 
      throw runtime_error("generateMSG1 failed");

    return sgxMsg1Obj;
}

string RAContext::proc_msg2(sgx_ra_msg2_t *p_msg2, uint32_t msg2_size, sgx_ecall_proc_msg2_trusted_t p_proc_msg2,
    sgx_ecall_get_msg3_trusted_t p_get_msg3) {
    sgx_ra_msg3_t *p_msg3 = NULL;
    uint32_t msg3_size;
    int ret = 0;

    int busy_retry_time = 4;
    do {
        ret = sgx_ra_proc_msg2(getContext(),
                               enclave->getID(),
                               p_proc_msg2,
                               p_get_msg3,
                               p_msg2,
                               msg2_size,
                               &p_msg3,
                               &msg3_size);
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
    if(ret != SGX_SUCCESS) {
        throw runtime_error(string{"Error, call sgx_ra_proc_msg2 fail, error code: "} + to_string(ret));
    }
    auto reply = string{reinterpret_cast<const char*>(p_msg3), msg3_size};
    return move(reply);
}
