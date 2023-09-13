#include <stdarg.h>
#include <stdio.h>

#include <assert.h>
#include "onesided_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"
#include "mbedtls/entropy.h"
#include "sgx_trts.h"
#include "sgx_utils.h"
#include "IASReport.h"

#include "UtilityFunctions.h"
#include "LogSgx.h"
#include "mbedtls/glue.h"
#include <stdexcept>
#include "sgx_lfence.h"
constexpr size_t element_size = 128/8; //4096;
constexpr size_t size_inc = 0; // 16
template <typename T>
void clear(T &t){
  memset_s(&t,sizeof(t),0,sizeof(T));
}
template <typename T>
void hexdump(T &t){
  auto readout = reinterpret_cast<const uint8_t*>(&t);
  for(int i = 0; i < sizeof(T); i++){
    printf_sgx("%02x", readout[i]);
  }
  printf_sgx("\n");
}
struct ECCState {
  sgx_ecc_state_handle_t ecc_state = nullptr;
  sgx_status_t status = SGX_SUCCESS;
  ECCState(){
   auto se_ret = sgx_ecc256_open_context(&ecc_state);
   if(se_ret != SGX_SUCCESS){
     if(SGX_ERROR_OUT_OF_MEMORY != se_ret)
       status = SGX_ERROR_UNEXPECTED;
     else
       status = se_ret;
   }
  }
  operator bool() const{
    return status == SGX_SUCCESS;
  }
  explicit operator sgx_status_t() const {
    return status;
  }
  ~ECCState(){
    if(ecc_state != nullptr){
      sgx_ecc256_close_context(ecc_state);
    }
  }
};
sgx_quote_nonce_t nonce = {};
sgx_quote_nonce_t other_enclave = {};
sgx_ec256_private_t priv_key = {};
sgx_ec256_dh_shared_t dh_key = {};
int state = 0;
int role = -1;
sgx_status_t SGXAPI init_onesided_nonce(sgx_quote_nonce_t *out_nonce){
  if(state != 0){
    return SGX_ERROR_UNEXPECTED;
  }
  state++;
  sgx_lfence();
  if(SGX_SUCCESS != sgx_read_rand(reinterpret_cast<uint8_t*>(&nonce), sizeof(nonce))){
    throw runtime_error("cannot read rand");
  }
  *out_nonce = nonce;
}
sgx_status_t SGXAPI init_onesided(uint8_t *mrenclave, sgx_quote_nonce_t *othernonce, sgx_ec256_public_t *ga, int role_in, const sgx_target_info_t *p_qe_target, sgx_report_t *p_report) {
  if(state != 1){
    return SGX_ERROR_UNEXPECTED;
  }
  state++;
  sgx_lfence();

  sgx_status_t se_ret = {};
  
  sgx_report_data_t report_data = {};
  sgx_ec256_public_t pub_key = {};
  ECCState state;
  if(!state){
    return sgx_status_t(state);
  }
  role = role_in;
  se_ret = sgx_ecc256_create_key_pair(&priv_key, &pub_key, state.ecc_state);
  if (SGX_SUCCESS != se_ret) {
    if(SGX_ERROR_OUT_OF_MEMORY != se_ret)
      se_ret = SGX_ERROR_UNEXPECTED;
    return se_ret;
  }
  
  *ga = pub_key;
  other_enclave = *othernonce;
  sha256 sha = {};
  sha.add(reinterpret_cast<uint8_t*>(&nonce), sizeof(nonce));
  sha.add(reinterpret_cast<uint8_t*>(&pub_key), sizeof(pub_key));
  sha.add(reinterpret_cast<uint8_t*>(&role), sizeof(role));
  sha.hash(reinterpret_cast<sgx_sha256_hash_t*>(&report_data));
  clear(pub_key);
  se_ret = sgx_create_report(p_qe_target, &report_data, p_report);
  return se_ret;
}

sgx_status_t SGXAPI finish_kex(sgx_ec256_public_t *go, const char* report, const char* signature) {
  if(state != 2){
    return SGX_ERROR_UNEXPECTED;
  }
  state++;
  sgx_lfence();
  sgx_report_data_t report_data = {};
  sha256 sha = {};
  sha.add(reinterpret_cast<uint8_t*>(&other_enclave), sizeof(other_enclave));
  sha.add(reinterpret_cast<uint8_t*>(go), sizeof(*go));
  int other_role = 1-role;
  sha.add(reinterpret_cast<uint8_t*>(&other_role), sizeof(other_role));
  sha.hash(reinterpret_cast<sgx_sha256_hash_t*>(&report_data));
  auto ireport = IASReport{{report}, {signature}};
  ireport.verify(report_data);
  ECCState state;
  if(!state){
    return sgx_status_t(state);
  }
  int valid = 0;
  // We have already validated the report but better safe than sorry
  auto ret = sgx_ecc256_check_point(go, state.ecc_state, &valid);
  if(ret != SGX_SUCCESS || !valid){
    return SGX_ERROR_INVALID_PARAMETER;
  }
  ret = sgx_ecc256_compute_shared_dhkey(&priv_key,
        go,
        &dh_key, state.ecc_state);
  if(ret != SGX_SUCCESS){
    return ret;
  }
  clear(priv_key);

  return SGX_SUCCESS;
}

sgx_status_t SGXAPI setInput(const unsigned char *elems, unsigned char *elems_out, int n_elems, const sgx_target_info_t *p_qe_target, sgx_report_t *p_report){
  if(state != 3 || role != 0){
    return SGX_ERROR_UNEXPECTED;
  }
  if(!sgx_is_outside_enclave(elems, (element_size + size_inc) * n_elems) || !sgx_is_outside_enclave(elems_out, (element_size + 2*size_inc) * n_elems) )
    return SGX_ERROR_INVALID_PARAMETER;
  state++;
  sgx_lfence();
  auto det = aes256det{reinterpret_cast<uint8_t*>(&dh_key), 128};
  if(size_inc == 0){
      det.crypt_block(elems, elems_out, n_elems*16);
  }else{
    for(int i = 0; i < n_elems; i++){
      det.crypt(elems + (element_size + size_inc)*i, elems_out + (element_size + 2*size_inc)*i, element_size + size_inc);
    }
  }

  auto report_data = sgx_report_data_t{};
  auto se_ret = sgx_create_report(p_qe_target, &report_data, p_report);
  return se_ret;
}
sgx_status_t SGXAPI releaseKey(unsigned char *out){
  if(state != 3 || role != 1){
    return SGX_ERROR_UNEXPECTED;
  }
  state++;
  sgx_lfence();
  memcpy(out, &dh_key, 16);
  return SGX_SUCCESS;
}
constexpr bool keepDataInEnclave = false;
sha256hash chash = {};
unsigned char *inElems;
sgx_status_t SGXAPI commit(const unsigned char *elems, int n_elems) {
  if(state != 4 || role != 1){
    return SGX_ERROR_UNEXPECTED;
  }
  state++;
  sgx_lfence();
  if(keepDataInEnclave){
    inElems = reinterpret_cast<unsigned char *>(malloc(n_elems * (element_size+3*size_inc)));
    memcpy(inElems, elems, n_elems * (element_size+3*size_inc));
  }else{
    sha256 sha;
    sha.add(elems, n_elems * (element_size+3*size_inc));
    sha.hash(reinterpret_cast<uint8_t*>(&chash));
  }
  // auto report_data = sgx_report_data_t{};
  // auto se_ret = sgx_create_report(p_qe_target, &report_data, p_report);
  return SGX_SUCCESS;
}

sgx_status_t SGXAPI do_uhf(const unsigned char *elems, uint64_t *hashes, uint64_t *uhf, int n_elems, const sgx_target_info_t *p_qe_target, sgx_report_t *p_report) {
  if(state != 5 || role != 1){
    return SGX_ERROR_UNEXPECTED;
  }
  state++;
  sgx_lfence();
  uint8_t elem[element_size+3*size_inc] = {};
  sha256 sha_check;
  sha256 sha_ucheck;
  
  uint64_t muhf;
  if(SGX_SUCCESS != sgx_read_rand(reinterpret_cast<uint8_t*>(&muhf), sizeof(muhf))){
    throw runtime_error("cannot read rand");
  }
  *uhf = muhf;
  sha_ucheck.add(reinterpret_cast<uint8_t*>(&muhf), sizeof(muhf));

  
  auto uf = UHF{std::vector<uint64_t>{muhf}};
  for(int i = 0; i < n_elems; i++){
    uint64_t hash;
    if(keepDataInEnclave){
      hash = uf.hash(inElems + sizeof(elem)*i, sizeof(elem));
    }else{
      memcpy(elem, elems + sizeof(elem)*i, sizeof(elem));
      sha_check.add(elem, sizeof(elem));
      hash = uf.hash(elem, sizeof(elem));
    }
    sha_ucheck.add(reinterpret_cast<uint8_t*>(&hash), sizeof(hash));
    hashes[i] = hash;
  }
  if(!keepDataInEnclave){
    sha256hash chash2 = {};
    sha_check.hash(reinterpret_cast<uint8_t*>(&chash2));
    if(compare_sha256(chash, chash2) != 0) {
      return SGX_ERROR_UNEXPECTED;
    }
  }
  auto report_data = sgx_report_data_t{};
  sha_ucheck.hash(reinterpret_cast<uint8_t*>(&report_data));
  auto se_ret = sgx_create_report(p_qe_target, &report_data, p_report);
  return se_ret;
}
