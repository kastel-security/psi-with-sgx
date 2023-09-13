#pragma once

#include <sstream>
#include <string>
#include <vector>

#include "sgx_error.h"
#include "Base64.h"

using namespace std;

#define FILE_UUID_LENGTH 32

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

void print_error_message(sgx_status_t ret);

void SafeFree(void *ptr);

string GetRandomString();

string ByteArrayToString(const uint8_t *arr, int size);
string ByteArrayToStringNoFill(const uint8_t *arr, int size);
int StringToByteArray(string str, uint8_t **arr);
string ByteArrayToNoHexString(const uint8_t *arr, int size);
string UIntToString(uint32_t *arr, int size);
int HexStringToByteArray(string str, uint8_t **arr);

int ReadFileToBuffer(string filePath, uint8_t **content);
int ReadFileToBuffer(string filePath, char **content);
int SaveBufferToFile(string filePath, string content);
int RemoveFile(string filePath);

string Base64encode(const string val);
string Base64decode(const string val);
string Base64encodeUint8(uint8_t *val, uint32_t len);

string toHex(string target);

template<int size>
string BytesToString(const uint8_t (&array)[size]){
    return string(reinterpret_cast<const char*>(array), size* sizeof(uint8_t));
}

template<int size>
string BytesToString(const uint32_t (&array)[size]){
    return string(reinterpret_cast<const char*>(array), size * sizeof(uint32_t));
}
void store_bytes(const string &bytes, void *target, size_t target_length);

template<int size>
void store_bytes(const string &bytes, uint8_t (&array)[size]){
    store_bytes(bytes, reinterpret_cast<void*>(array), size * sizeof(uint8_t));
}
template<int size>
void store_bytes(const string &bytes, uint32_t (&array)[size]){
    store_bytes(bytes, reinterpret_cast<void*>(array), size * sizeof(uint32_t));
}

string BytesToString(const uint8_t *array, size_t len);

#ifdef ENCLAVE
#include "mbedtls/glue.h"
#include "sgx_tcrypto.h"
class sha256 {
    sgx_sha_state_handle_t state;
public:
    sha256(){
        if(sgx_sha256_init(&state) != SGX_SUCCESS){
            throw "init failed";
        }
    }
    ~sha256(){
        sgx_sha256_close(state);
    }
    void operator<<(const std::string &data){
        add(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }
    void add(const uint8_t *data, size_t len){
      size_t block_max = 1u << 30;
      while(len > block_max){
        if(sgx_sha256_update(data, block_max, state) != SGX_SUCCESS){
            throw "update failed";
        }
	data += block_max;
	len -= block_max;
      }
      if(sgx_sha256_update(data, len, state) != SGX_SUCCESS){
	throw "update failed";
      }
    }
    void hash(uint8_t *target){
        hash(reinterpret_cast<sgx_sha256_hash_t *>(target));
    }
    void hash(sgx_sha256_hash_t *target){
        if(sgx_sha256_get_hash(state, target) != SGX_SUCCESS){
            throw "final failed";
        }
    }
};
#include <mbedtls/aes.h>
class aes256det {
public:
  mbedtls_aes_context ctx;
  sgx_aes_ctr_128bit_key_t key;
  sgx_cmac_state_handle_t cmac = {};
  aes256det(const unsigned char* key, size_t length_bits);
  ~aes256det();
  // out needs to have at least len+16
  void crypt(const unsigned char *in, unsigned char *out, size_t len);
  void decrypt(const unsigned char *in, unsigned char *out, size_t len);
  void crypt_block(const unsigned char *in, unsigned char *out, size_t len);
};

#else
#ifdef MBEDTLS_SHA256
#include "mbedtls/sha256.h"
class sha256 {
public:
    mbedtls_sha256_context sha_handle = {};
    sha256(){
        mbedtls_sha256_init (&sha_handle);
        mbedtls_sha256_starts_ret(&sha_handle, false);
    }
    ~sha256(){
        mbedtls_sha256_free(&sha_handle);
    }
    void operator<<(const std::string &data){
        add(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }
    void add(const uint8_t *data, size_t length){
        if (mbedtls_sha256_update_ret(&sha_handle, data, length) != 0) {
            throw std::runtime_error("sha256 update failed");
        }
    }
    void hash(uint8_t *target){
        if (mbedtls_sha256_finish_ret(&sha_handle, target) != 0) {
            throw std::runtime_error("sha256 get hash failed");
        }
    }

};
#else

#include <openssl/sha.h>
class sha256 {
public:
  SHA256_CTX ctx = {};
  sha256(){
        SHA256_Init(&ctx);
    }
    ~sha256(){
    }
    void operator<<(const std::string &data){
        add(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }
    void add(const uint8_t *data, size_t length){
        if (SHA256_Update(&ctx, data, length) != 1) {
            throw std::runtime_error("sha256 update failed");
        }
    }
    void hash(uint8_t *target){
        if (SHA256_Final(target, &ctx) != 1) {
            throw std::runtime_error("sha256 get hash failed");
        }
    }

};
#endif
#include <memory>
class aes256det {
public:
  static std::unique_ptr<aes256det> create(const unsigned char* key, size_t length_bits);
  // out needs to have at least len+16
  virtual void crypt(const unsigned char *in, unsigned char *out, size_t len) = 0;
  virtual void crypt_block(const unsigned char *in, unsigned char *out, size_t len) = 0;
  virtual void decrypt(const unsigned char *in, unsigned char *out, size_t len) = 0;
};
#endif


struct sha256hash {
    uint8_t data[32];
};
int compare_sha256(const sha256hash &a, const sha256hash &b);


#ifndef ENCLAVE
#include <chrono>
struct TimerCounter {
  float value = 0;
};
class Timer {
  std::chrono::steady_clock::time_point start;
  string name;
  TimerCounter *counter = nullptr;
public:
  Timer(TimerCounter *counter);
  Timer(const string &name);
  float operator() ();
  ~Timer();
};
#else
#include "mbedtls/glue.h"
#endif

/*class UHF {
  uint64_t mult;
public:
  UHF(uint64_t mult) : mult(mult) {
  }
  uint64_t hash(uint8_t *data, size_t size){
    if(size % 8 != 0 ){
      throw std::runtime_error("size should be divisible by 4");
    }
    uint64_t *d = reinterpret_cast<uint64_t *>(data);
    size_t sz = size / 8;
    uint64_t hash = 0;
    for(size_t i = 0; i < sz; i++) {
      hash = hash * mult + d[i];
    }
    return hash;
  }
  };*/
#ifdef UHF_MULT
class UHF {
  static constexpr uint64_t mask =  0xFFFFFFFFFFFFFFul;
  static constexpr uint64_t mask_lower =  0xFFFFFFFFul;
  std::vector<uint64_t> mult;
public:
  static constexpr uint64_t prime = 0x100000000000051ul;
  UHF(std::vector<uint64_t> mult) : mult(mult) {
  }
  uint64_t mmult(uint64_t a, uint64_t d){
    uint64_t lower = (d & mask_lower) * (a & mask_lower);
    uint64_t mid = (d >> 32) * (a & mask_lower);
    uint64_t mid2 = (d & mask_lower) * (a >> 32);
    mid %= prime;
    mid2 %= prime;
    mid += mid2;
    uint64_t upper = (d >> 32) * (a >> 32);
    mid <<= 32;
    mid %= prime;
    lower %= prime;
    lower += mid;
    upper %= prime;
    upper += mid >> 32;
    upper %= prime;

    for(int i = 0; i < 64/7; i++){
      upper <<= 7;
      upper %= prime;
    }
    upper <<= 1;
    lower += upper;
    lower %= prime;
    return lower;
  }
  uint64_t hash(uint8_t *data, size_t size){
    if(size < 8){
      throw std::runtime_error("size should be divisible by 4");
    }
    if(mult.size() * 7 < size ){
      throw std::runtime_error("size should be divisible by 4");
    }
    size_t sz = size / 7;
    uint64_t hash = 0;
    for(size_t i = 0; i < sz; i++) {
      uint64_t d = (*reinterpret_cast<uint64_t *>(data + i*7) & mask);
      uint64_t a = mult[i];
      hash += mmult(a,d);
      hash %= prime;
    }
    if(size / 7 != 0){
      uint64_t rem = *reinterpret_cast<uint64_t *>(data + size - 8) >> (64 - ( (size%7) * 8));
      hash += mmult(rem, mult[sz]);
    }
    return hash;
  }
};
#else
#define XXH_PRIVATE_API
#define XXH_STATIC_LINKING_ONLY
#define XXH_IMPLEMENTATION
#include "xxhash.h"
class UHF {
  uint64_t seed;
public:
  UHF(std::vector<uint64_t> mult) : seed(mult[0]) {
  }
  uint64_t hash(uint8_t *data, size_t size){
    return XXH3_64bits_withSeed(data, size, seed);
  }

};
#endif
