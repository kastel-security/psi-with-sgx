#include "UtilityFunctions.h"

#include <iostream>
#include <iomanip>
#include <sstream>

#ifndef ENCLAVE
#include <fstream>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/remove_whitespace.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "sgx_urts.h"
using namespace boost::archive::iterators;
using boost::lexical_cast;
using boost::uuids::uuid;
using boost::uuids::random_generator;
#endif


#ifdef ENCLAVE
#include "LogSgx.h"
#else
#include "LogBase.h"
using namespace util;
#endif

using namespace std;

void SafeFree(void *ptr) {
    if (NULL != ptr) {
        free(ptr);
        ptr = NULL;
    }
}


#ifdef ENCLAVE
string GetRandomString() {
    throw runtime_error("... without lexical cast..");
}
#else
string GetRandomString() {
    string str = lexical_cast<string>((random_generator())());
    str.erase(remove(str.begin(), str.end(), '-'), str.end());

    return str;
}

int SaveBufferToFile(string filePath, string content) {
    std::ofstream out(filePath);
    out << content;
    out.close();
    return 0;
}


int ReadFileToBuffer(string filePath, char **content) {
    ifstream t(filePath);
    string str((istreambuf_iterator<char>(t)), istreambuf_iterator<char>());

    *content = (char*) malloc(sizeof(char) * (str.size()+1));
    memset(*content, '\0', (str.size()+1));
    str.copy(*content, str.size());

    return str.size();
}


int ReadFileToBuffer(string filePath, uint8_t **content) {
    ifstream file(filePath, ios::binary | ios::ate);
    streamsize file_size = file.tellg();

    file.seekg(0, ios::beg);

    std::vector<char> buffer(file_size);

    if (file.read(buffer.data(), file_size)) {
        string str(buffer.begin(), buffer.end());

        vector<uint8_t> vec(str.begin(), str.end());

        *content = (uint8_t*) malloc(sizeof(uint8_t) * vec.size());
        copy(vec.begin(), vec.end(), *content);

        return str.length();
    }

    return -1;
}


int RemoveFile(string filePath) {
    if (remove(filePath.c_str()) != 0 ) {
        Log("Error deleting file: " + filePath);
        return 1;
    } else
        Log("File deleted successfully: " + filePath);

    return 0;
}


string ByteArrayToString(const uint8_t *arr, int size) {
    ostringstream convert;

    for (int a = 0; a < size; a++) {
        convert << setfill('0') << setw(2) << hex << (unsigned int)arr[a];
    }

    return convert.str();
}


string ByteArrayToStringNoFill(const uint8_t *arr, int size) {
    ostringstream convert;

    for (int a = 0; a < size; a++) {
        convert << hex << (int)arr[a];
    }

    return convert.str();
}

string toHex(string target) {
    ostringstream convert;

    for (char &c: target) {
        convert << setfill('0') << setw(2) << hex << (unsigned int) (c&0xFF);
    }

    return convert.str();
}



string ByteArrayToNoHexString(const uint8_t *arr, int size) {
    std::ostringstream convert;

    for (int a = 0; a < size; a++) {
        convert << (uint8_t)arr[a];
    }

    return convert.str();
}


string UIntToString(uint32_t *arr, int size) {
    stringstream ss;

    for (int i=0; i<size; i++) {
        ss << arr[i];
    }

    return ss.str();
}

#endif


int HexStringToByteArray(string str, uint8_t **arr) {
    vector<uint8_t> bytes;

    for (unsigned int i=0; i<str.length(); i+=2) {
        string byteString = str.substr(i, 2);
        char byte = (char) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back((unsigned char)byte);
    }

    *arr = (uint8_t*) malloc(sizeof(uint8_t) * bytes.size());
    copy(bytes.begin(), bytes.end(), *arr);

    return bytes.size();
}


int StringToByteArray(string str, uint8_t **arr) {
    vector<uint8_t> vec(str.begin(), str.end());

    *arr = (uint8_t*) malloc(sizeof(uint8_t) * vec.size());
    copy(vec.begin(), vec.end(), *arr);

    return vec.size();
}




static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_MODE_INCOMPATIBLE,
        "Target enclave mode is incompatible with the mode of the current RTS",
        NULL
    },
    {
        SGX_ERROR_SERVICE_UNAVAILABLE,
        "sgx_create_enclave() needs the AE service to get a launch token",
        NULL
    },
    {
        SGX_ERROR_SERVICE_TIMEOUT,
        "The request to the AE service timed out",
        NULL
    },
    {
        SGX_ERROR_SERVICE_INVALID_PRIVILEGE,
        "The request requires some special attributes for the enclave, but is not privileged",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as a product enclave and cannot be created as a debuggable enclave",
        NULL
    },
    {
        SGX_ERROR_UNDEFINED_SYMBOL,
        "The enclave contains an import table",
        NULL
    },
    {
        SGX_ERROR_INVALID_MISC,
        "The MiscSelct/MiscMask settings are not correct",
        NULL
    },
    {
        SGX_ERROR_MAC_MISMATCH,
        "The input MAC does not match the MAC calculated",
        NULL
    }
};


void print_error_message(sgx_status_t ret) {
    size_t idx = 0;
    size_t ttl = sizeof(sgx_errlist)/sizeof (sgx_errlist[0]);

    for (idx = 0; idx < ttl; idx++) {
        if (ret == sgx_errlist[idx].err) {
            if (NULL != sgx_errlist[idx].sug)
                Log("%s", sgx_errlist[idx].sug);

            Log("%s", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        Log("Unexpected error occurred");
}


string Base64decode(const string val) {
    return base64_decode(val);
}


string Base64encodeUint8(uint8_t *val, uint32_t len) {
    return base64_encode(val, len);
}


void store_bytes(const string &bytes, void *target, size_t target_length){
    if(bytes.size() < target_length){
        throw runtime_error("to few bytes in field");
    }
    memcpy(target, bytes.data(), target_length);
}
string BytesToString(const uint8_t *array, size_t len){
    return string(reinterpret_cast<const char*>(array), len);
}

int compare_sha256(const sha256hash &a, const sha256hash &b){
    for(int i = 0; i < sizeof(sha256hash); i++){
        const uint8_t &a_b = a.data[i];
        const uint8_t &b_b = b.data[i];
        if(a_b < b_b){
            return -1;
        }
        if(a_b > b_b){
            return 1;
        }
    }
    return 0;
}

#ifndef ENCLAVE
#include <chrono>
Timer::Timer(TimerCounter *counter) : counter(counter) {
    start = std::chrono::steady_clock::now();
}  
Timer::Timer(const string &name) : name(name){
    start = std::chrono::steady_clock::now();
}
float Timer::operator() (){
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count() / 1000.0f;
}
Timer::~Timer(){
  if(counter){
    counter->value += (*this)();
  } else {
    Log(" %s: %dms", name, std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count());
  }
}
#endif

// true:  211.9 M/s
// false: 192.3 M/s
constexpr bool USE_SHA256_FOR_DET = false;
#ifdef ENCLAVE
#include <mbedtls/aes.h>
#include <mbedtls/aesni.h>
aes256det::aes256det(const unsigned char* key, size_t length_bits) {
  if(length_bits != 128){
    throw "wrong length";
  }
  memcpy(this->key, key, sizeof(this->key));
  // sgx_cmac128_init(static_cast<sgx_cmac_128bit_key_t*>(&this->key), &cmac);
  mbedtls_aes_init (&ctx);
  mbedtls_aes_setkey_enc(&ctx, key, length_bits);
}
aes256det::~aes256det(){
  //sgx_cmac128_close(cmac);
    mbedtls_aes_free(&ctx);
}
void aes256det::crypt(const unsigned char *in, unsigned char *out, size_t len){
  uint8_t hash[32] = {};
  if(USE_SHA256_FOR_DET){
    sha256 sha;
    sha.add(in, len);
    sha.hash(hash);
  } else {
    sgx_cmac128_init(static_cast<sgx_cmac_128bit_key_t*>(&this->key), &cmac);
    sgx_cmac128_update(in, len, cmac);
    sgx_cmac128_final(cmac, reinterpret_cast<sgx_cmac_128bit_tag_t*>(&hash));
    sgx_cmac128_close(cmac);
  }
  memcpy(out, hash, 16);
  sgx_aes_ctr_encrypt(&key, in, len, hash, 128, out + 16);
}
void aes256det::crypt_block(const unsigned char *in, unsigned char *out, size_t len) {
  for(size_t i = 0; i < len; i += 16){
    mbedtls_aesni_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in + i, out + i);
  }
}
void aes256det::decrypt(const unsigned char *in, unsigned char *out, size_t len){
  auto nc_off = size_t{0};
  uint8_t stream_block[16] = {};
  uint8_t nonce[16];
  memcpy(nonce, in, 16);
  sgx_aes_ctr_encrypt(&key, in + 16, len, nonce, 128, out);

  uint8_t hash[32];
  if(USE_SHA256_FOR_DET){
    sha256 sha;
    sha.add(out, len);
    sha.hash(hash);
  } else {
    sgx_cmac_state_handle_t cmac = {};
    sgx_cmac128_init(static_cast<sgx_cmac_128bit_key_t*>(&this->key), &cmac);
    sgx_cmac128_update(out, len, cmac);
    sgx_cmac128_final(cmac, reinterpret_cast<sgx_cmac_128bit_tag_t*>(&hash));
    sgx_cmac128_close(cmac);
  }
  if(memcmp(hash, in, 16) != 0){
    throw std::runtime_error("IV mismatch");
  }
}
#else
#include <mbedtls/cmac.h>
#include <mbedtls/cipher.h>
#include <mbedtls/aes.h>
class mbedtls_aes256det : public aes256det {
  mbedtls_aes_context ctx;
  mbedtls_cipher_context_t cmac = {};
public:
  mbedtls_aes256det(const unsigned char* key, size_t length_bits){
    mbedtls_aes_init (&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, length_bits);
    if(!USE_SHA256_FOR_DET){
      auto cipher_info = mbedtls_cipher_info_from_type( MBEDTLS_CIPHER_AES_128_ECB );
      mbedtls_cipher_init(&cmac);
      mbedtls_cipher_setup(&cmac, cipher_info );
      mbedtls_cipher_cmac_starts (&cmac, key, 128);
    }
  }
  ~mbedtls_aes256det(){
    mbedtls_aes_free(&ctx);
    if(!USE_SHA256_FOR_DET){
      mbedtls_cipher_free(&cmac);
    }
  }
  virtual void crypt_block(const unsigned char *in, unsigned char *out, size_t len) {
    if(len != 16){
      throw std::runtime_error("length mismatch");
    }
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out);
  }
  // out needs to have at least len+16
  virtual void crypt(const unsigned char *in, unsigned char *out, size_t len) {
    uint8_t hash[32] = {};
    if(USE_SHA256_FOR_DET){
      sha256 sha;
      sha.add(in, len);
      sha.hash(hash);
    } else {
      mbedtls_cipher_cmac_update (&cmac, in, len);
      mbedtls_cipher_cmac_finish(&cmac, hash);
      mbedtls_cipher_cmac_reset(&cmac);
    }
    auto nc_off = size_t{0};
    uint8_t stream_block[16] = {};
    memcpy(out, hash, 16);
    mbedtls_aes_crypt_ctr(&ctx, len, &nc_off, hash, stream_block, in, out + 16);
  }
  virtual void decrypt(const unsigned char *in, unsigned char *out, size_t len){
    auto nc_off = size_t{0};
    uint8_t stream_block[16] = {};
    uint8_t nonce[16];
    memcpy(nonce, in, 16);
    mbedtls_aes_crypt_ctr(&ctx, len, &nc_off, nonce, stream_block, in + 16, out);
    
    uint8_t hash[32];
    if(USE_SHA256_FOR_DET){
      sha256 sha;
      sha.add(out, len);
      sha.hash(hash);
    } else {
      mbedtls_cipher_cmac_update (&cmac, out, len);
      mbedtls_cipher_cmac_finish(&cmac, hash);
      mbedtls_cipher_cmac_reset(&cmac);
    }
    if(memcmp(hash, in, 16) != 0){
      throw std::runtime_error("IV mismatch");
    }
  }
};
#include <openssl/evp.h>
#include <openssl/cmac.h>
#ifdef flexsize
class ossl_aes256det : public aes256det {
  EVP_CIPHER_CTX *ctx;
  CMAC_CTX *cmac;
  CMAC_CTX *cmac_tmp;
  uint8_t key[16];
public:
  ossl_aes256det(const unsigned char* key, size_t length_bits){
    ctx = EVP_CIPHER_CTX_new();
    memcpy(this->key, key, 16);
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, this->key, nullptr);
    if(!USE_SHA256_FOR_DET){
      cmac = CMAC_CTX_new();
      CMAC_Init(cmac, key, 16,
		EVP_aes_128_cbc(), NULL);
      cmac_tmp = CMAC_CTX_new();
      CMAC_CTX_copy(cmac_tmp, cmac);

    }
  }
  ~ossl_aes256det(){
    EVP_CIPHER_CTX_free(ctx);
    if(!USE_SHA256_FOR_DET){
      CMAC_CTX_free(cmac);
      CMAC_CTX_free(cmac_tmp);
    }
  }
  void CMAC_CTX_copy_hack(CMAC_CTX *to, CMAC_CTX *from) {

    struct CMAC_CTX_st_int {
    /* Cipher context to use */
    EVP_CIPHER_CTX *cctx;
    /* Keys k1 and k2 */
    unsigned char k1[EVP_MAX_BLOCK_LENGTH];
    unsigned char k2[EVP_MAX_BLOCK_LENGTH];
    /* Temporary block */
    unsigned char tbl[EVP_MAX_BLOCK_LENGTH];
    /* Last (possibly partial) block */
    unsigned char last_block[EVP_MAX_BLOCK_LENGTH];
    /* Number of bytes in last block: -1 means context not initialised */
    int nlast_block;
    };
    memcpy(reinterpret_cast<uint8_t*>(to) + sizeof(int*), reinterpret_cast<uint8_t*>(from) + sizeof(int *), sizeof(CMAC_CTX_st_int) - sizeof(int *));
    //std::cout << (long long int) &((struct CMAC_CTX_st_int*)from)->nlast_block << ";" << (long long int) (reinterpret_cast<uint8_t*>(from) + sizeof(EVP_CIPHER_CTX*) + 4*EVP_MAX_BLOCK_LENGTH) << "\n";
    //std::cout << sizeof(struct CMAC_CTX_st_int) << ";" << sizeof(EVP_CIPHER_CTX*) + 4*EVP_MAX_BLOCK_LENGTH + sizeof(int) << "\n";
  }
  // out needs to have at least len+16
  virtual void crypt(const unsigned char *in, unsigned char *out, size_t len) {
    uint8_t hash[32] = {};
    if(USE_SHA256_FOR_DET){
      sha256 sha;
      sha.add(in, len);
      sha.hash(hash);
    } else {
      CMAC_CTX_copy(cmac_tmp, cmac);
      CMAC_Update(cmac_tmp, in, len);
      auto nc_off = size_t{0};
      CMAC_Final(cmac_tmp, hash, &nc_off);
    }
    auto nc_off = int{0};
    uint8_t stream_block[16] = {};
    memcpy(out, hash, 16);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, hash);
    EVP_EncryptUpdate(ctx, out + 16, &nc_off, in, len);
  }
  virtual void decrypt(const unsigned char *in, unsigned char *out, size_t len){
    throw std::runtime_error("Not implemented");
  }
  virtual void crypt_block(const unsigned char *in, unsigned char *out, size_t len) {
    throw std::runtime_error("Not implemented");
  }
};
#else
class ossl_aes256det : public aes256det {
  EVP_CIPHER_CTX *ctx;
  uint8_t key[16];
public:
  ossl_aes256det(const unsigned char* key, size_t length_bits){
    ctx = EVP_CIPHER_CTX_new();
    memcpy(this->key, key, 16);
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, this->key, nullptr);
  }
  ~ossl_aes256det(){
    EVP_CIPHER_CTX_free(ctx);
  }
  virtual void crypt(const unsigned char *in, unsigned char *out, size_t len) {
    throw std::runtime_error("Not implemented");
  }
  virtual void decrypt(const unsigned char *in, unsigned char *out, size_t len){
    throw std::runtime_error("Not implemented");
  }
  virtual void crypt_block(const unsigned char *in, unsigned char *out, size_t len) {
    int len_out = 16;
    EVP_EncryptUpdate(ctx, out, &len_out, in, len);
  }
};
#endif
std::unique_ptr<aes256det> aes256det::create(const unsigned char* key, size_t length_bits){
  //return std::make_unique<mbedtls_aes256det>(key, length_bits);
  return std::make_unique<ossl_aes256det>(key, length_bits);
}
#endif
