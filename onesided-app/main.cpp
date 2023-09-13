#include <iostream>
#include "Enclave.h"
#include "Report.h"
#include "WebService.h"
#include "onesided_u.h"
// #include "isv_enclave_u.h"
#include "../GeneralSettings.h"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <openssl/rand.h>
#include "networking.h"
#include "radixsort.h"
#include <thread>

#ifdef TEST_HASH_ONLY
void testHashingAttestation(){
  Enclave e("hash-enclave.signed.so");
  auto ws = WebService::getInstance();

  Report r;
  r.fetchSigRL(*ws);
        
  size_t set_size = 3;

  sgx_status_t inner_res;
  vector<uint8_t> list(32 * set_size);
  for(size_t i = 0; i < set_size; i++){
    *reinterpret_cast<uint32_t*>(&list[i*32]) = i+1;
  }
  vector<uint8_t> index_out(4 * set_size);
  vector<uint8_t> out(32 * set_size);
  sgx_quote_nonce_t nonce = {};
  e.call<prepareInput>(set_size,
				  list.data(), index_out.data(), out.data(), r.target_info(), r.report(), &nonce);
  r.generateQuote(Settings::spid);
  auto ias_report = r.submitReport( *ws);

}
#endif
#ifdef flexsize
constexpr size_t size_inc = 16;
constexpr size_t element_size = 128;//4096;
constexpr size_t element3_size = element_size + 3 * 16;
typedef uint8_t element[element_size];
typedef uint8_t crypted_element[element_size+16];
typedef uint8_t crypted2_element[element_size+2*16];
typedef uint8_t crypted3_element[element_size+3*16];
#else
constexpr size_t size_inc = 0;
constexpr size_t element_size = 128/8;//4096;
constexpr size_t element3_size = element_size;
typedef uint8_t element[element_size];
typedef uint8_t crypted_element[element_size];
typedef uint8_t crypted2_element[element_size];
typedef uint8_t crypted3_element[element_size];
#endif

class crypted3_element_cls {
  uint8_t data[element3_size];
public:
  int operator <(const crypted3_element_cls &other){
    for(int i = 0; i < sizeof(data)/8; i++){
      
    }
    if(data[0] < other.data[0]){
      return 0;
    }
    if(data[0] > other.data[0]){
      return 1;
    }
    return 0;
  }
};
template<typename T>
struct crypted_type {
};
template<>
struct crypted_type<element> {
  typedef crypted_element value;
};
#ifdef flexsize
template<>
struct crypted_type<crypted_element> {
  typedef crypted2_element value;
};
template<>
struct crypted_type<crypted2_element> {
  typedef crypted3_element value;
};
#endif

#ifdef flexsize
template<typename T1>
std::vector<typename crypted_type<T1>::value> transform(aes256det &det, std::vector<T1> &vec) {
  using T2 = typename crypted_type<T1>::value;
  static_assert(sizeof(T2) == sizeof(T1) + 16);
  auto out = std::vector<T2>(vec.size());
  for(int i = 0; i < vec.size(); i++) {
    det.crypt(vec[i], out[i], sizeof(vec[i]));
  }
  return std::move(out);
}
#else
template<typename T1>
std::vector<typename crypted_type<T1>::value> transform(aes256det &det, std::vector<T1> &vec) {
  using T2 = typename crypted_type<T1>::value;
  static_assert(sizeof(T2) == sizeof(T1));
  auto out = std::vector<T2>(vec.size());
  for(int i = 0; i < vec.size(); i++) {
    det.crypt_block(vec[i], out[i], sizeof(vec[i]));
  }
  return std::move(out);
}
#endif


TimerCounter totalWebRequest;
std::unique_ptr<IASReport> submit(const std::unique_ptr<Report> &report){
  auto timer = Timer{&totalWebRequest};
  return report->submitReport(*WebService::getInstance());
}

void testAesDet(){
  uint8_t key[16] = {};
  auto det = aes256det::create(key, sizeof(key)*8);
  std::string data = "Hallo";
  uint8_t *in = (uint8_t*) data.data();
  uint8_t cipher[16 + 5];
  det->crypt(in, cipher, 5);
  std::cout << ByteArrayToString(cipher, sizeof(cipher)) << "\n";
  uint8_t out[ 5];
  det->decrypt(cipher, out, 5);
  std::cout << "Reconstructed: "  << std::string((char*)out, 5) << "\n";
}

uint8_t mrenclave[32] = {};
class Pshared {
public:
  std::unique_ptr<cppsock> connection;
  std::unique_ptr<Enclave> enclave;
  sgx_quote_nonce_t eid = {};
  sgx_ec256_public_t gpub = {};
  Pshared(std::unique_ptr<cppsock> &&connection) : connection(std::move(connection)){
  }
  virtual int role() = 0;
  void setupEnclave(){
    enclave = std::make_unique<Enclave>("onesided-enclave.signed.so");
    auto total_time = std::make_unique<Timer>("init");
    enclave->call<init_onesided_nonce>(&eid);
  }
  void exchange(std::string &my, std::string &other){
    send(my);
    other = readString();
  }
  void send(std::string &s){
    size_t len = s.size();
    connection->send(&len, sizeof(len));
    connection->send(s.data(), len);
  }
  std::string readString(){
    size_t len = {};
    connection->readAll(&len, sizeof(len));
    char data[len];
    connection->readAll(data, len);
    return std::string{data, len};
  }
  void send(IASReport &report){
    send(report.response);
    send(report.response_signature);
  }
  IASReport receiveReport(){
    return {readString(), readString()};
  }
  void send(Report &report){
    auto data = std::string{report.getQuote().begin(), report.getQuote().end()};
    send(data);
  }
  std::unique_ptr<Report> receiveRawReport(){
    return std::make_unique<Report>(readString());
  }
  template<typename T>
  void exchange(T &my, T &other){
    connection->send(&my, sizeof(T));
    connection->readAll(&other, sizeof(T));
  }
  void init() {
    if(!enclave){
      throw std::runtime_error("");
    }
    sgx_quote_nonce_t oeid = {};
    exchange(eid, oeid);
    auto r =  enclave->callAttested<init_onesided>(mrenclave, &oeid, &gpub, role());
    sgx_report_data_t user_data = {};
    auto ir = submit(r);
    
    sgx_ec256_public_t opub = {};
    exchange(gpub, opub);
    std::string response, sig;
    exchange(ir->response, response);
    exchange(ir->response_signature, sig);

    sha256 sha = {};
    int role = 1-this->role();
    sha.add(reinterpret_cast<uint8_t*>(&oeid), sizeof(oeid));
    sha.add(reinterpret_cast<uint8_t*>(&opub), sizeof(opub));
    sha.add(reinterpret_cast<uint8_t*>(&role), sizeof(role));
    sha.hash(reinterpret_cast<uint8_t*>(&user_data));
    auto oir = IASReport{response, sig};
    oir.verify(user_data);

    
    enclave->call<finish_kex>(&opub, response.c_str(), sig.c_str());
  }
};
void sort(std::vector<uint64_t> &data){
  //std::sort(data.begin(), data.end());
  radix_sort(data);
}
struct P1 : public Pshared {
  std::vector<element> s1;
  std::vector<crypted3_element> s1_crypted3;
  P1(std::unique_ptr<cppsock> &&con, size_t setsize) : Pshared(std::move(con)), s1(setsize){
    int pos = setsize/2;
    for(element &e: s1){
      *((int*)&e[0]) = pos++;
    }
  }
  int role(){
    return 0;
  }
  auto crypt3(aes256det &det){
    auto time = std::make_unique<Timer>("encrypt");
    auto s1_crypted = transform(det, s1);
    float duration = (*time)();
    time.reset();
    std::cout << s1.size() * sizeof(element) / duration / 1000000.0 << " Mbytes/s\n";
    auto s1_crypted2 = std::vector<crypted2_element>(s1.size());
  
    time = std::make_unique<Timer>("encrypt");
    auto report = this->enclave->callAttested<setInput>(reinterpret_cast<uint8_t*>(s1_crypted.data()), reinterpret_cast<uint8_t*>(s1_crypted2.data()), s1.size());
    duration = (*time)();
    time.reset();
    std::cout << s1.size() * sizeof(element) / duration / 1000000.0 << " Mbytes/s\n";

    s1_crypted3 = transform(det, s1_crypted2);
    return submit(report);
  }
  auto hashAndEval(aes256det &det) -> int {
    auto ireport = crypt3(det);
    ireport->verify({});

    auto hashfun = std::vector<uint64_t>(1);
    connection->readAll(hashfun.data(), hashfun.size() * sizeof(uint64_t));
  
    auto hash = UHF{hashfun};
    int intSize = 0;
    if(false){
      auto lookupTimer = std::make_unique<Timer>("Lookup");
      
      auto hashReport = receiveReport();
      auto hashes = connection->readVect<uint64_t>();
      auto time = std::make_unique<Timer>("sort_hashes");
      sort(hashes);
      time.reset();
      for(auto &ciph : s1_crypted3){
	auto hashVal = hash.hash(ciph, sizeof(ciph));
	if(std::binary_search(hashes.begin(), hashes.end(), hashVal)){
	  intSize++;
	}
      }
    }else{
      auto lookupTimer = std::make_unique<Timer>("Lookup");
      std::vector<uint64_t> hashes2(s1_crypted3.size());
      {
	auto sortTimer = Timer{"hash2"};
	for(int i = 0; i < s1_crypted3.size(); i++){
	  hashes2[i] = hash.hash(s1_crypted3[i], sizeof(s1_crypted3[i]));
	}
      }
      {
	auto sortTimer = Timer{"Sort"};
	sort(hashes2);
      }
      auto hashReport = receiveReport();
      auto hashes = connection->readVect<uint64_t>();
      auto report_data = sgx_report_data_t{};
      {
	auto sortTimer = Timer{"sha-check"};
	sha256 sha_ucheck;
	sha_ucheck.add(reinterpret_cast<uint8_t*>(hashfun.data()), sizeof(uint64_t));
	sha_ucheck.add(reinterpret_cast<uint8_t*>(hashes.data()), hashes.size() * sizeof(uint64_t));
	sha_ucheck.hash(reinterpret_cast<uint8_t*>(&report_data));
      }
      hashReport.verify(report_data);
      auto time = std::make_unique<Timer>("sort_hashes");
      sort(hashes);
      time.reset();
      {
	auto sortTimer = Timer{"Merge"};
	int i = 0;
	int j = 0;
	while(i < hashes.size() && j < hashes2.size()){
	  auto hash1 = hashes[i];
	  auto hash2 = hashes2[j];
	  if(hash1 < hash2){
	    i++;
	  }else if(hash1 > hash2){
	    j++;
	  }else{
	    i++;
	    j++;
	    intSize++;
	  }
	}
      }
    }
    return intSize;
  }
};
struct P2 : public Pshared {
  std::vector<element> s2;
  std::vector<crypted3_element> s2_crypted3;
  P2(std::unique_ptr<cppsock> &&con, size_t setsize) : Pshared(std::move(con)), s2(setsize) {
    int pos = 0;
    for(element &e: s2){
      *((int*)&e[0]) = pos++;
    }
  }
  int role(){
    return 1;
  }
  void crypt3(aes256det &det){
    uint8_t key2[16];
    enclave->call<releaseKey>(key2);
    auto time = std::make_unique<Timer>("3x encrypt");
    auto s2_crypted = transform(det, s2);
    auto det2 = aes256det::create(key2, sizeof(key2)*8);
    auto s2_crypted2 = transform(*det2, s2_crypted);
    s2_crypted3 = transform(det, s2_crypted2);
  }
  void sort(){
    static_assert(sizeof(crypted3_element_cls) == sizeof(crypted3_element));
    auto time = std::make_unique<Timer>("sort_pre");
    #ifdef flexsize
    auto indices = std::vector<crypted3_element *>(s2_crypted3.size());
    for(int i =0; i< indices.size(); i++){
      indices[i] = &s2_crypted3[i];
    }
    std::sort(indices.begin(), indices.end(), [](crypted3_element *a, crypted3_element *b){
					      for(int i = 0; i < sizeof(crypted3_element)/8; i++){
						if(reinterpret_cast<uint64_t*>(*a)[i] > reinterpret_cast<uint64_t*>(*b)[i]) {
						  return 1;
						}
						if(reinterpret_cast<uint64_t*>(*a)[i] < reinterpret_cast<uint64_t*>(*b)[i]){
						  return 0;
						}
					      }
					      return 0;
					     });
    auto s2_crypted_sorted = std::vector<crypted3_element>(s2_crypted3.size());
    for(int i =0; i< indices.size(); i++){
      memcpy(s2_crypted_sorted[i],*indices[i], sizeof(s2_crypted_sorted[i]));
    }
    #else
    auto &s2_crypted_sorted = s2_crypted3;
    radix_sort(reinterpret_cast<unsigned __int128*>(s2_crypted_sorted.data()), s2_crypted_sorted.size());
    #endif
    time.reset();
    if(&s2_crypted3 != &s2_crypted_sorted){
      s2_crypted3 = std::move(s2_crypted_sorted);
    }
  }
  void sortAndHash(const std::unique_ptr<Timer> &total){
    auto sorttotal = std::make_unique<Timer>("sorttotal");
    sort();
    sorttotal.reset();
    std::cout << "Sort done: " << (*total)() << "\n";
    auto time = std::make_unique<Timer>("committing");
    enclave->call<commit>(reinterpret_cast<uint8_t*>(s2_crypted3.data()), s2_crypted3.size());
    time.reset();
    std::cout << "Commit attestation: " << (*total)() << "\n";
    auto gettinghash = std::make_unique<Timer>("requesting the hash function");

    auto hashes = std::vector<uint64_t>(s2_crypted3.size());
    uint64_t uhf = 0;
    gettinghash.reset();
    
    std::cout << "Hashfun here: " << (*total)() << "\n";
    auto hashingTimer = std::make_unique<Timer>("hashing");

    // 
    auto reporthash = enclave->callAttested<do_uhf>(reinterpret_cast<uint8_t*>(s2_crypted3.data()), hashes.data(), &uhf, s2_crypted3.size());
    connection->send(&uhf, sizeof(uint64_t));
    hashingTimer.reset();
    auto ireportHash = submit(reporthash);
    send(*ireportHash);
    connection->sendVect(hashes);
  }


};

class Measurement {
  std::vector<float> datapoints;
public:
  void add(TimerCounter &counter){
    datapoints.push_back(counter.value);
    counter.value = 0;
  }
  void add(std::unique_ptr<Timer> &timer){
    datapoints.push_back((*timer)());
  }
  void print(std::ostream &out){
    float avg = 0;
    for(float f : datapoints){
      avg += f;
    }
    avg /= datapoints.size();
    float stdev = 0;
    for(float f : datapoints){
      stdev += (f - avg) * (f - avg);
    }
    stdev /= datapoints.size();
    stdev = sqrt(stdev);
    out << " " << avg << " " << stdev;
  }
};
void bench(size_t setsize, Measurement &total, Measurement &webRequestPrepare, Measurement &webRequest, Measurement &prepare, std::string target_host){
  std::unique_ptr<cppsock> serv = std::make_unique<cppsock>();
  serv->bind();
  serv->listen();
  std::unique_ptr<cppsock> client = std::make_unique<cppsock>();
  //client->connect("::1");
  client->connect(target_host);
  std::unique_ptr<cppsock> servClient = std::make_unique<cppsock>(serv->accept());
  P1 p1{std::move(client), setsize};
  P2 p2{std::move(servClient), setsize};

  auto total_time = std::make_unique<Timer>("total");
  uint8_t key[16] = {};
  auto det = aes256det::create(key, sizeof(key)*8);
  // testAesDet();
  // testHashingAttestation();
  auto p2thread = std::thread{[&p2](){
     p2.setupEnclave();
     p2.init();
  }};
  p1.setupEnclave();
  p1.init();
  p2thread.join();
  
  std::cout << "Verified\n";
  prepare.add(total_time);
  webRequestPrepare.add(totalWebRequest);
  std::cout << "Preparation: " << (*total_time)() << "\n";

  p2thread = std::thread{[&p2,&det, &total_time](){
    p2.crypt3(*det);
    std::cout << "Done crypting on p2: " << (*total_time)() << "\n";

    p2.sortAndHash(total_time);
    std::cout << "SortAndHash done: " << (*total_time)() << "\n";
  }};
  int intSize = p1.hashAndEval(*det);
  p2thread.join();
  std::cout << "After BinSearch: " << (*total_time)() << "\n";
  if(intSize != setsize/2){
    throw std::runtime_error("Intersection size wrong");
  }
  std::cout << std::dec << intSize << "\n";
  std::cout << "Total WebRequest: " << totalWebRequest.value << "\n"; 
  webRequest.add(totalWebRequest);
  total.add(total_time);
}
void benchDet(){
  uint8_t key[16] = {};
  auto det = aes256det::create(key, sizeof(key)*8);
  auto timer = Timer{"enc"};
  element elem = {};
  crypted_element elemCr = {};
  size_t n = 10000000;
  for(int i = 0; i < n; i++){
    det->crypt(elem, elemCr, sizeof(elem));
  }
  std::cout << n / 1000000.0 * sizeof(elem) / timer() << "MB/sec\n";
  std::cout << std::hex << (int)elemCr[0] << ","<< (int)elemCr[1] << "\n";
}
int main(int argc, char *argv[]) {
  std::string target_host = "::1";
  if(argc == 2){
    target_host = std::string{argv[1]};
  }
  //benchDet();
  //return 0;
  
  std::ofstream measurements("measurements.txt");
  int sz = 24;
  for(int cnt = 1 << sz; cnt <= 1 << sz; cnt += 1 << sz){
    Measurement total, webRequestPrepare, webRequest, prepare;
    for(int i = 0; i < 5; i++){
      bench(cnt, total, webRequestPrepare, webRequest, prepare);
    }
    measurements << cnt;
    total.print(measurements);
    webRequestPrepare.print(measurements);
    webRequest.print(measurements);
    prepare.print(measurements);
    measurements << std::endl;
  }
  return 0;
}
