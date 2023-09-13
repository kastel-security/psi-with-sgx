#include <vector>
#include <iostream>

class cppsock {
  int fd;
  cppsock(int fd);
  cppsock(const cppsock &o) = delete;
public:
  cppsock();
  cppsock(cppsock &&o) {
    fd = o.fd;
    o.fd = -1;
  }
  void connect(std::string host);
  void bind();
  void listen();
  cppsock accept();
  ~cppsock();
  void send(const uint8_t *data, size_t len);
  ssize_t read(uint8_t *data, size_t len);
  void readAll(uint8_t *data, size_t len);
  void send(const void *data, size_t len){
    send(reinterpret_cast<const uint8_t*>(data), len);
  }
  template<typename T>
  void sendVect(const std::vector<T> &data){
    size_t size = data.size();
    send(&size, sizeof(size));
    send(data.data(), data.size() * sizeof(T));

  }
  template<typename T>
  std::vector<T> readVect(){
    auto size = size_t{};
    readAll(&size, sizeof(size));
    auto ret = std::vector<T>(size);
    readAll(ret.data(), size * sizeof(T));
    return ret;
  }

    
  void readAll(void *data, size_t len){
    readAll(reinterpret_cast<uint8_t*>(data), len);
  }
  template<int len>
  cppsock &operator>> (uint8_t (&data)[len]){
    readAll(data, len);
    return *this;
  }
  template<int len>
  cppsock &operator<< (const uint8_t (&data)[len]){
    send(data, len);
    return *this;
  }
};
