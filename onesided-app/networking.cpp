#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdexcept>
#include <arpa/inet.h>
#include <netdb.h>
#include "networking.h"

cppsock::cppsock(int fd) : fd(fd){
}
cppsock::cppsock() {
  fd = ::socket(AF_INET6, SOCK_STREAM, 0);
  if(fd == -1){
    perror("socket");
    throw std::runtime_error("socket");
  }
}
void cppsock::connect(std::string host){
  auto hint = addrinfo {};
  hint.ai_family = AF_INET6;
  hint.ai_socktype = SOCK_STREAM;

  struct addrinfo *res = nullptr;
  if(getaddrinfo(host.c_str(), "4321", &hint, &res) != 0){
    throw std::runtime_error("addrinfo failed");
  }
  if(res == nullptr){
    throw std::runtime_error("No addresses");
  }
  if(res->ai_next != nullptr){
    throw std::runtime_error("Multiple addresses");
  }
  if(::connect(fd, res->ai_addr, res->ai_addrlen)){
    throw std::runtime_error("bind failed");
  }
  freeaddrinfo(res);
}
void cppsock::bind(){
  const int enable = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    perror("setsockopt failed");
    throw std::runtime_error("setsockopt");
  }
  struct sockaddr_in6 sockaddr;
  sockaddr.sin6_port = htons(4321);
  sockaddr.sin6_family = AF_INET6;
  sockaddr.sin6_addr = in6addr_any;
  if(::bind(fd, (struct sockaddr*) &sockaddr, sizeof(sockaddr))){
    throw std::runtime_error("bind failed");
  }
}
void cppsock::listen(){
  if(::listen(fd, 5)){
    throw std::runtime_error("listen failed");
  }
}
cppsock cppsock::accept(){
  struct sockaddr_in6 sockaddr;
  socklen_t socksize = sizeof(sockaddr);
  int sockfd = ::accept(fd, (struct sockaddr*) &sockaddr, &socksize);
  if(sockfd == -1){
    perror("accept");
    throw std::runtime_error("accept failed");
  }
  return {sockfd};
}
cppsock::~cppsock() {
  if(fd != -1){
    close(fd);
  }
}
void cppsock::send(const uint8_t *data, size_t len){
  while(len > 0){
    ssize_t written = write(fd, data, len);
    if(written == -1){
      throw std::runtime_error("write failed");
    }
    data += written;
    len -= written;
  }
}
ssize_t cppsock::read(uint8_t *data, size_t len){
  return ::read(fd, data, len);
}
void cppsock::readAll(uint8_t *data, size_t len){
  while(len > 0){
    ssize_t read = ::read(fd, data, len);
    data += read;
      len -= read;
  }
}
