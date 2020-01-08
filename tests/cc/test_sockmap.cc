#include <stdio.h>

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include "BPF.h"
#include "catch.hpp"

static int make_loopback() {
  int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  REQUIRE(s > -1);

  const int one = 1;
  REQUIRE(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
  REQUIRE(listen(s, 10) == 0);
  return s;
}

static int socket_port(int s) {
  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);

  REQUIRE(getsockname(s, (struct sockaddr *) &addr, &len) == 0);
  return ntohs(addr.sin_port);
}

static int make_connect(int port) {
  int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  REQUIRE(s > -1);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;

  REQUIRE(connect(s, (struct sockaddr *) &addr, sizeof(addr)) == 0);
  return s;
}

TEST_CASE("test sockmap", "[sockmap]") {
  const std::string BPF_PROGRAM = R"(
    BPF_SOCKMAP(map, 16);
  )";

  ebpf::BPF bpf;

  ebpf::StatusTuple status = bpf.init(BPF_PROGRAM);
  REQUIRE(status.code() == 0);

  ebpf::BPFSockmapTable t = bpf.get_sockmap_table("map");
  REQUIRE(t.capacity() == 16);

  int loop = make_loopback();
  int port = socket_port(loop);

  int s1 = make_connect(port);
  status = t.update_value(0, s1);
  REQUIRE(status.code() == 0);

  int s2 = make_connect(port);
  status = t.update_value(15, s2);
  REQUIRE(status.code() == 0);

  status = t.remove_value(0);
  REQUIRE(status.code() == 0);

  status = t.remove_value(15);
  REQUIRE(status.code() == 0);

  t.remove_value(0);
  REQUIRE(status.code() == 0);

  close(loop);
  close(s1);
}

TEST_CASE("test sockmap progs", "[sockmap]") {
  const std::string BPF_PROGRAM = R"(
    #include <uapi/linux/bpf.h>
    #include <uapi/linux/if_ether.h>
    #include <uapi/linux/if_packet.h>
    #include <uapi/linux/ip.h>

    BPF_SOCKMAP(sock_map, 16);

    int prog_parser(struct __sk_buff *skb) {
      return skb->len;
    }

    int prog_verdict(struct __sk_buff *skb) {
      return sock_map.sk_redirect_map(skb, 1, 0);
    }
  )";

  ebpf::BPF bpf;

  ebpf::StatusTuple status = bpf.init(BPF_PROGRAM);
  REQUIRE(status.code() == 0);

  ebpf::BPFSockmapTable t = bpf.get_sockmap_table("sock_map");
  REQUIRE(t.capacity() == 16);

  int verdict_fd;
  status = bpf.attach_fd("prog_verdict", BPF_PROG_TYPE_SK_SKB, verdict_fd, BPF_SK_SKB_STREAM_VERDICT, t.get_fd());
  REQUIRE(status.code() == 0);

  int parser_fd;
  status = bpf.attach_fd("prog_parser", BPF_PROG_TYPE_SK_SKB, parser_fd, BPF_SK_SKB_STREAM_PARSER, t.get_fd());
  REQUIRE(status.code() == 0);
}
