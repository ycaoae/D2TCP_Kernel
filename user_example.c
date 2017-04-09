#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define MAX_PAYLOAD 1024
#define NETLINK_USER 31

struct ctrl_msg {
  uint32_t saddr;
  uint32_t daddr;
  uint16_t sport;
  uint16_t dport;
  uint32_t size;
  uint32_t time_to_ddl;
};

int nl_send_d2tcp_ctrl_msg(uint32_t saddr, uint16_t sport, uint32_t daddr,
    uint16_t dport, uint32_t size_in_bytes, uint32_t microsecs_to_ddl) {

  struct ctrl_msg request;
  struct ctrl_msg* echo;
  struct sockaddr_nl src_addr, dest_addr;
  struct nlmsghdr* nlh = NULL;
  struct iovec iov;
  int sock_fd;
  struct msghdr msg;

  sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
  if (sock_fd < 0) {
    return sock_fd;
  }

  memset(&src_addr, 0, sizeof(src_addr));
  src_addr.nl_family = AF_NETLINK;
  src_addr.nl_pid = getpid();
  bind(sock_fd, (struct sockaddr*) &src_addr, sizeof(src_addr));

  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.nl_family = AF_NETLINK;
  dest_addr.nl_pid = 0;
  dest_addr.nl_groups = 0;

  request.saddr = saddr;
  request.sport = sport;
  request.daddr = daddr;
  request.dport = dport;
  request.size = size_in_bytes;
  request.time_to_ddl = microsecs_to_ddl;

  nlh = (struct nlmsghdr*) malloc(NLMSG_SPACE(MAX_PAYLOAD));
  memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
  nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
  nlh->nlmsg_pid = getpid();
  nlh->nlmsg_flags = 0;
  memcpy(NLMSG_DATA(nlh), &request, sizeof(request));

  iov.iov_base = (void*) nlh;
  iov.iov_len = nlh->nlmsg_len;
  memset(&msg, 0, sizeof(msg));
  msg.msg_name = (void*) &dest_addr;
  msg.msg_namelen = sizeof(dest_addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  sendmsg(sock_fd, &msg, 0);
  recvmsg(sock_fd, &msg, 0);
  printf("Check syslog for result.\n");
  close(sock_fd);
  return 0;
}

int main() {
  uint32_t saddr;
  uint32_t daddr;
  uint16_t sport;
  uint16_t dport;
  uint32_t size;
  uint32_t time_to_ddl;

  printf("Input source IP (unsigned int): ");
  scanf("%u", &saddr);
  printf("Input source port (unsigned short): ");
  scanf("%hu", &sport);
  printf("Input destination IP (unsigned int): ");
  scanf("%u", &daddr);
  printf("Input destination port (unsigned short): ");
  scanf("%hu", &dport);
  printf("Input total number of bytes: ");
  scanf("%u", &size);
  printf("Input number of microseconds to deadline: ");
  scanf("%u", &time_to_ddl);

  return nl_send_d2tcp_ctrl_msg(saddr, sport, daddr, dport, size, time_to_ddl);
}