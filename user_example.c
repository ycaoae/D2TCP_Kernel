#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h> // For creating random numbers only.

#define NETLINK_D2TCP 31
#define MAX_PAYLOAD 1024

struct d2tcp_ctrl_msg {
  uint32_t ddl;
  uint32_t total_num_bytes;
};

void send_d2tcp_ctrl_msg(uint32_t deadline, uint32_t num_bytes) {

  struct sockaddr_nl src_addr, dest_addr;
  struct nlmsghdr* nlh = NULL;
  struct iovec iov;
  int sock_fd;
  struct msghdr msg;
  struct d2tcp_ctrl_msg send_payload;
  struct d2tcp_ctrl_msg* recv_payload;

  if ((sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_D2TCP)) < 0) {
    return;
  }

  memset(&src_addr, 0, sizeof(src_addr));
  src_addr.nl_family = AF_NETLINK;
  src_addr.nl_pid = getpid();
  bind(sock_fd, (struct sockaddr*) &src_addr, sizeof(src_addr));
  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.nl_family = AF_NETLINK;
  dest_addr.nl_pid = 0;
  dest_addr.nl_groups = 0;

  nlh = (struct nlmsghdr*) malloc(NLMSG_SPACE(MAX_PAYLOAD));
  memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
  nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
  nlh->nlmsg_pid = getpid();
  nlh->nlmsg_flags = 0;
  send_payload.ddl = deadline;
  send_payload.total_num_bytes = num_bytes;
  memcpy(NLMSG_DATA(nlh), &send_payload, sizeof(send_payload));

  iov.iov_base = (void*) nlh;
  iov.iov_len = nlh->nlmsg_len;
  memset(&msg, 0, sizeof(msg));
  msg.msg_name = (void*) &dest_addr;
  msg.msg_namelen = sizeof(dest_addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  printf("Sending message to kernel %d, %d\n", deadline, num_bytes);
  sendmsg(sock_fd, &msg, 0);
  printf("Waiting for message from kernel\n");
  recvmsg(sock_fd, &msg, 0);
  recv_payload = (struct d2tcp_ctrl_msg*) NLMSG_DATA(nlh);
  printf("Received message payload: %d, %d\n", recv_payload->ddl, recv_payload->total_num_bytes);
  close(sock_fd);
}

int main() {
  srand(time(NULL));
  send_d2tcp_ctrl_msg(rand() & 15, rand() & 15);
}