// SPDX-License-Identifier: Apache-2.0

/**********************************************************************
 *
 *  Copyright (C) 2025 Franz-Josef Haider
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 *  implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 **********************************************************************/

#include <arpa/inet.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEBUG 0

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le16(val) (val)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_le16(val) bswap_16(val)
#else
#error "unknown byte order"
#endif

volatile int stop_signal = 0;

#define MY_TEMP_FAILURE_RETRY(expression) \
  (__extension__                                                              \
    ({ long int __result;                                                     \
       do __result = (long int) (expression);                                 \
       while (__result == -1L && errno == EINTR && !stop_signal);             \
       __result; }))

static int open_vhci(uint8_t type)
{
    uint8_t create_req[2] = { 0xff, type };
    ssize_t written;
    char buf[8192];
    int fd;

    fd = open("/dev/vhci", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "Failed to open /dev/vhci device\n");
        return -1;
    }

    written = write(fd, create_req, sizeof(create_req));
    if (written < 0) {
        fprintf(stderr, "Failed to set device type\n");
        close(fd);
        return -1;
    }

    // read and discard the setup packet
    MY_TEMP_FAILURE_RETRY(read(fd, buf, 8192));

    return fd;
}

static void handle_signal(int signal)
{
    switch (signal) {
        case SIGINT:
            printf("Caught SIGINT, exiting now\n");
            stop_signal = 1;
            break;
        default:
            fprintf(stderr, "Caught wrong signal: %d\n", signal);
            return;
    }
}

static void connection_loop(int hci_fd, int conn_fd)
{
    struct pollfd fds[2];
    fds[0].fd = hci_fd;
    fds[0].events = POLLIN;
    fds[1].fd = conn_fd;
    fds[1].events = POLLIN;

    while (!stop_signal) {
#if DEBUG
        fprintf(stderr, "polling\n");
#endif
        int r = MY_TEMP_FAILURE_RETRY(poll(fds, 2, -1));
#if DEBUG
        fprintf(stderr, "poll returned %d\n", r);
#endif
        if (r < 0) {
            fprintf(stderr, "poll failed %d\n", r);
            break;
        } else if (r) {
            if (fds[0].revents & POLLIN) {
                char buf[8192];

                r = MY_TEMP_FAILURE_RETRY(read(hci_fd, buf, 8192));
                if (r < 0) {
                    fprintf(stderr, "reading from hci failed\n");
                    break;
                }

#if DEBUG
                fprintf(stderr, "SENDING TO OTHER SIDE ");
                for (int i = 0; i < r; i++) {
                    fprintf(stderr, "%x ", buf[i]);
                }
                fprintf(stderr, "\n");
#endif

                int r2 = MY_TEMP_FAILURE_RETRY(send(conn_fd, buf, r, MSG_NOSIGNAL));
                if (r2 != r) {
                    fprintf(stderr, "Failed to send to the other side %d %d\n", r2, r);
                    break;
                }
            }
            if (fds[1].revents & POLLIN) {
                char buf[8192];

                r = MY_TEMP_FAILURE_RETRY(recv(conn_fd, buf, 8192, MSG_NOSIGNAL));
                if (r < 0) {
                    fprintf(stderr, "receiving from socket failed\n");
                    break;
                }
                if (!r) {
                    fprintf(stderr, "socket has no data\n");
                    break;
                }

#if DEBUG
                fprintf(stderr, "WRITING TO HCI ");
                for (int i = 0; i < r; i++) {
                    fprintf(stderr, "%x ", buf[i]);
                }
                fprintf(stderr, "\n");
#endif

                int offset = 0;
                hci_command_hdr *cmd_hdr;
                hci_event_hdr *evt_hdr;
                hci_acl_hdr *acl_hdr;
                hci_sco_hdr *sco_hdr;
                uint16_t pktlen;

                while (r > 0) {
                    switch (buf[offset]) {
                        case HCI_COMMAND_PKT:
                            if (r < 1 + sizeof(*cmd_hdr)) {
                                fprintf(stderr, "FIXME: IMPLEMENT RECEIVING MORE\n");
                                abort();
                            }

                            cmd_hdr = (hci_command_hdr*)(buf + offset + 1);
                            pktlen = 1 + sizeof(*cmd_hdr) + cmd_hdr->plen;

                            break;
                        case HCI_ACLDATA_PKT:
                            if (r < 1 + sizeof(*acl_hdr)) {
                                fprintf(stderr, "FIXME: IMPLEMENT RECEIVING MORE\n");
                                abort();
                            }

                            acl_hdr = (hci_acl_hdr*)(buf + offset + 1);
                            pktlen = 1 + sizeof(*acl_hdr) + cpu_to_le16(acl_hdr->dlen);

                            break;
                        case HCI_SCODATA_PKT:
                            if (r < 1 + sizeof(*sco_hdr)) {
                                fprintf(stderr, "FIXME: IMPLEMENT RECEIVING MORE\n");
                                abort();
                            }

                            sco_hdr = (hci_sco_hdr*)(buf + offset + 1);
                            pktlen = 1 + sizeof(*sco_hdr) + sco_hdr->dlen;

                            break;
                        case HCI_EVENT_PKT:
                            if (r < 1 + sizeof(*evt_hdr)) {
                                fprintf(stderr, "FIXME: IMPLEMENT RECEIVING MORE\n");
                                abort();
                            }

                            evt_hdr = (hci_event_hdr*)(buf + offset + 1);
                            pktlen = 1 + sizeof(*evt_hdr) + evt_hdr->plen;

                            break;
                        case HCI_ISODATA_PKT: {
                                fprintf(stderr, "FIXME: IMPLEMENT ISODATA_PKT\n");
                                abort();
                            }
                            break;
                        default:
                            fprintf(stderr, "FIXME: UNKNOWN PKT %d\n", buf[offset]);
                            abort();
                            break;
                    }

#if DEBUG
                    fprintf(stderr, "WRITING TO HCI FOR REAL ");
                    for (int i = 0; i < pktlen; i++) {
                        fprintf(stderr, "%x ", buf[offset + i]);
                    }
                    fprintf(stderr, "\n");
#endif

                    int r2 = MY_TEMP_FAILURE_RETRY(write(hci_fd, buf + offset, pktlen));
                    if (r2 != pktlen) {
                        fprintf(stderr, "Failed to write to hci %d %d\n", r2, pktlen);
                        break;
                    }

                    r -= pktlen;
                    offset += pktlen;
                }
            }
        }
    }
}

static int wait_hcidev(int hci_interface);

int main(int argc, char *argv[])
{
    int server = 1;
    char server_ip[512] = "127.0.0.1";
    int server_port = 5555;
    int hci_dev = 0;

    for (int i = 0; i < argc; i++) {
        if (0 == strcmp("--client", argv[i])) {
            if (i + 2 < argc) {
                i++;
                strncpy(server_ip, argv[i], 512);
                i++;
                server_port = atoi(argv[i]);
            } else {
                fprintf(stderr, "--client argument missing (server port)\n");
                return -1;
            }
            server = 0;
        } else if (0 == strcmp("--server", argv[i])) {
            if (i + 2 < argc) {
                i++;
                strncpy(server_ip, argv[i], 512);
                i++;
                server_port = atoi(argv[i]);
            } else {
                fprintf(stderr, "--server argument missing (server port)\n");
                return -1;
            }
            server = 1;
        } else if (0 == strcmp("--hci-dev", argv[i])) {
            if (i + 1 < argc) {
                i++;
                hci_dev = atoi(argv[i]);
            } else {
                fprintf(stderr, "--hci-dev argument missing\n");
                return -1;
            }
        }
    }

    struct sigaction sa;
    sa.sa_handler = &handle_signal;
    sa.sa_flags = SA_RESTART;
    sigfillset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        fprintf(stderr, "Cannot handle SIGINT\n");
        return -1;
    }

    if (server) {
        struct sockaddr_hci addr;

        memset(&addr, 0, sizeof(addr));
        addr.hci_family = AF_BLUETOOTH;
        addr.hci_dev = hci_dev;
        addr.hci_channel = HCI_CHANNEL_USER;

        int hci_fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
        if (hci_fd < 0) {
            fprintf(stderr, "Failed to create bluetooth socket\n");
            return -1;
        }

        if (wait_hcidev(hci_dev) < 0) {
            fprintf(stderr, "Failed to wait for bluetooth device\n");
            close(hci_fd);
            return -1;
        }

        if (ioctl(hci_fd, HCIDEVDOWN, hci_dev)) {
            fprintf(stderr, "Failed to put bluetooth device down (use sudo?)\n");
            close(hci_fd);
            return -1;
        }

        if (bind(hci_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            fprintf(stderr, "socket bind error %s\n", strerror(errno));
            close(hci_fd);
            return -1;
        }

        int sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = inet_addr(server_ip);
        serv_addr.sin_port = htons(server_port);
        if (bind(sock_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            fprintf(stderr, "tcp socket bind error %s\n", strerror(errno));
            close(hci_fd);
            close(sock_fd);
            return -1;
        }

        listen(sock_fd, 1);

        struct sockaddr_in clnt_addr;
        socklen_t clnt_addr_size = sizeof(clnt_addr);

        int client_fd = accept(sock_fd, (struct sockaddr*)&clnt_addr, &clnt_addr_size);

        // can i close server socket here?
        close(sock_fd);

        connection_loop(hci_fd, client_fd);

        close(client_fd);
        close(hci_fd);
    } else {
        int conn_fd = socket(AF_INET, SOCK_STREAM, 0);

        if (conn_fd < 0) {
            fprintf(stderr, "Failed to create client socket\n");
            return -1;
        }

        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = inet_addr(server_ip);
        serv_addr.sin_port = htons(server_port);

        if (MY_TEMP_FAILURE_RETRY(connect(conn_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
            fprintf(stderr, "Failed to connect to server\n");
            close(conn_fd);
            return -1;
        }

        int vhci_fd = open_vhci(HCI_PRIMARY);

        if (vhci_fd < 0) {
            fprintf(stderr, "Failed to open vhci device\n");
            close(conn_fd);
            return -1;
        }

        connection_loop(vhci_fd, conn_fd);

        close(conn_fd);
        close(vhci_fd);
    }

    return 0;
}

/**********************************************************************
 *
 *  Copyright (C) 2015 Intel Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 *  implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 **********************************************************************/

// https://android.googlesource.com/platform/system/bt/+/98a9641/vendor_libs/linux/bt_vendor_linux.c

#define MGMT_OP_INDEX_LIST      0x0003
#define MGMT_EV_INDEX_ADDED     0x0004
#define MGMT_EV_COMMAND_COMP    0x0001
#define MGMT_EV_SIZE_MAX        1024
#define MGMT_EV_POLL_TIMEOUT    3000 /* 3000ms */

struct mgmt_pkt {
  uint16_t opcode;
  uint16_t index;
  uint16_t len;
  uint8_t data[MGMT_EV_SIZE_MAX];
} __attribute__((packed));

struct mgmt_event_read_index {
  uint16_t cc_opcode;
  uint8_t status;
  uint16_t num_intf;
  uint16_t index[0];
} __attribute__((packed));

int wait_hcidev(int hci_interface)
{
  struct sockaddr_hci addr;
  struct pollfd fds[1];
  struct mgmt_pkt ev;
  int fd;
  int ret = 0;
  fd = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
  if (fd < 0) {
    fprintf(stderr, "Bluetooth socket error: %s\n", strerror(errno));
    return -1;
  }
  memset(&addr, 0, sizeof(addr));
  addr.hci_family = AF_BLUETOOTH;
  addr.hci_dev = HCI_DEV_NONE;
  addr.hci_channel = HCI_CHANNEL_CONTROL;
  if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    fprintf(stderr, "HCI Channel Control: %s\n", strerror(errno));
    close(fd);
    return -1;
  }
  fds[0].fd = fd;
  fds[0].events = POLLIN;
  /* Read Controller Index List Command */
  ev.opcode = MGMT_OP_INDEX_LIST;
  ev.index = HCI_DEV_NONE;
  ev.len = 0;
  if (write(fd, &ev, 6) != 6) {
    fprintf(stderr, "Unable to write mgmt command: %s\n", strerror(errno));
    ret = -1;
    goto end;
  }
  while (1) {
    int n = poll(fds, 1, MGMT_EV_POLL_TIMEOUT);
    if (n == -1) {
      fprintf(stderr, "Poll error: %s\n", strerror(errno));
      ret = -1;
      break;
    } else if (n == 0) {
      fprintf(stderr, "Timeout, no HCI device detected\n");
      ret = -1;
      break;
    }
    if (fds[0].revents & POLLIN) {
      n = read(fd, &ev, sizeof(struct mgmt_pkt));
      if (n < 0) {
        fprintf(stderr,
                  "Error reading control channel\n");
        ret = -1;
        break;
      }
      if (ev.opcode == MGMT_EV_INDEX_ADDED && ev.index == hci_interface) {
        goto end;
      } else if (ev.opcode == MGMT_EV_COMMAND_COMP) {
        struct mgmt_event_read_index *cc;
        int i;
        cc = (struct mgmt_event_read_index *)ev.data;
        if (cc->cc_opcode != MGMT_OP_INDEX_LIST || cc->status != 0)
          continue;
        for (i = 0; i < cc->num_intf; i++) {
          if (cc->index[i] == hci_interface)
            goto end;
        }
      }
    }
  }
end:
  close(fd);
  return ret;
}

