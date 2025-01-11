// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"


int create_socket(void)
{
	/* TODO: Implement create_socket(). */
	int socketfd = socket(PF_UNIX, SOCK_STREAM, 0);
	DIE(socketfd < 0, "socket");
	struct sockaddr_un *addr = calloc(1, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path, strlen(SOCKET_NAME) + 1, SOCKET_NAME);

	int rc = bind(socketfd, (struct sockaddr *) addr, sizeof(*addr));
	DIE(rc < 0, "bind");
	return socketfd;
}

int connect_socket(int fd)
{
	/* TODO: Implement connect_socket(). */
	// TODO: accept
	int connectfd = accept(fd, NULL, NULL);
	DIE(connectfd < 0, "accept");
	return connectfd;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
	/* TODO: Implement send_socket(). */
	// hello
	int rc = 0;
	int size_left = len;
	// doing a while loop so that if the data cannot be sent in one go, it will be sent through several send calls
	while (size_left > 0) {
		rc = send(fd, buf, size_left, 0);
		// DIE(rc < 0, "send");
		if (rc < 0) {
			perror("send failed");
			return -1;
		}

		size_left -= rc;
		if (rc == 0) {
			break;
		}
	}
	return 0;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	/* TODO: Implement recv_socket(). */
	// TOOD get the data from the client

	while (len > 0) {
		ssize_t rec = recv(fd, buf, sizeof(buf));
		if (rec < 0) {
			perror("receive failed");
			return -1;
		}
		len = len - rec;
		if (rec == 0) {
			break;
		}
	}

	return 0;
}

void close_socket(int fd)
{
	/* TODO: Implement close_socket(). */
}
