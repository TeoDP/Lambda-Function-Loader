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
	return -1;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	/* TODO: Implement recv_socket(). */
	// TOOD get the data from the client 
	return -1;
}

void close_socket(int fd)
{
	/* TODO: Implement close_socket(). */
}
