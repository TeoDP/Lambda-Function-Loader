// SPDX-License-Identifier: BSD-3-Clause

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "ipc.h"
#include "server.h"

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

static int lib_prehooks(struct lib *lib)
{
	/* TODO: Implement lib_prehooks(). */
	return 0;
}

static int lib_load(struct lib *lib)
{
	/* TODO: Implement lib_load(). */
	return 0;
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */
	return 0;
}

static int lib_close(struct lib *lib)
{
	/* TODO: Implement lib_close(). */
	return 0;
}

static int lib_posthooks(struct lib *lib)
{
	/* TODO: Implement lib_posthooks(). */
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_load(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	int ret;

	ret = sscanf(buf, "%s %s %s", name, func, params);
	if (ret < 0)
		return -1;

	return ret;
}

int main(void)
{
	int rc = 0;
	/* TODO: Implement server connection. */

	int socketfd = create_socket();

	struct sockaddr_un *addr = calloc(1, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path, strlen(SOCKET_NAME) + 1, SOCKET_NAME);
	
	rc = bind(socketfd, (struct sockaddr *) addr, sizeof(*addr));
	DIE(rc < 0, "bind");

	// TODO: change the number of clients that can be queued (for multi_threading)
	rc = listen(socketfd, 1);
	DIE(rc < 0, "listen");

	int ret;
	struct lib lib;

	while (1) {
		/* TODO - get message from client */

		struct sockaddr_un *client_addr = calloc(1, sizeof(*addr));
		client_addr->sun_family = AF_UNIX;
		snprintf(client_addr->sun_path, strlen(SOCKET_NAME) + 1, SOCKET_NAME);
		
		int client_fd = accept(socketfd, (struct sockaddr *) client_addr, sizeof(*client_addr));

		char *raw_data = calloc(4 * BUFSIZE, sizeof(char));

		rc = recv_socket(client_fd, raw_data, sizeof(raw_data));

		/* TODO - parse message with parse_command and populate lib */

		struct lib *client_data = calloc(1, sizeof(struct lib));
		client_data->libname = calloc(BUFSIZE, sizeof(char));
		client_data->funcname = calloc(BUFSIZE, sizeof(char));
		client_data->filename = calloc(BUFSIZE, sizeof(char));

		parse_command(raw_data, client_data->libname, client_data->funcname, client_data->filename);
		
		/* TODO - handle request from client */
		ret = lib_run(&lib);
	}

	return 0;
}
