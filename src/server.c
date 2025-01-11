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

int outfd;

static int lib_prehooks(struct lib *lib)
{
	/* TODO: Implement lib_prehooks(). */
	char *output_filename = calloc(strlen(OUTPUT_TEMPLATE) + 1, sizeof(char));
	strcpy(output_filename, OUTPUT_TEMPLATE);
	outfd= mkstemp(output_filename);
	DIE(outfd < 0, "mkstemp");

	lib->outputfile = output_filename;
	printf("%s\n", lib->outputfile);
	fflush(stdout);
	return 0;
}

static int lib_load(struct lib *lib)
{
	/* TODO: Implement lib_load(). */
	// TODO dlopen()
	void *handle = dlopen(lib->libname, RTLD_LAZY);
	lib->handle = handle;
	return 0;
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */
	// TODO use dlsym to find the function pointer and run
	if (lib->handle == NULL) {
		perror("handle");
		return -1;
	}
	void (*function)(void *) = NULL;
	void (*function2)() = NULL;
	if (lib->funcname[0] != 0) {
		function = dlsym(lib->handle, lib->funcname);
	} else {
		function2 = dlsym(lib->handle, "run");
	}
	// if (function == NULL) {
	// 	perror("function");
	// 	return -1;
	// }



	int stdout_fd = dup(1);
	dup2(outfd, 1);

	setvbuf(stdout, NULL, _IONBF, 0);

	// printf("test\n");

	if (lib->filename[0] != 0) {
		(*function)(lib->filename);
	} else {
		(*function2)();
		// printf("hello\n");
		// write(1, "hello2\n", 8);
		fsync(1);
	}
	// printf("world\n");
	dup2(stdout_fd, 1);
	close (outfd);

	return 0;
}

static int lib_close(struct lib *lib)
{
	/* TODO: Implement lib_close(). */
	// close the handle with dlclose
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

	setvbuf(stdout, NULL, _IONBF, 0);
	/* TODO: Implement server connection. */

	int socketfd = create_socket();

	struct sockaddr_un *addr = calloc(1, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path, strlen(SOCKET_NAME) + 1, SOCKET_NAME);

	unlink(SOCKET_NAME);
	rc = bind(socketfd, (struct sockaddr *) addr, sizeof(*addr));
	DIE(rc < 0, "bind");

	// TODO: change the number of clients that can be queued (for multi_threading)
	rc = listen(socketfd, 1);
	DIE(rc < 0, "listen");

	int ret;
	// struct lib lib;

	while (1) {
		/* TODO - get message from client */
		
		int client_fd = accept(socketfd, NULL, NULL);
		printf("clientfd = %d\n", client_fd);
		DIE(client_fd < 0, "accept");


		char *raw_data = calloc(4 * BUFSIZE, sizeof(char));

		rc = recv_socket(client_fd, raw_data, 4 * BUFSIZE);

		/* TODO - parse message with parse_command and populate lib */

		struct lib *client_data = calloc(1, sizeof(struct lib));
		client_data->libname = calloc(BUFSIZE, sizeof(char));
		client_data->funcname = calloc(BUFSIZE, sizeof(char));
		client_data->filename = calloc(BUFSIZE, sizeof(char));

		parse_command(raw_data, client_data->libname, client_data->funcname, client_data->filename);

		printf("%s %s %s\n", client_data->libname, client_data->funcname, client_data->filename);

		fflush(stdout);

		// client_data->outputfile = calloc(BUFSIZE, sizeof(char));
		
		/* TODO - handle request from client */
		ret = lib_run(client_data);

		send_socket(client_fd, client_data->outputfile, strlen(client_data->outputfile) + 1);
		// free(raw_data);
		close (client_fd);
	}

	return 0;
}
