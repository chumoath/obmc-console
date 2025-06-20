/**
 * Copyright © 2016 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <termios.h> /* for speed_t */
#include <time.h>
#include <systemd/sd-bus.h>
#include <sys/time.h>
#include <sys/un.h>

struct console;
struct config;

/* Handler API.
 *
 * Console data handlers: these implement the functions that process
 * data coming out of the main tty device.
 *
 * Handlers are registered at link time using the console_handler_register()
 * macro. We call each handler's ->init() function at startup, and ->fini() at
 * exit.
 *
 * Handlers will almost always want to register a ringbuffer consumer, which
 * provides data coming from the tty. Use cosole_register_ringbuffer_consumer()
 * for this. To send data to the tty, use console_data_out().
 *
 * If a handler needs to monitor a separate file descriptor for events, use the
 * poller API, through console_poller_register().
 */
struct handler;

struct handler_type {
	const char *name;
	struct handler *(*init)(const struct handler_type *type,
				struct console *console, struct config *config);
	void (*fini)(struct handler *handler);
	int (*baudrate)(struct handler *handler, speed_t baudrate);
	void (*deselect)(struct handler *handler);
};

struct handler {
	const struct handler_type *type;
};

/* NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) */
#define __handler_name(n) __handler_##n
#define _handler_name(n)  __handler_name(n)

#ifndef __clang__
#define handler_type_check(h) BUILD_ASSERT_OR_ZERO((h)->init && (h)->fini)
#else
/* clang doesn't seem to be able to constify the type ops */
#define handler_type_check(h) 0
#endif

#define console_handler_register(h)                                            \
	static const __attribute__((section("handlers")))                      \
	__attribute__((used)) struct handler_type *                            \
	_handler_name(__COUNTER__) = (h) + handler_type_check(h)
/* NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) */

int console_data_out(struct console *console, const uint8_t *data, size_t len);

enum poller_ret {
	POLLER_OK = 0,
	POLLER_REMOVE,
	POLLER_EXIT,
};

typedef char(socket_path_t)[sizeof(((struct sockaddr_un *)NULL)->sun_path)];

typedef enum poller_ret (*poller_event_fn_t)(struct handler *handler,
					     int revents, void *data);
typedef enum poller_ret (*poller_timeout_fn_t)(struct handler *handler,
					       void *data);

enum tty_device {
	TTY_DEVICE_UNDEFINED = 0,
	TTY_DEVICE_VUART,
	TTY_DEVICE_UART,
	TTY_DEVICE_PTY,
};

struct console_server {
	struct {
		const char *kname;
		char *dev;
		int fd;
		enum tty_device type;
		union {
			struct {
				char *sysfs_devnode;
				int sirq;
				uint16_t lpc_addr;
			} vuart;
			struct {
				speed_t baud;
			} uart;
		};
	} tty;

	// All the pollfds are stored here,
	// so 'poll' can operate on them.
	// The other 'pollfd*' are just pointers to this array.
	struct pollfd *pollfds;
	size_t capacity_pollfds;

	// index into pollfds
	size_t tty_pollfd_index;

	struct config *config;

	// the currently active console
	struct console *active;

	struct console **consoles;
	size_t n_consoles;

	// index into (struct console_server)->pollfds
	size_t dbus_pollfd_index;

	struct sd_bus *bus;

	// may be NULL in case there is no mux
	struct console_mux *mux;
};

struct console {
	// point back to the console server
	// which we are a member of
	struct console_server *server;

	const char *console_id;

	/* Socket name starts with null character hence we need length */
	socket_path_t socket_name;
	ssize_t socket_name_len;

	struct ringbuffer *rb;

	struct handler **handlers;
	long n_handlers;

	struct poller **pollers;
	long n_pollers;

	// values to configure the mux
	unsigned long mux_index;
	const char *tty_name;
	const char *exec_name;
	sighandler_t sighandler_save;
};

/* poller API */
struct poller {
	struct handler *handler;
	void *data;
	poller_event_fn_t event_fn;
	poller_timeout_fn_t timeout_fn;
	struct timeval timeout;
	bool remove;

	// index into (struct console_server)->pollfds
	size_t pollfd_index;
};

struct poller *console_poller_register(struct console *console,
				       struct handler *handler,
				       poller_event_fn_t poller_fn,
				       poller_timeout_fn_t timeout_fn, int fd,
				       int events, void *data);

void console_poller_unregister(struct console *console, struct poller *poller);

void console_poller_set_events(struct console *console, struct poller *poller,
			       int events);

void console_poller_set_timeout(struct console *console, struct poller *poller,
				const struct timeval *tv);

/* ringbuffer API */

enum ringbuffer_poll_ret {
	RINGBUFFER_POLL_OK = 0,
	RINGBUFFER_POLL_REMOVE,
};

typedef enum ringbuffer_poll_ret (*ringbuffer_poll_fn_t)(void *data,
							 size_t force_len);

struct ringbuffer_consumer;

struct ringbuffer {
	uint8_t *buf;
	size_t size;
	size_t tail;
	struct ringbuffer_consumer **consumers;
	int n_consumers;
};

struct ringbuffer_consumer {
	struct ringbuffer *rb;
	ringbuffer_poll_fn_t poll_fn;
	void *poll_data;
	size_t pos;
};

struct ringbuffer *ringbuffer_init(size_t size);
void ringbuffer_fini(struct ringbuffer *rb);

struct ringbuffer_consumer *
ringbuffer_consumer_register(struct ringbuffer *rb,
			     ringbuffer_poll_fn_t poll_fn, void *data);

void ringbuffer_consumer_unregister(struct ringbuffer_consumer *rbc);

int ringbuffer_queue(struct ringbuffer *rb, uint8_t *data, size_t len);

size_t ringbuffer_dequeue_peek(struct ringbuffer_consumer *rbc, size_t offset,
			       uint8_t **data);

int ringbuffer_dequeue_commit(struct ringbuffer_consumer *rbc, size_t len);

size_t ringbuffer_len(struct ringbuffer_consumer *rbc);

/* console wrapper around ringbuffer consumer registration */
struct ringbuffer_consumer *
console_ringbuffer_consumer_register(struct console *console,
				     ringbuffer_poll_fn_t poll_fn, void *data);

/* Console server API */
void tty_init_termios(struct console_server *server);

/* socket paths */
ssize_t console_socket_path(socket_path_t path, const char *id);
ssize_t console_socket_path_readable(const struct sockaddr_un *addr,
				     size_t addrlen, socket_path_t path);

/* utils */
int write_buf_to_fd(int fd, const uint8_t *buf, size_t len);

/* console_server dbus */
int dbus_server_init(struct console_server *server);
void dbus_server_fini(struct console_server *server);

/* console-dbus API */
int dbus_init(struct console *console,
	      struct config *config __attribute__((unused)));

/* socket-handler API */
int dbus_create_socket_consumer(struct console *console);

#ifndef offsetof
#define offsetof(type, member) ((unsigned long)&((type *)NULL)->member)
#endif

#define container_of(ptr, type, member)                                        \
	((type *)((void *)((char *)(ptr) - offsetof(type, member))))

#define BUILD_ASSERT(c)                                                        \
	do {                                                                   \
		char __c[(c) ? 1 : -1] __attribute__((unused));                \
	} while (0)

#define BUILD_ASSERT_OR_ZERO(c) (sizeof(char[(c) ? 1 : -1]) - 1)

// returns the index of that pollfd in server->pollfds
// we cannot return a pointer because 'realloc' may move server->pollfds
ssize_t console_server_request_pollfd(struct console_server *server, int fd,
				      short int events);

int console_server_release_pollfd(struct console_server *server,
				  size_t pollfd_index);
