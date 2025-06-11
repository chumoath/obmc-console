#include <assert.h>
#include <err.h>
#include <errno.h>
#include <gpiod.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>

#include "console-server.h"
#include "console-mux.h"
#include "config.h"

struct console_gpio {
	char *name;
	struct gpiod_line *line;
};

struct console_mux {
	struct console_gpio *mux_gpios;
	size_t n_mux_gpios;
};

static const char *key_mux_gpios = "mux-gpios";
static const char *key_mux_index = "mux-index";

__attribute__((nonnull)) static size_t strtokcnt(const char *str,
						 const char sep)
{
	ssize_t n = 1;

	while (*str) {
		if (*str == sep) {
			n++;
		}
		str++;
	}

	return n;
}

__attribute__((nonnull)) static size_t
count_mux_gpios(const char *config_mux_gpios)
{
	return strtokcnt(config_mux_gpios, ',');
}

__attribute__((nonnull)) static char *
extract_mux_gpio_name(const char **config_gpio_names)
{
	const char *current;
	const char *comma;
	ptrdiff_t length;

	assert(*config_gpio_names);
	current = *config_gpio_names;
	comma = strchrnul(current, ',');
	length = comma - current;

	if (length == 0) {
		return NULL;
	}

	char *word = calloc(length + 1, 1);
	if (!word) {
		return NULL;
	}

	strncpy(word, current, length);

	*config_gpio_names = comma + !!(*comma);

	return word;
}

__attribute__((nonnull)) static struct console_gpio *
console_mux_find_gpio_by_index(struct console_gpio *gpio,
			       const char **config_gpio_names)
{
	assert(*config_gpio_names);

	gpio->name = extract_mux_gpio_name(config_gpio_names);
	if (gpio->name == NULL) {
		warnx("could not extract mux gpio name from config '%s'",
		      *config_gpio_names);
		return NULL;
	}

	gpio->line = gpiod_line_find(gpio->name);
	if (gpio->line == NULL) {
		warnx("libgpiod: could not find line %s", gpio->name);
		free(gpio->name);
		return NULL;
	}

	return gpio;
}

__attribute__((nonnull)) static void
console_mux_release_gpio_lines(struct console_server *server)
{
	for (unsigned long i = 0; i < server->mux->n_mux_gpios; i++) {
		struct console_gpio *gpio = &server->mux->mux_gpios[i];
		gpiod_line_release(gpio->line);
		gpiod_line_close_chip(gpio->line);

		free(gpio->name);
		gpio->name = NULL;
	}
}

__attribute__((nonnull)) static int
console_mux_request_gpio_lines(struct console_server *server,
			       const char *config_gpio_names)
{
	const char *current = config_gpio_names;
	struct console_gpio *gpio;
	int status = 0;

	for (server->mux->n_mux_gpios = 0; *current;
	     server->mux->n_mux_gpios++) {
		size_t i = server->mux->n_mux_gpios;
		gpio = console_mux_find_gpio_by_index(
			&server->mux->mux_gpios[i], &current);
		if (gpio == NULL) {
			console_mux_release_gpio_lines(server);
			return -1;
		}

		status = gpiod_line_request_output(
			gpio->line, program_invocation_short_name, 0);
		if (status != 0) {
			warnx("could not set line %s as output", gpio->name);
			warnx("releasing all lines already requested");
			console_mux_release_gpio_lines(server);
			return -1;
		}
	}

	return 0;
}

int console_server_mux_init(struct console_server *server)
{
	const char *config_gpio_names;
	size_t max_ngpios;
	size_t ngpios;

	config_gpio_names = config_get_value(server->config, key_mux_gpios);
	if (!config_gpio_names) {
		return 0;
	}

	ngpios = count_mux_gpios(config_gpio_names);
	max_ngpios = sizeof(((struct console *)0)->mux_index) * CHAR_BIT;
	if (ngpios > max_ngpios) {
		return -1;
	}

	server->mux = calloc(1, sizeof(struct console_mux));
	if (!server->mux) {
		return -1;
	}

	server->mux->n_mux_gpios = 0;
	server->mux->mux_gpios = calloc(ngpios, sizeof(struct console_gpio));
	if (!server->mux->mux_gpios) {
		return -1;
	}

	return console_mux_request_gpio_lines(server, config_gpio_names);
}

void console_server_mux_fini(struct console_server *server)
{
	if (!server->mux) {
		return;
	}

	console_mux_release_gpio_lines(server);

	free(server->mux->mux_gpios);
	server->mux->mux_gpios = NULL;

	free(server->mux);
	server->mux = NULL;
}

int console_mux_init(struct console *console, struct config *config)
{
	if (!console->server->mux) {
		return 0;
	}

	if (console->server->mux->n_mux_gpios == 0) {
		return 0;
	}

	const char *gpio_value = config_get_section_value(
		config, console->console_id, key_mux_index);

	if (gpio_value == NULL) {
		warnx("console %s does not have property %s in config",
		      console->console_id, key_mux_index);
		return -1;
	}

	errno = 0;
	console->mux_index = strtoul(gpio_value, NULL, 0);
	if (errno == ERANGE) {
		return -1;
	}

	return 0;
}

static int console_timestamp(char *buffer, size_t size)
{
	size_t status;
	time_t rawtime;
	struct tm *timeinfo;

	time(&rawtime);
	timeinfo = gmtime(&rawtime);

	status = strftime(buffer, size, "%Y-%m-%d %H:%M:%S UTC", timeinfo);
	return !status;
}

static int console_print_timestamped(struct console *console,
				     const char *message)
{
#define TIMESTAMP_MAX_SIZE 32
	char buf_timestamp[TIMESTAMP_MAX_SIZE];
	int status;
	char *buf;

	status = console_timestamp(buf_timestamp, sizeof(buf_timestamp));
	if (status != 0) {
		warnx("Error: unable to print timestamp");
		return status;
	}

	status = asprintf(&buf, "[obmc-console] %s %s\n", buf_timestamp,
			  message);
	if (status == -1) {
		return -1;
	}

	ringbuffer_queue(console->rb, (uint8_t *)buf, strlen(buf));

	free(buf);

	return 0;
}

static int console_mux_set_lines(struct console *console)
{
	int status = 0;

	for (size_t i = 0; i < console->server->mux->n_mux_gpios; i++) {
		struct console_gpio *gpio = &console->server->mux->mux_gpios[i];
		const uint8_t value = (console->mux_index >> i) & 0x1;

		status = gpiod_line_set_value(gpio->line, value);
		if (status != 0) {
			warnx("could not set line %s", gpio->name);
			return -1;
		}
	}

	return 0;
}

int tty_init(struct console_server *server, struct config *config,
                    const char *tty_arg);
void tty_fini(struct console_server *server);

static pid_t child_pid = -1;
static char pty_line[64];
static struct console *active_console = NULL;

void start_debug(const char *exec)
{
	child_pid = vfork();
	if (child_pid == 0) {
		close(0);
		open(pty_line, O_RDWR);
		dup2(0, 1);
		dup2(0, 2);
		struct termios termbuf;
		tcgetattr(0, &termbuf);
		termbuf.c_lflag |= ECHO;
		termbuf.c_oflag |= ONLCR | XTABS;
		termbuf.c_iflag |= ICRNL;
		termbuf.c_iflag &= ~IXOFF;
		tcsetattr(STDIN_FILENO, TCSANOW, &termbuf);
		char *envp[] = {"TERM=xterm",
			"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/0/bus",
			"DBUS_STARTER_BUS_TYPE=system",
			NULL};
		execve(exec, NULL, envp);
		exit(-2);
	}
}

void handle_sigchld(int sig)
{
	int status;
	pid_t pid;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (pid == child_pid) {
			printf ("Child process %d exited, status = %d, Restarting...\n", pid, status);
			start_debug(active_console->exec_name);
		}
	}
}

int pty_init(struct console *console)
{
	int p;
	struct console_server *server = console->server;

	console->sighandler_save = signal(SIGCHLD, handle_sigchld);

	p = open("/dev/ptmx", O_RDWR);
	if ( p >= 0) {
		grantpt(p);
		unlockpt(p);
		if (ptsname_r(p, pty_line, 63) != 0) {
			exit(-2);
		}
		pty_line[63] = '\0';
	}

	printf ("pty_line = %s\n", pty_line);
	start_debug(console->exec_name);

	server->tty.fd = p;
	int index = console_server_request_pollfd(server, server->tty.fd, POLLIN);
	if (index < 0) {
		return -1;
	}

	server->tty_pollfd_index = (size_t)index;

	return 0;
}

void pty_fini(struct console_server *server)
{
        if (server->tty_pollfd_index < server->capacity_pollfds) {
                console_server_release_pollfd(server, server->tty_pollfd_index);
                server->tty_pollfd_index = SIZE_MAX;
        }

	signal(SIGCHLD, server->active->sighandler_save);

	if (child_pid != -1) {
		if (kill(child_pid, SIGTERM) < 0) {
			perror("kill debug process failed");
			kill(child_pid, SIGKILL);
		} else {
			printf ("Sent SIGTERM to debug process %d\n", child_pid);
		}

		int status;
		if (waitpid(child_pid, &status, 0) < 0) {
			perror("waitpid failed");
		} else {
			if (WIFEXITED(status)) {
				printf ("Child exited with status %d\n", WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				printf ("Child killed by signal %d\n", WTERMSIG(status));
			}
		}
	}
	child_pid = -1;
}

int console_mux_activate(struct console *console)
{
	struct console_server *server = console->server;
	const bool first_activation = server->active == NULL;
	const bool is_active = server->active == console;
	int status = 0;

	if (is_active) {
		return 0;
	}

	if (server->active) {
		if (strncmp(server->active->console_id, "debug", 5)) {
			tty_fini(server);
		} else {
			pty_fini(server);
		}
	}

	if (!strncmp(console->console_id, "debug", 5)) {
		pty_init(console);
	} else {
		tty_init(server, server->config, console->tty_name);
	}

	if (server->mux) {
		status = console_mux_set_lines(console);
	}

	if (status != 0) {
		warnx("Error: unable to set mux gpios");
		return status;
	}

	server->active = console;

	active_console = console;

	/* Don't print disconnect/connect events on startup */
	if (first_activation) {
		return 0;
	}

	for (size_t i = 0; i < server->n_consoles; i++) {
		struct console *other = server->consoles[i];
		if (other == console) {
			continue;
		}
		console_print_timestamped(other, "DISCONNECTED");

		for (long j = 0; j < other->n_handlers; j++) {
			struct handler *h = other->handlers[j];

			if (h->type->deselect) {
				h->type->deselect(h);
			}
		}
	}

	console_print_timestamped(console, "CONNECTED");

	return 0;
}
