/*
 * dnssec-check - Simple DNSSEC validation tool
 * Copyright (C) 2025 Liu Yu <f78fk@live.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include "config.h"

#define DEFAULT_DIG_PATH "/usr/bin/dig"

#define BUF_SIZE 8192
#define EXIT_SUCCESS           0
#define EXIT_GENERAL_ERROR     1
#define EXIT_DIG_NOT_FOUND    127

static int g_debug_enabled = DEFAULT_DEBUG;
#define DEBUG_PRINT(fmt, ...) \
    do { if (g_debug_enabled) printf("[DEBUG] " fmt, ##__VA_ARGS__); } while (0)

static char g_dig_path[512] = DEFAULT_DIG_PATH;
static dnssec_config config = {0};

static void handle_signal(int sig)
{
 	const char prefix[] = "\nReceived signal ";
    const char suffix[] = ", shutting down gracefully...\n";
    char num_buf[16];
    int n = sig;
    int num_len = 0;
    do {
        num_buf[num_len++] = "0123456789"[n % 10];
        n /= 10;
    } while (n > 0);
    for (int i = 0; i < num_len / 2; i++) {
        char tmp = num_buf[i];
        num_buf[i] = num_buf[num_len - 1 - i];
        num_buf[num_len - 1 - i] = tmp;
    }
	
    write(STDOUT_FILENO, prefix, strlen(prefix));
    write(STDOUT_FILENO, num_buf, num_len);
    write(STDOUT_FILENO, suffix, strlen(suffix));
    _exit(EXIT_SUCCESS);
}

static void setup_signal_handlers()
{
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
}

static int run_dig(const char *domain, const char *args[], char *output_buf,
		   size_t buf_size, char *err_buf)
{
	int pipe_fd[2];
	if (pipe(pipe_fd) == -1)
		return 0;

	pid_t pid = fork();
	if (pid < 0)
		return 0;

	if (pid == 0) {
		close(pipe_fd[0]);
		dup2(pipe_fd[1], STDOUT_FILENO);
		dup2(pipe_fd[1], STDERR_FILENO);
		close(pipe_fd[1]);

		char *argv[16];
		int i = 0;
		argv[i++] = (char *)g_dig_path;
		while (args[i - 1] != NULL && i < 14) {
			argv[i] = (char *)args[i - 1];
			i++;
		}
		argv[i++] = (char *)domain;
		argv[i++] = "A";
		argv[i] = NULL;

		execvp(g_dig_path, argv);
		perror("execvp failed");
		exit(1);
	} else {
		close(pipe_fd[1]);
		size_t total_read = 0;
		ssize_t bytes_read;
		while ((bytes_read =
			read(pipe_fd[0], output_buf + total_read,
			     buf_size - total_read - 1)) > 0) {
			total_read += bytes_read;
			if (total_read >= buf_size - 1)
				break;
		}
		output_buf[total_read] = '\0';
		close(pipe_fd[0]);

		int status;
		waitpid(pid, &status, 0);
		return WIFEXITED(status) && WEXITSTATUS(status) == 0;
	}
}

static void parse_dig_output(const char *output, int *ad_flag, char *rcode_buf)
{
	*ad_flag = 0;
	strcpy(rcode_buf, "UNKNOWN");

	char *copy = strdup(output);
	if (!copy) {
		fprintf(stderr, "[ERROR] strdup() failed\n");
		return;
	}

	char *line = NULL;
	char *rest = copy;

	DEBUG_PRINT("=== Begin parsing dig output ===\n");

	while ((line = strsep(&rest, "\n")) != NULL) {
		DEBUG_PRINT("LINE: %s\n", line);

		if (strstr(line, "HEADER") && strstr(line, "status:")) {
			DEBUG_PRINT("Found HEADER line with status:\n");

			char *pos = strstr(line, "status:");
			if (pos) {
				pos += strlen("status:");
				while (*pos == ' ')
					pos++;

				sscanf(pos, "%15[^, \n]", rcode_buf);
				DEBUG_PRINT("Parsed rcode_buf: %s\n",
					    rcode_buf);
			} else {
				printf
				    ("[WARN] 'status:' not found in HEADER line\n");
			}

		} else if (strstr(line, "flags:")) {
			DEBUG_PRINT("Found flags line\n");

			char *flag_start = strstr(line, "flags:");
			if (!flag_start)
				continue;

			flag_start += strlen("flags:");
			while (*flag_start == ' ')
				flag_start++;

			char *semi = strchr(flag_start, ';');
			if (semi)
				*semi = '\0';

			DEBUG_PRINT("Extracted flags segment: %s\n",
				    flag_start);

			char *token = strtok(flag_start, " \t");
			while (token) {
				DEBUG_PRINT("Found flag token: %s\n", token);
				if (strcmp(token, "ad") == 0) {
					*ad_flag = 1;
					DEBUG_PRINT
					    ("Found AD flag, set ad_flag = 1\n");
					break;
				}
				token = strtok(NULL, " \t");
			}
		}
	}

	DEBUG_PRINT("=== Finished parsing ===\n");
	free(copy);
}

static int query_domain(const char *domain, const char *args[], int *ad_flag,
			char *rcode, char *error_out)
{
	char output[BUF_SIZE] = { 0 };
	char error[256] = { 0 };

	if (!run_dig(domain, args, output, sizeof(output), error)) {
		snprintf(error_out, 256, "%s",
			 error[0] ? error : "dig execution failed");
		return 0;
	}

	parse_dig_output(output, ad_flag, rcode);
	return 1;
}

static void determine_result(const char *secure_domain, int secure_ad,
			     const char *rcode_secure,
			     const char *broken_domain, int broken_ad,
			     const char *rcode_broken)
{
	printf("Parsed %s: AD=%s, Status=%s\n", secure_domain,
	       secure_ad ? "true" : "false", rcode_secure);
	printf("Parsed %s: AD=%s, Status=%s\n", broken_domain,
	       broken_ad ? "true" : "false", rcode_broken);

	if (strcmp(rcode_broken, "NOERROR") == 0) {
		printf(" -> Severity level: insecure\n");
		return;
	}

	if (strcmp(rcode_secure, "NOERROR") != 0) {
		printf
		    (" -> Severity level: unknown (%s could not be resolved)\n",
		     secure_domain);
		return;
	}

	if (secure_ad && !broken_ad && strcmp(rcode_broken, "SERVFAIL") == 0) {
		printf(" -> Severity level: secure\n");
	} else if (!secure_ad && strcmp(rcode_broken, "SERVFAIL") == 0) {
		printf(" -> Severity level: medium\n");
	} else if (strcmp(rcode_broken, "SERVFAIL") != 0) {
		printf(" -> Severity level: insecure\n");
	} else {
		printf(" -> Severity level: unknown\n");
	}
}

static int find_dig_path(char *buf, size_t buflen)
{
	char *path_env = getenv("PATH");
	if (!path_env)
		return 0;

	char *paths = strdup(path_env);
	char *dir = strtok(paths, ":");
	while (dir) {
		char fullpath[512];
		snprintf(fullpath, sizeof(fullpath), "%s/dig", dir);
		if (access(fullpath, X_OK) == 0) {
			strncpy(buf, fullpath, buflen - 1);
			buf[buflen - 1] = '\0';
			free(paths);
			return 1;
		}
		dir = strtok(NULL, ":");
	}
	free(paths);
	return 0;
}

int main(void)
{
	int exit_code = EXIT_GENERAL_ERROR;
	setup_signal_handlers();

	if ( load_config(&config) < 0 ) {
		printf("Using default configuration.\n");
	} else {
		printf("Loaded configuration from %s\n",CONF_FILE_PATH);
		g_debug_enabled = config.debug;
		DEBUG_PRINT(" secure_domain = %s\n", config.secure_domain);
		DEBUG_PRINT(" broken_domain = %s\n", config.broken_domain);
		DEBUG_PRINT(" dig_time = %s\n", config.dig_time);
		DEBUG_PRINT(" dig_tries = %s\n", config.dig_tries);
		DEBUG_PRINT(" debug = %d\n", config.debug);
	}

	char time_arg[32], tries_arg[32];
	snprintf(time_arg, sizeof(time_arg), "+time=%s", config.dig_time);
	snprintf(tries_arg, sizeof(tries_arg), "+tries=%s", config.dig_tries);
	const char *dig_args[] =
	    { "+dnssec", time_arg, tries_arg, "+multi", NULL };

	if (!find_dig_path(g_dig_path, sizeof(g_dig_path))) {
		fprintf(stderr, "dig not found in PATH\n");
		exit_code = EXIT_DIG_NOT_FOUND;
		goto err;
	}

	printf("[*] Querying %s ...\n", config.secure_domain);
	int secure_ad = 0;
	char rcode_secure[32] = { 0 }, error[256] = { 0 };
	int secure_query_result =
	    query_domain(config.secure_domain, dig_args, &secure_ad, rcode_secure,
			 error);
	if (!secure_query_result)
		fprintf(stderr, "[ERROR] Failed to query %s: %s\n",
			config.secure_domain, error);

	printf("[*] Querying %s ...\n", config.broken_domain);
	int broken_ad = 0;
	char rcode_broken[32] = { 0 };
	int broken_query_result =
	    query_domain(config.broken_domain, dig_args, &broken_ad, rcode_broken,
			 error);
	if (!broken_query_result)
		fprintf(stderr, "[ERROR] Failed to query %s: %s\n",
			config.broken_domain, error);

	if (!secure_query_result || !broken_query_result) {
		exit_code = EXIT_GENERAL_ERROR;
		goto err;
	}

	determine_result(config.secure_domain, secure_ad, rcode_secure,
			 config.broken_domain, broken_ad, rcode_broken);

	exit_code = EXIT_SUCCESS;

err:
    if (config.secure_domain) free((void*)config.secure_domain);
    if (config.broken_domain) free((void*)config.broken_domain);
	if (config.dig_time) free((void*)config.dig_time);
	if (config.dig_tries) free((void*)config.dig_tries);
	return exit_code;	
}
