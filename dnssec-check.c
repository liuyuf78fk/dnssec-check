/*
 * dnssec-check - Simple DNSSEC validation tool
 * Copyright (C) 2025 Liu Yu
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY...
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/wait.h>

#define DIG_COMMAND "dig"
#define BUF_SIZE 8192

void handle_signal(int sig)
{
	printf("\n[INFO] Received signal %d, shutting down gracefully...\n",
	       sig);
	exit(0);
}

void setup_signal_handlers()
{
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
}

bool run_dig(const char *domain, const char *args[], char *output_buf,
	     size_t buf_size, char *err_buf)
{
	int pipe_fd[2];
	if (pipe(pipe_fd) == -1) {
		perror("pipe");
		return false;
	}

	pid_t pid = fork();
	if (pid < 0) {
		perror("fork");
		return false;
	}

	if (pid == 0) {
		close(pipe_fd[0]);
		dup2(pipe_fd[1], STDOUT_FILENO);
		dup2(pipe_fd[1], STDERR_FILENO);
		close(pipe_fd[1]);

		char *argv[16];
		int i = 0;
		argv[i++] = "dig";
		for (int j = 0; args[j] != NULL && i < 14; ++j) {
			argv[i++] = (char *)args[j];
		}
		argv[i++] = (char *)domain;
		argv[i++] = "A";
		argv[i] = NULL;

		execvp(DIG_COMMAND, argv);
		perror("execvp failed");
		exit(1);
	} else {
		close(pipe_fd[1]);
		ssize_t total_read = read(pipe_fd[0], output_buf, buf_size - 1);
		if (total_read >= 0) {
			output_buf[total_read] = '\0';
		} else {
			snprintf(err_buf, 256, "Failed to read dig output.");
		}
		close(pipe_fd[0]);

		int status;
		waitpid(pid, &status, 0);
		return WIFEXITED(status) && WEXITSTATUS(status) == 0;
	}
}

void parse_dig_output(const char *output, bool *ad_flag, char *rcode_buf)
{
	*ad_flag = false;
	strcpy(rcode_buf, "UNKNOWN");

	char *line = NULL;
	char *copy = strdup(output);
	char *rest = copy;

	while ((line = strsep(&rest, "\n")) != NULL) {
		if (strstr(line, ";; ->>HEADER<<-")) {
			char *pos = strstr(line, "status:");
			if (pos) {
				sscanf(pos, "status: %15s", rcode_buf);
				char *comma = strchr(rcode_buf, ',');
				if (comma)
					*comma = '\0';
			}
		} else if (strstr(line, ";; flags:")) {
			char *flag_start = strstr(line, "flags:");
			if (flag_start) {
				flag_start += 6;
				char *semi = strchr(flag_start, ';');
				if (semi)
					*semi = '\0';
				char *token = strtok(flag_start, " \t");
				while (token) {
					if (strcmp(token, "ad") == 0) {
						*ad_flag = true;
						break;
					}
					token = strtok(NULL, " \t");
				}
			}
		}
	}

	free(copy);
}

bool query_domain(const char *domain, bool *ad, char *rcode, char *error_out)
{
	const char *args[] =
	    { "+dnssec", "+time=3", "+tries=2", "+multi", NULL };
	char output[BUF_SIZE] = { 0 };
	char error[256] = { 0 };

	bool success = run_dig(domain, args, output, sizeof(output), error);
	if (!success) {
		snprintf(error_out, 256, "%s",
			 error[0] ? error : "dig execution failed");
		return false;
	}

	parse_dig_output(output, ad, rcode);
	return true;
}

void determine_result(bool nic_ad, const char *nic_rcode, bool failed_ad,
		      const char *failed_rcode)
{
	printf("Parsed nic.cz: AD=%s, Status=%s\n", nic_ad ? "true" : "false",
	       nic_rcode);
	printf("Parsed dnssec-failed.org: AD=%s, Status=%s\n",
	       failed_ad ? "true" : "false", failed_rcode);

	if (strcmp(failed_rcode, "NOERROR") == 0) {
		printf(" -> Severity level: insecure\n");
		return;
	}

	if (strcmp(nic_rcode, "NOERROR") != 0) {
		printf
		    (" -> Severity level: unknown (nic.cz could not be resolved)\n");
		return;
	}

	if (nic_ad && !failed_ad && strcmp(failed_rcode, "SERVFAIL") == 0) {
		printf
		    (" -> Severity level: secure (local resolver validates DNSSEC correctly)\n");
	} else if (!nic_ad && strcmp(failed_rcode, "SERVFAIL") == 0) {
		printf
		    (" -> Severity level: medium (upstream validates but local does not)\n");
	} else if (strcmp(failed_rcode, "SERVFAIL") != 0) {
		printf
		    (" -> Severity level: insecure (dnssec-failed.org resolved incorrectly)\n");
	} else {
		printf(" -> Severity level: unknown\n");
	}
}

int main(void)
{
	setup_signal_handlers();

	bool nic_ad = false, failed_ad = false;
	char nic_rcode[32] = { 0 };
	char failed_rcode[32] = { 0 };
	char error[256] = { 0 };

	printf("[*] Querying nic.cz ...\n");
	bool ok1 = query_domain("nic.cz", &nic_ad, nic_rcode, error);
	if (!ok1) {
		fprintf(stderr, "[ERROR] Failed to query nic.cz: %s\n", error);
	}

	printf("[*] Querying dnssec-failed.org ...\n");
	bool ok2 =
	    query_domain("dnssec-failed.org", &failed_ad, failed_rcode, error);
	if (!ok2) {
		fprintf(stderr,
			"[ERROR] Failed to query dnssec-failed.org: %s\n",
			error);
	}

	printf("\n[RESULT] Validation outcome:\n");
	if (!ok1 || !ok2) {
		printf(" -> Severity level: tool-error\n");
	} else {
		determine_result(nic_ad, nic_rcode, failed_ad, failed_rcode);
	}

	return 0;
}
