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

#ifndef CONFIG_H
#define CONFIG_H

#define DEFAULT_SECURE_DOMAIN "nic.cz"
#define DEFAULT_BROKEN_DOMAIN "dnssec-failed.org"
#define DEFAULT_TIME "3"
#define DEFAULT_TRIES "2"
#define DEFAULT_DEBUG 0
#define CONF_FILE_PATH "/etc/dnssec-check/dnssec-check.conf"

typedef struct {
    const char* secure_domain;
    const char* broken_domain;
    const char* dig_time;
    const char* dig_tries;
    int debug;
} dnssec_config;

int load_config(dnssec_config *cfg);

#endif	

