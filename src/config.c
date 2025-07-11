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
#include "inih/ini.h"
#include "config.h"

static int handler(void* user, const char* section, const char* name, const char* value) {
    dnssec_config* config = (dnssec_config*)user;

    #define MATCH(s, n) (strcmp(section, s) == 0 && strcmp(name, n) == 0)

    if (MATCH("domains", "secure_domain")) {
        config->secure_domain = strdup(value);
    } else if (MATCH("domains", "broken_domain")) {
        config->broken_domain = strdup(value);
    } else if (MATCH("query", "dig_time")) {
        config->dig_time = strdup(value);
    } else if (MATCH("query", "dig_tries")) {
        config->dig_tries = strdup(value);
    } else if (MATCH("output", "debug")) {
        config->debug = atoi(value);
    } else {
        return 0;
    }
    return 1;
}

int load_config(dnssec_config *cfg) {

    cfg->secure_domain = DEFAULT_SECURE_DOMAIN;
    cfg->broken_domain = DEFAULT_BROKEN_DOMAIN;
    cfg->dig_time = DEFAULT_TIME;
    cfg->dig_tries = DEFAULT_TRIES;
    cfg->debug = DEFAULT_DEBUG;
    
    if (ini_parse(CONF_FILE_PATH, handler, cfg) < 0) {
        fprintf(stderr, "[ERROR] Cannot load config file\n");
        return -1;
    }

    return 0;
}
