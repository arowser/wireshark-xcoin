/* echld-test.c
 *  basic test framework for echld
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copyright (c) 2013 by Luis Ontanon <luis@ontanon.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <sys/time.h>
#include <sys/uio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <glib/gprintf.h>

#include "echld/echld.h"
#include "echld/echld-util.h"

#include "epan/epan.h"
#include "wsutil/str_util.h"

typedef char* (*cmd_cb_t)(char** params, char** err);

typedef struct _cmd_t {
	const char* txt;
	cmd_cb_t cb;
	int args_taken;
	const char* help;
} cmd_t;

static char* new_child_cmd(char** params _U_, char** err) {
	int child = echld_new(NULL);

	if (child <= 0) {
		*err = g_strdup("No child\n");
		return NULL;
	}

	return g_strdup_printf("New chld_id=%d\n",child);;
}


void ping_cb(long usec, void* data) {
	int ping_id = *((int*)data);

	if (usec >= 0) {
		fprintf(stdout, "Ping ping_id=%d returned in %dus\n",ping_id,(int)usec);
	} else {
		fprintf(stdout, "Ping ping_id=%d erored\n",ping_id);
	}

	g_free(data);
}


static char* ping_cmd(char** params, char** err) {
	int child = (int) strtol(params[1], NULL, 10);
	static int ping_id = 0;
	int* ping_data = g_new(int,1);

	*ping_data = ping_id++;

	if (!echld_ping(child,ping_cb,ping_data)) {
		*err = g_strdup_printf("Could not send ping child=%d",child);
		return NULL;
	} else {
		return g_strdup_printf("Ping sent child=%d",child);
	}
}

void param_cb(const char* param, const char* value, const char* error, void* data _U_) {
	if (error) {
		fprintf(stdout, "Param Set Error msg=%s\n", error );
	} else {
		fprintf(stdout, "Param: param='%s' val='%s'\n", param, value );
	}
}

static char* set_cmd(char** params, char** err) {
	int child = (int) strtol(params[1], NULL, 10);
	char* param = params[2];
	char* value = params[3];

	if ( ! echld_set_param(child,param,value,param_cb,NULL) ) {
		*err = g_strdup_printf("Failed to SET child=%d param='%s' value='%s'",child,param,value);
		return NULL;
	} else {
		return g_strdup_printf("Set command sent child=%d param='%s' value='%s'",child,param,value);
	}
}

static char* get_cmd(char** params, char** err) {
	int child = (int) strtol(params[1], NULL, 10);
	char* param = params[2];

	if ( ! echld_get_param(child,param,param_cb,NULL) ) {
		*err = g_strdup_printf("Failed to GET child=%d param='%s'",child,param);
		return NULL;
	} else {
		return g_strdup_printf("Get command sent child=%d param='%s'",child,param);
	}
}

static void close_cb(const char* error, void* data) {
	if (error) {
		fprintf(stdout, "Close Error msg=%s\n", error );
	} else {
		fprintf(stdout, "Closed: child=%d\n", *((int*)data) );
	}
}

static char* close_cmd(char** params, char** err) {
	int child = (int) strtol(params[1], NULL, 10);
	int* cmdp = g_new(int,1);
	*cmdp = child;
	if ( ! echld_close(child,close_cb,cmdp) ) {
		*err = g_strdup_printf("Could not close child=%d",child);
		return NULL;
	} else {
		return g_strdup_printf("CLose command sent child=%d",child);
	}
}
int keep_going = 1;

static char* quit_cmd(char** params _U_, char** err _U_) {
	keep_going = 0;
	return g_strdup("Quitting");
}

static char* help_cmd(char**, char**);

static char* nothing_at_last_cmd(char** pars _U_, char** err _U_) {
	return g_strdup("");
}


cmd_t commands[] = {
	{ "QUIT", quit_cmd, 0, "QUIT"},
	{ "HELP", help_cmd, 0, "HELP"},
	{ "NEW", new_child_cmd, 0, "NEW"},
	{ "PING", ping_cmd, 1, "PING child_id"},
	{ "SET", set_cmd, 3, "SET child_id param_name param_val"},
	{ "GET", get_cmd, 2, "GET child_id param_name"},
	{ "CLOSE", close_cmd, 1, "CLOSE child_id"},
	{ "", nothing_at_last_cmd,0,""},
	{ NULL, NULL, 0, NULL }
};

static char* help_cmd(char** params _U_, char** err _U_) {
	GString* out = g_string_new("Commands:\n");
	cmd_t* c = commands;
	char* s;

	for (;c->txt;c++) {
		g_string_append_printf(out,"%s\n",c->help);
	}
	s = out->str;
	g_string_free(out,FALSE);
	return s;
}





int got_param = 0;


int main(int argc _U_, char** argv _U_) {
	struct timeval tv;
	int tot_cycles = 0;

	tv.tv_sec = 5;
	tv.tv_usec = 0;

	echld_set_parent_dbg_level(5);

	echld_initialize(ECHLD_ENCODING_JSON,argv[0],main);

	do {
		fd_set rfds;
		fd_set efds;
		int nfds;

		FD_ZERO(&rfds);
		FD_ZERO(&efds);
		FD_SET(0,&rfds);
		FD_SET(0,&efds);

		nfds = echld_select(FD_SETSIZE, &rfds, NULL, &efds, &tv);

		if (FD_ISSET(0,&rfds)) {
			size_t len;
			char* cmd_line;

			if(( cmd_line = fgetln(stdin,&len) )) {
				cmd_t* c = commands;
				cmd_line[len] = 0;
				g_strchomp(cmd_line);

				for (;c->txt;c++) {
					if ( strcasestr(cmd_line, c->txt) == cmd_line ) {
						char** params = g_strsplit(cmd_line, " ", c->args_taken+1);
						char* err = NULL;
						char* str = c->cb(params,&err);

						if (err) {
							fprintf(stdout, "Error: %s\n", err);
							g_free(err);
						} else {
							fprintf(stdout, "%s\n", str);
							g_free(str);
						}
						
						g_strfreev(params);
						goto cmd_executed;
					}
				}
				
				fprintf(stdout, "Error: no such command %s\n", cmd_line);
			}
		}

	cmd_executed:
		tot_cycles++;
	} while( keep_going );

	fprintf(stderr, "Done: tot_cycles=%d\n", tot_cycles );

	echld_terminate();
	return 0;
}