/* $OpenBSD: cmd-list-windows.c,v 1.46 2020/04/13 10:59:58 nicm Exp $ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicholas.marriott@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <stdlib.h>
#include <unistd.h>

#include "tmux.h"

/*
 * List windows on given session.
 */

#define LIST_WINDOWS_TEMPLATE					\
	"#{window_index}: #{window_name}#{window_raw_flags} "	\
	"(#{window_panes} panes) "				\
	"[#{window_width}x#{window_height}] "			\
	"[layout #{window_layout}] #{window_id}"		\
	"#{?window_active, (active),}";
#define LIST_WINDOWS_WITH_SESSION_TEMPLATE			\
	"#{session_name}:"					\
	"#{window_index}: #{window_name}#{window_raw_flags} "	\
	"(#{window_panes} panes) "				\
	"[#{window_width}x#{window_height}] "

static enum cmd_retval	cmd_list_windows_exec(struct cmd *, struct cmdq_item *);

static void	cmd_list_windows_server(struct cmd *, struct cmdq_item *);
static void	cmd_list_windows_session(struct cmd *, struct session *,
		    struct cmdq_item *, int);

const struct cmd_entry cmd_list_windows_entry = {
	.name = "list-windows",
	.alias = "lsw",

	.args = { "F:f:at:", 0, 0 },
	.usage = "[-a] [-F format] [-f filter] " CMD_TARGET_SESSION_USAGE,

	.target = { 't', CMD_FIND_SESSION, 0 },

	.flags = CMD_AFTERHOOK,
	.exec = cmd_list_windows_exec
};

static enum cmd_retval
cmd_list_windows_exec(struct cmd *self, struct cmdq_item *item)
{
	struct args		*args = cmd_get_args(self);
	struct cmd_find_state	*target = cmdq_get_target(item);

	if (args_has(args, 'a'))
		cmd_list_windows_server(self, item);
	else
		cmd_list_windows_session(self, target->s, item, 0);

	return (CMD_RETURN_NORMAL);
}

static void
cmd_list_windows_server(struct cmd *self, struct cmdq_item *item)
{
	struct session	*s;

	RB_FOREACH(s, sessions, &sessions)
		cmd_list_windows_session(self, s, item, 1);
}

static void
cmd_list_windows_session(struct cmd *self, struct session *s,
    struct cmdq_item *item, int type)
{
	struct args		*args = cmd_get_args(self);
	struct winlink		*wl;
	u_int			 n;
	struct format_tree	*ft;
	const char		*template, *filter;
	char			*line, *expanded;
	int			 flag;

	template = args_get(args, 'F');
	if (template == NULL) {
		switch (type) {
		case 0:
			template = LIST_WINDOWS_TEMPLATE;
			break;
		case 1:
			template = LIST_WINDOWS_WITH_SESSION_TEMPLATE;
			break;
		}
	}
	filter = args_get(args, 'f');

	n = 0;
	RB_FOREACH(wl, winlinks, &s->windows) {
		ft = format_create(cmdq_get_client(item), item, FORMAT_NONE, 0);
		format_add(ft, "line", "%u", n);
		format_defaults(ft, NULL, s, wl, NULL);

		if (filter != NULL) {
			expanded = format_expand(ft, filter);
			flag = format_true(expanded);
			free(expanded);
		} else
			flag = 1;
		if (flag) {
			line = format_expand(ft, template);
			cmdq_print(item, "%s", line);
			free(line);
		}

		format_free(ft);
		n++;
	}
}
