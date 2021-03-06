/*	$OpenBSD: proc.h,v 1.7 2018/08/05 08:16:24 mestre Exp $	*/

/*
 * Copyright (c) 2010-2015 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <imsg.h>
#include <event.h>
#include "types.h"

#ifndef _PROC_H
#define _PROC_H

struct control_sock {
	const char	*cs_name;
	struct event	 cs_ev;
	struct event	 cs_evt;
	int		 cs_fd;
	int		 cs_restricted;
	void		*cs_env;

	TAILQ_ENTRY(control_sock) cs_entry;
};
TAILQ_HEAD(control_socks, control_sock);

struct privsep_pipes {
	int				*pp_pipes[PROC_MAX];
};

struct privsep {
	struct privsep_pipes		*ps_pipes[PROC_MAX];
	struct privsep_pipes		*ps_pp;

	struct imsgev			*ps_ievs[PROC_MAX];
	const char			*ps_title[PROC_MAX];
	pid_t				 ps_pid[PROC_MAX];
	struct passwd			*ps_pw;
	int				 ps_noaction;

	struct control_sock		 ps_csock;
	struct control_socks		 ps_rcsocks;

	unsigned int			 ps_instances[PROC_MAX];
	unsigned int			 ps_instance;

	/* Event and signal handlers */
	struct event			 ps_evsigint;
	struct event			 ps_evsigterm;
	struct event			 ps_evsigchld;
	struct event			 ps_evsighup;
	struct event			 ps_evsigpipe;
	struct event			 ps_evsigusr1;

	void				*ps_env;
};

struct privsep_proc {
	const char		*p_title;
	enum privsep_procid	 p_id;
	int			(*p_cb)(int, struct privsep_proc *,
				    struct imsg *);
	void			(*p_init)(struct privsep *,
				    struct privsep_proc *);
	const char		*p_chroot;
	struct privsep		*p_ps;
	void			(*p_shutdown)(void);
	struct passwd		*p_pw;
};

struct privsep_fd {
	enum privsep_procid		 pf_procid;
	unsigned int			 pf_instance;
};

struct imsgev {
	struct imsgbuf		 ibuf;
	void			(*handler)(int, short, void *);
	struct event		 ev;
	struct privsep_proc	*proc;
	void			*data;
	short			 events;
	const char		*name;
};

#ifndef IMSG_DATA_SIZE
#define	IMSG_DATA_SIZE(_imsg)	((_imsg)->hdr.len - IMSG_HEADER_SIZE)
#endif

#ifndef IMSG_SIZE_CHECK
#define	IMSG_SIZE_CHECK(_imsg, _type)				\
	do {							\
		if (IMSG_DATA_SIZE(_imsg) < sizeof(*(_type)))	\
			fatal("received imsg size was wrong.");	\
	} while (0 /* CONSTCOND */)
#endif

#if DEBUG
#define DPRINTF		log_debug
#else
#define DPRINTF(x...)	do {} while(0)
#endif

#define PROC_PARENT_SOCK_FILENO 3
#define PROC_MAX_INSTANCES      32

struct ctl_conn {
	TAILQ_ENTRY(ctl_conn)		 entry;
	uint8_t				 flags;
#define CTL_CONN_NOTIFY			 0x01
	struct imsgev			 iev;
	int				 restricted;
};
TAILQ_HEAD(ctl_connlist, ctl_conn);
extern  struct ctl_connlist ctl_conns;

/* proc.c */
void	 proc_init(struct privsep *, struct privsep_proc *, unsigned int, int,
	    int, char **, enum privsep_procid);
void	 proc_kill(struct privsep *);
void	 proc_connect(struct privsep *ps);
void	 proc_dispatch(int, short event, void *);
void	 proc_run(struct privsep *, struct privsep_proc *,
	    struct privsep_proc *, unsigned int,
	    void (*)(struct privsep *, struct privsep_proc *, void *), void *);
void	 imsg_event_add(struct imsgev *);
int	 imsg_compose_event(struct imsgev *, uint16_t, uint32_t,
	    pid_t, int, void *, uint16_t);
int	 imsg_composev_event(struct imsgev *, uint16_t, uint32_t,
	    pid_t, int, const struct iovec *, int);
int	 proc_compose_imsg(struct privsep *, enum privsep_procid, int,
	    uint16_t, uint32_t, int, void *, uint16_t);
int	 proc_compose(struct privsep *, enum privsep_procid,
	    uint16_t, void *data, uint16_t);
int	 proc_composev_imsg(struct privsep *, enum privsep_procid, int,
	    uint16_t, uint32_t, int, const struct iovec *, int);
int	 proc_composev(struct privsep *, enum privsep_procid,
	    uint16_t, const struct iovec *, int);
int	 proc_forward_imsg(struct privsep *, struct imsg *,
	    enum privsep_procid, int);
struct imsgbuf *
	 proc_ibuf(struct privsep *, enum privsep_procid, int);
struct imsgev *
	 proc_iev(struct privsep *, enum privsep_procid, int);
enum privsep_procid
	 proc_getid(struct privsep_proc *, unsigned int, const char *);
int	 proc_flush_imsg(struct privsep *, enum privsep_procid, int);

/* control.c */
int	 control_init(struct privsep *, struct control_sock *);
int	 control_listen(struct control_sock *);
struct ctl_conn
	*control_connbyfd(int);
void	 control(struct privsep *, struct privsep_proc *);

/* log.c */
void	log_init(int, int);
void	log_procinit(const char *);
void	log_setverbose(int);
int	log_getverbose(void);
void	log_warn(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_warnx(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_info(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_debug(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	logit(int, const char *, ...)
	    __attribute__((__format__ (printf, 2, 3)));
void	vlog(int, const char *, va_list)
	    __attribute__((__format__ (printf, 2, 0)));
__dead void fatal(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
__dead void fatalx(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));

void	 socket_set_blockmode(int, enum blockmodes);

#endif /* _PROC_H */
