/*
 * Copyright 2021, the University of Queensland
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <err.h>
#include <syslog.h>
#include <fcntl.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/cdefs.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/un.h>
#include <sys/pfexec.h>
#include <sys/pfexecvar.h>

#include <event.h>

const off_t CONFIG_MAX_SIZE	= 16777216LL;	/* 16 MB */
const size_t BACKLOG		= 8;

struct client {
	TAILQ_ENTRY(client)		 c_entry;
	struct sockaddr_storage		 c_raddr;
	int				 c_fd;
	struct event			 c_readable;
	struct pfexec_req		 c_req;
	struct pfexec_resp		 c_resp;
};

static struct event			 pfd_acceptable;
static TAILQ_HEAD(clhead, client)	 pfd_clients;
static char				*pfd_configbuf;

static void	on_lsock_acceptable(int, short, void *);
static void	on_client_readable(int, short, void *);
static int	process_request(const struct pfexec_req *,
    struct pfexec_resp *);
static void	log_request(const struct pfexec_req *,
    const struct pfexec_resp *);

void __dead
usage(const char *arg0)
{
	fprintf(stderr, "Usage: %s [-f] [-c file]\n", arg0);
	fprintf(stderr, "       %s [-c file] -t\n", arg0);
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -f            Foreground operation: do not fork or "
	    "daemonise\n");
	fprintf(stderr, "  -c <file>     Use <file> as configuration file "
	    "instead of /etc/pfexecd.conf\n");
	fprintf(stderr, "  -t            Test configuration file: check "
	    "syntax and exit 0 if ok\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *optstring = "fc:t";
	const char *conf = "/etc/pfexecd.conf";
	int daemon = 1, testmode = 0;
	pid_t kid;
	int c;
	int rc, fd, lsock;
	size_t conflen;
	struct stat stat;
	ssize_t done;
	struct sockaddr_un laddr;

	TAILQ_INIT(&pfd_clients);

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'f':
			daemon = 0;
			break;
		case 't':
			testmode = 1;
			break;
		case 'c':
			conf = optarg;
			break;
		default:
			warnx("invalid argument");
			usage(argv[0]);
		}
	}

	fd = open(conf, O_RDONLY);
	if (fd < 0)
		err(1, "open(%s)", conf);
	rc = fstat(fd, &stat);
	if (rc < 0)
		err(1, "fstat(%s)", conf);
	if ((stat.st_mode & S_IFREG) == 0)
		errx(1, "config file %s is not a regular file", conf);
	if (stat.st_size > CONFIG_MAX_SIZE)
		errx(1, "config file %s is too big to be pfexecd.conf", conf);
	conflen = stat.st_size + 1;
	pfd_configbuf = calloc(1, conflen);
	if (pfd_configbuf == NULL)
		err(1, "malloc");

	for (done = 0; done < stat.st_size;) {
		ssize_t rr;
		rr = read(fd, pfd_configbuf + done, conflen - done);
		if (rr < 0)
			err(1, "read(%s)", conf);
		if (rr == 0)
			break;
		done += rr;
	}
	pfd_configbuf[conflen - 1] = '\0';
	close(fd);

	/*
	 * Open the pfexecd listening socket which the kernel will connect
	 * to. We unlink() any old socket file which exists before calling
	 * bind() (it would be nicer to have a pid file and check it first)
	 */
	if (!testmode) {
		lsock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
		if (lsock < 0)
			err(1, "socket");

		bzero(&laddr, sizeof(laddr));
		laddr.sun_len = sizeof(laddr);
		laddr.sun_family = AF_UNIX;
		strlcpy(laddr.sun_path, PFEXECD_SOCK, sizeof(laddr.sun_path));

		unlink(PFEXECD_SOCK);
		if (bind(lsock, (struct sockaddr *)&laddr, sizeof(laddr)))
			err(1, "bind(%s)", PFEXECD_SOCK);
		if (listen(lsock, BACKLOG))
			err(1, "listen(%s)", PFEXECD_SOCK);
	}

	if (daemon && !testmode) {
		kid = fork();
		if (kid < 0) {
			err(1, "fork");
		} else if (kid > 0) {
			/* The parent process exits immediately. */
			return (0);
		}
		umask(0);
		if (setsid() < 0) {
			syslog(LOG_AUTHPRIV | LOG_NOTICE,
			    "setsid failed: %d (%s)", errno, strerror(errno));
			exit(1);
		}
		chdir("/");

		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	/* TODO: drop privileges here */

	/* TODO: parse configuration file here: do it *after* dropping privs */

	/* If we're in config test mode and config parsing was ok, exit now. */
	if (testmode)
		return (0);

	/*
	 * Ignore SIGPIPE if we get it from any of our sockets: we'll poll
	 * them for read/hup/err later and figure it out anyway.
	 */
	signal(SIGPIPE, SIG_IGN);

	event_init();
	event_set(&pfd_acceptable, lsock, EV_READ, on_lsock_acceptable, NULL);
	event_add(&pfd_acceptable, NULL);

	event_dispatch();

	free(pfd_configbuf);
	close(lsock);

	return (0);
}

static void
destroy_client(struct client *client)
{
	TAILQ_REMOVE(&pfd_clients, client, c_entry);
	event_del(&client->c_readable);
	close(client->c_fd);
	free(client);
}

static void
on_lsock_acceptable(int lsock, short evt, void *arg)
{
	struct sockaddr_storage raddr;
	socklen_t slen;
	int newfd, rc;
	struct client *client;
	uid_t uid;
	gid_t gid;

	slen = sizeof(raddr);
	newfd = accept(lsock, (struct sockaddr *)&raddr, &slen);
	if (newfd < 0) {
		switch (errno) {
		case ECONNABORTED:
		case ECONNRESET:
			goto out;
		default:
			syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to accept "
			    "connection, aborting: %d (%s)", errno,
			    strerror(errno));
			exit(1);
		}
	}

	/* Check that the process connecting to us is running as "root". */
	rc = getpeereid(newfd, &uid, &gid);
	if (rc != 0) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to retrieve peer "
		    "uid/gid for new connection, closing");
		close(newfd);
		goto out;
	}
	if (uid != 0 || gid != 0) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "rejecting connection "
		    "from non-root user: uid %d, gid %d", uid, gid);
		close(newfd);
		goto out;
	}

	/*
	 * Set the socket's send buffer size now to make sure there's enough
	 * memory for it.
	 */
	slen = sizeof(struct pfexec_resp) + 32;
	rc = setsockopt(newfd, SOL_SOCKET, SO_SNDBUF, &slen, sizeof(slen));
	if (rc < 0) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to set send buffer "
		    "size for new client, closing");
		close(newfd);
		goto out;
	}

	client = calloc(1, sizeof (*client));
	if (client == NULL) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to allocate memory "
		    "for new client, closing");
		close(newfd);
		goto out;
	}

	client->c_fd = newfd;
	bcopy(&raddr, &client->c_raddr, sizeof(raddr));

	TAILQ_INSERT_TAIL(&pfd_clients, client, c_entry);

	event_set(&client->c_readable, newfd, EV_READ, on_client_readable,
	    client);
	event_add(&client->c_readable, NULL);

out:
	event_add(&pfd_acceptable, NULL);
}

static void
on_client_readable(int sock, short evt, void *arg)
{
	struct client *client = (struct client *)arg;
	struct msghdr hdr;
	struct iovec iov;
	ssize_t recvd;
	int rc;

	bzero(&hdr, sizeof(hdr));
	bzero(&iov, sizeof(iov));
	hdr.msg_iovlen = 1;
	hdr.msg_iov = &iov;
	iov.iov_base = &client->c_req;
	iov.iov_len = sizeof(struct pfexec_req);

	recvd = recvmsg(sock, &hdr, MSG_DONTWAIT);
	if (recvd < 0) {
		if (errno == EAGAIN)
			goto out;
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to read request "
		    "from client, closing");
		destroy_client(client);
		return;
	}
	if (recvd == 0) {
		/* EOF: the other end has closed the connection */
		destroy_client(client);
		return;
	}
	if (recvd < sizeof(struct pfexec_req)) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "short request from client, "
		    "closing");
		destroy_client(client);
		return;
	}

	bzero(&client->c_resp, sizeof(struct pfexec_resp));
	rc = process_request(&client->c_req, &client->c_resp);
	if (rc != 0) {
		bzero(&client->c_resp, sizeof(struct pfexec_resp));
		client->c_resp.pfr_errno = rc;
	}
	log_request(&client->c_req, &client->c_resp);

	bzero(&hdr, sizeof(hdr));
	bzero(&iov, sizeof(iov));
	hdr.msg_iovlen = 1;
	hdr.msg_iov = &iov;
	iov.iov_base = &client->c_resp;
	iov.iov_len = sizeof(struct pfexec_resp);
	recvd = sendmsg(sock, &hdr, MSG_EOR);
	if (recvd < 0) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to write to client, "
		    "closing");
		destroy_client(client);
		return;
	}

out:
	event_add(&client->c_readable, NULL);
}

static int
process_request(const struct pfexec_req *req, struct pfexec_resp *resp)
{
	uint i;

	/* Check for correctly formed request. */
	if (req->pfr_ngroups >= NGROUPS_MAX)
		return (EINVAL);
	if (req->pfr_req_flags & ~PFEXECVE_ALL_FLAGS)
		return (EINVAL);
	if (strlen(req->pfr_path) < 1 ||
	    strlen(req->pfr_path) >= PATH_MAX)
		return (EINVAL);
	if (req->pfr_argc >= 1024 || req->pfr_envc >= 1024)
		return (EINVAL);
	if ((req->pfr_req_flags & PFEXECVE_USER) && (
	    strlen(req->pfr_req_user) < 1 ||
	    strlen(req->pfr_req_user) >= LOGIN_NAME_MAX))
		return (EINVAL);

	/*
	 * Validate all the argument and env var references before we try to
	 * use any of them.
	 */
	for (i = 0; i < req->pfr_argc; ++i) {
		const struct pfexec_arg *a = &req->pfr_argp[i];
		if (a->pfa_offset >= ARG_MAX)
			return (EINVAL);
		if (a->pfa_len >= ARG_MAX)
			return (EINVAL);
		if (a->pfa_offset + a->pfa_len >= ARG_MAX)
			return (EINVAL);
	}
	for (i = 0; i < req->pfr_envc; ++i) {
		const struct pfexec_arg *a = &req->pfr_envp[i];
		if (a->pfa_offset >= ARG_MAX)
			return (EINVAL);
		if (a->pfa_len >= ARG_MAX)
			return (EINVAL);
		if (a->pfa_offset + a->pfa_len >= ARG_MAX)
			return (EINVAL);
	}

	/* TODO: determine whether this request should be allowed */

	return (EPERM);
}

static void
log_request(const struct pfexec_req *req, const struct pfexec_resp *resp)
{
	const char *requser = (req->pfr_req_flags & PFEXECVE_USER) ?
	    req->pfr_req_user : "root";
	if (resp->pfr_errno == 0) {
		syslog(LOG_AUTHPRIV | LOG_INFO,
		    "uid %d ran command %s as %s (pid %d)",
		    req->pfr_uid, req->pfr_path, requser, req->pfr_pid);
		return;
	}
	if (resp->pfr_errno == EPERM) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "denied escalation for pid %d (%s) as %s, run by uid %d",
		    req->pfr_pid, req->pfr_path, requser, req->pfr_uid);
		return;
	}
	syslog(LOG_AUTHPRIV | LOG_NOTICE,
	    "error processing esclation request from pid %d, run by uid %d: "
	    "%d: %s", req->pfr_pid, req->pfr_uid, resp->pfr_errno,
	    strerror(resp->pfr_errno));
}
