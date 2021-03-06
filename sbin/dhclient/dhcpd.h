/*	$OpenBSD: dhcpd.h,v 1.298 2021/03/24 16:04:10 krw Exp $	*/

/*
 * Copyright (c) 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 1995, 1996, 1997, 1998, 1999
 * The Internet Software Consortium.    All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The Internet Software Consortium nor the names
 *    of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software has been written for the Internet Software Consortium
 * by Ted Lemon <mellon@fugue.com> in cooperation with Vixie
 * Enterprises.  To learn more about the Internet Software Consortium,
 * see ``http://www.vix.com/isc''.  To learn more about Vixie
 * Enterprises, see ``http://www.vix.com''.
 */

#define	LOCAL_PORT	68
#define	REMOTE_PORT	67
#define	TERMINATE	1
#define	RESTART		2
#define DB_TIMEFMT	"%w %Y/%m/%d %T UTC"
#define	RT_BUF_SIZE	2048

struct option_data {
	unsigned int	 len;
	uint8_t		*data;
};

struct reject_elem {
	TAILQ_ENTRY(reject_elem) next;
	struct in_addr		 addr;
};

struct client_lease {
	TAILQ_ENTRY(client_lease) next;
	time_t			 epoch;
	struct in_addr		 address;
	struct in_addr		 next_server;
	char			*server_name;
	char			*filename;
	char			 ssid[32];
	uint8_t			 ssid_len;
	struct option_data	 options[DHO_COUNT];
};
#define BOOTP_LEASE(l)	((l)->options[DHO_DHCP_MESSAGE_TYPE].len == 0)

/* Possible states in which the client can be. */
enum dhcp_state {
	S_PREBOOT,
	S_REBOOTING,
	S_INIT,
	S_SELECTING,
	S_REQUESTING,
	S_BOUND,
	S_RENEWING
};

enum actions {
	ACTION_USELEASE,
	ACTION_DEFAULT,
	ACTION_SUPERSEDE,
	ACTION_PREPEND,
	ACTION_APPEND,
	ACTION_IGNORE
};

TAILQ_HEAD(client_lease_tq, client_lease);

struct client_config {
	struct option_data	 defaults[DHO_COUNT];
	enum actions		 default_actions[DHO_COUNT];
	struct in_addr		 address;
	struct in_addr		 next_server;
	struct option_data	 send_options[DHO_COUNT];
	uint8_t			 required_options[DHO_COUNT];
	uint8_t			 requested_options[DHO_COUNT];
	int			 requested_option_count;
	int			 required_option_count;
	time_t			 offer_interval;
	time_t			 initial_interval;
	time_t			 link_interval;
	time_t			 retry_interval;
	time_t			 select_interval;
	time_t			 reboot_interval;
	time_t			 backoff_cutoff;
	TAILQ_HEAD(, reject_elem) reject_list;
	char			*filename;
	char			*server_name;
};


struct interface_info {
	struct ether_addr	 hw_address;
	char			 name[IFNAMSIZ];
	char			 ssid[32];
	uint8_t			 ssid_len;
	int			 bpffd; /* bpf - reading & broadcast writing*/
	int			 udpfd; /* udp - unicast writing */
	unsigned char		*rbuf;
	size_t			 rbuf_max;
	int			 errors;
	uint16_t		 index;
	int			 link_state;
	int			 rdomain;
	int			 flags;
#define IFI_IN_CHARGE		0x01
	uint32_t		 mtu;
	struct dhcp_packet	 recv_packet;
	struct dhcp_packet	 sent_packet;
	int			 sent_packet_length;
	uint32_t		 xid;
	struct timespec		 timeout;
	struct timespec		 reboot_timeout;
	struct timespec		 expiry;
	struct timespec		 rebind;
	struct timespec		 renew;
	void			(*timeout_func)(struct interface_info *);
	uint16_t		 secs;
	struct timespec		 first_sending;
	struct timespec		 link_timeout;
	struct timespec		 offer_timeout;
	struct timespec		 select_timeout;
	enum dhcp_state		 state;
	struct in_addr		 destination;
	time_t			 interval;
	struct in_addr		 requested_address;
	struct client_lease	*active;
	struct client_lease	*offer;
	char			*offer_src;
	struct proposal		*configured;
	struct unwind_info	*unwind_info;
	struct client_lease_tq	 lease_db;
};

#define	_PATH_DHCLIENT_CONF	"/etc/dhclient.conf"
#define	_PATH_LEASE_DB		"/var/db/dhclient.leases"

/* options.c */
int			 pack_options(unsigned char *, int,
	struct option_data *);
struct option_data	*unpack_options(struct dhcp_packet *);
char			*pretty_print_option(unsigned int, struct option_data *,
    int);
char			*pretty_print_string(unsigned char *, size_t, int);
char			*code_to_name(int);
char			*code_to_format(int);
int			 code_to_action(int, int);
int			 name_to_code(char *);
void			 merge_option_data(char *, struct option_data *,
    struct option_data *, struct option_data *);

/* conflex.c */
extern int	 lexline, lexchar;
extern char	*token_line, *tlname;

void		 new_parse(char *);
int		 next_token(char **, FILE *);
int		 peek_token(char **, FILE *);

/* parse.c */
void		 skip_to_semi(FILE *);
int		 parse_semi(FILE *);
int		 parse_string(FILE *, char **);
int		 parse_ip_addr(FILE *, struct in_addr *);
int		 parse_cidr(FILE *, unsigned char *);
int		 parse_number(FILE *, long long *, long long, long long);
int		 parse_boolean(FILE *, unsigned char *);
void		 parse_warn(char *);

/* bpf.c */
int		 get_bpf_sock(char *);
int		 get_udp_sock(int);
int		 configure_bpf_sock(int);
ssize_t		 send_packet(struct interface_info *, struct in_addr,
    struct in_addr, const char *);
ssize_t		 receive_packet(unsigned char *, unsigned char *,
    struct sockaddr_in *, struct ether_addr *, struct dhcp_packet *);

/* dispatch.c */
void		 dispatch(struct interface_info *, int);
void		 set_timeout( struct interface_info *, time_t,
    void (*)(struct interface_info *));
void		 cancel_timeout(struct interface_info *);

/* dhclient.c */
extern char			*path_dhclient_conf;
extern char			*path_lease_db;
extern char			*log_procname;
extern struct client_config	*config;
extern struct imsgbuf		*unpriv_ibuf;
extern int			 quit;
extern int			 cmd_opts;
#define		OPT_NOACTION	0x01
#define		OPT_VERBOSE	0x02
#define		OPT_FOREGROUND	0x04
#define		OPT_RELEASE	0x08

void		 dhcpoffer(struct interface_info *, struct option_data *,
    const char *);
void		 dhcpack(struct interface_info *, struct option_data *,
    const char *);
void		 dhcpnak(struct interface_info *, const char *);
void		 bootreply(struct interface_info *, struct option_data *,
    const char *);
void		 free_client_lease(struct client_lease *);
void		 routefd_handler(struct interface_info *, int);
void		 state_preboot(struct interface_info *);
char		*rfc1035_as_string(unsigned char *, size_t);

/* packet.c */
void		 assemble_eh_header(struct ether_addr, struct ether_header *);
ssize_t		 decode_udp_ip_header(unsigned char *, uint32_t,
    struct sockaddr_in *);
uint32_t	 checksum(unsigned char *, uint32_t, uint32_t);
uint32_t	 wrapsum(uint32_t);

/* clparse.c */
void		 init_config(void);
void		 read_conf(char *, uint8_t *, struct ether_addr *);
void		 read_lease_db(struct client_lease_tq *);

/* kroute.c */
unsigned int	 extract_route(uint8_t *, unsigned int, in_addr_t *,
    in_addr_t *, in_addr_t *);
void		 write_resolv_conf(void);

void		 propose(struct proposal *);
void		 revoke_proposal(struct proposal *);

void		 tell_unwind(struct unwind_info *, int);
