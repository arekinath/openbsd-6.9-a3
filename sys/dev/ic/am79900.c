/*	$OpenBSD: am79900.c,v 1.7 2017/01/22 10:17:37 dlg Exp $	*/
/*	$NetBSD: am79900.c,v 1.23 2012/02/02 19:43:02 tls Exp $	*/

/*-
 * Copyright (c) 1997 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Ralph Campbell and Rick Macklem.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)if_le.c	8.2 (Berkeley) 11/16/93
 */

/*-
 * Copyright (c) 1998
 *	Matthias Drochner.  All rights reserved.
 * Copyright (c) 1995 Charles M. Hannum.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Ralph Campbell and Rick Macklem.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)if_le.c	8.2 (Berkeley) 11/16/93
 */

#include "bpfilter.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/syslog.h>
#include <sys/socket.h>
#include <sys/device.h>
#include <sys/malloc.h>
#include <sys/ioctl.h>
#include <sys/errno.h>

#include <net/if.h>
#include <net/if_media.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#if NBPFILTER > 0
#include <net/bpf.h>
#endif

#include <dev/ic/lancereg.h>
#include <dev/ic/lancevar.h>
#include <dev/ic/am79900reg.h>
#include <dev/ic/am79900var.h>

void	am79900_meminit(struct lance_softc *);
void	am79900_start(struct ifnet *);

void	am79900_rint(struct lance_softc *);
void	am79900_tint(struct lance_softc *);

#ifdef LEDEBUG
void	am79900_recv_print(struct lance_softc *, int);
void	am79900_xmit_print(struct lance_softc *, int);
#endif

void
am79900_config(struct am79900_softc *sc)
{
	int mem, i;

	sc->lsc.sc_meminit = am79900_meminit;
	sc->lsc.sc_start = am79900_start;

	lance_config(&sc->lsc);

	mem = 0;
	sc->lsc.sc_initaddr = mem;
	mem += sizeof(struct leinit);
	sc->lsc.sc_rmdaddr = mem;
	mem += sizeof(struct lermd) * sc->lsc.sc_nrbuf;
	sc->lsc.sc_tmdaddr = mem;
	mem += sizeof(struct letmd) * sc->lsc.sc_ntbuf;
	for (i = 0; i < sc->lsc.sc_nrbuf; i++, mem += LEBLEN)
		sc->lsc.sc_rbufaddr[i] = mem;
	for (i = 0; i < sc->lsc.sc_ntbuf; i++, mem += LEBLEN)
		sc->lsc.sc_tbufaddr[i] = mem;

	if (mem > sc->lsc.sc_memsize)
		panic("%s: memsize", sc->lsc.sc_dev.dv_xname);
}

/*
 * Set up the initialization block and the descriptor rings.
 */
void
am79900_meminit(struct lance_softc *sc)
{
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	u_long a;
	int bix;
	struct leinit init;
	struct lermd rmd;
	struct letmd tmd;
	uint8_t *myaddr;

	if (ifp->if_flags & IFF_PROMISC)
		init.init_mode = LE_MODE_NORMAL | LE_MODE_PROM;
	else
		init.init_mode = LE_MODE_NORMAL;
	if (sc->sc_initmodemedia == 1)
		init.init_mode |= LE_MODE_PSEL0;

	init.init_mode |= ((ffs(sc->sc_ntbuf) - 1) << 28) |
	    ((ffs(sc->sc_nrbuf) - 1) << 20);

	/*
	 * Update our private copy of the Ethernet address.
	 * We NEED the copy so we can ensure its alignment!
	 */
	memcpy(sc->sc_enaddr, sc->sc_arpcom.ac_enaddr, ETHER_ADDR_LEN);
	myaddr = sc->sc_enaddr;

	init.init_padr[0] = myaddr[0] | (myaddr[1] << 8) |
	    (myaddr[2] << 16) | (myaddr[3] << 24);
	init.init_padr[1] = myaddr[4] | (myaddr[5] << 8);
	lance_setladrf(&sc->sc_arpcom, init.init_ladrf);

	sc->sc_last_rd = 0;
	sc->sc_first_td = sc->sc_last_td = sc->sc_no_td = 0;

	a = sc->sc_addr + LE_RMDADDR(sc, 0);
	init.init_rdra = a;

	a = sc->sc_addr + LE_TMDADDR(sc, 0);
	init.init_tdra = a;

	(*sc->sc_copytodesc)(sc, &init, LE_INITADDR(sc), sizeof(init));

	/*
	 * Set up receive ring descriptors.
	 */
	for (bix = 0; bix < sc->sc_nrbuf; bix++) {
		a = sc->sc_addr + LE_RBUFADDR(sc, bix);
		rmd.rmd0 = a;
		rmd.rmd1 = LE_R1_OWN | LE_R1_ONES | (-LEBLEN & 0xfff);
		rmd.rmd2 = 0;
		rmd.rmd3 = 0;
		(*sc->sc_copytodesc)(sc, &rmd, LE_RMDADDR(sc, bix),
		    sizeof(rmd));
	}

	/*
	 * Set up transmit ring descriptors.
	 */
	for (bix = 0; bix < sc->sc_ntbuf; bix++) {
		a = sc->sc_addr + LE_TBUFADDR(sc, bix);
		tmd.tmd0 = a;
		tmd.tmd1 = LE_T1_ONES;
		tmd.tmd2 = 0;
		tmd.tmd3 = 0;
		(*sc->sc_copytodesc)(sc, &tmd, LE_TMDADDR(sc, bix),
		    sizeof(tmd));
	}
}

void
am79900_rint(struct lance_softc *sc)
{
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	struct mbuf *m;
	struct mbuf_list ml = MBUF_LIST_INITIALIZER();
	int bix;
	int rp;
	struct lermd rmd;

	bix = sc->sc_last_rd;

	/* Process all buffers with valid data. */
	for (;;) {
		rp = LE_RMDADDR(sc, bix);
		(*sc->sc_copyfromdesc)(sc, &rmd, rp, sizeof(rmd));

		if (rmd.rmd1 & LE_R1_OWN)
			break;

		if (rmd.rmd1 & LE_R1_ERR) {
			if (rmd.rmd1 & LE_R1_ENP) {
#ifdef LEDEBUG
				if ((rmd.rmd1 & LE_R1_OFLO) == 0) {
					if (rmd.rmd1 & LE_R1_FRAM)
						printf("%s: framing error\n",
						    sc->sc_dev.dv_xname);
					if (rmd.rmd1 & LE_R1_CRC)
						printf("%s: crc mismatch\n",
						    sc->sc_dev.dv_xname);
				}
#endif
			} else {
				if (rmd.rmd1 & LE_R1_OFLO)
					printf("%s: overflow\n",
					    sc->sc_dev.dv_xname);
			}
			if (rmd.rmd1 & LE_R1_BUFF)
				printf("%s: receive buffer error\n",
				    sc->sc_dev.dv_xname);
			ifp->if_ierrors++;
		} else if ((rmd.rmd1 & (LE_R1_STP | LE_R1_ENP)) !=
		    (LE_R1_STP | LE_R1_ENP)) {
			printf("%s: dropping chained buffer\n",
			    sc->sc_dev.dv_xname);
			ifp->if_ierrors++;
		} else {
#ifdef LEDEBUG
			if (sc->sc_debug > 1)
				am79900_recv_print(sc, sc->sc_last_rd);
#endif
			m = lance_read(sc, LE_RBUFADDR(sc, bix),
			    (rmd.rmd2  & 0xfff) - 4);
			if (m != NULL)
				ml_enqueue(&ml, m);
		}

		rmd.rmd1 = LE_R1_OWN | LE_R1_ONES | (-LEBLEN & 0xfff);
		rmd.rmd2 = 0;
		rmd.rmd3 = 0;
		(*sc->sc_copytodesc)(sc, &rmd, rp, sizeof(rmd));

#ifdef LEDEBUG
		if (sc->sc_debug)
			printf("sc->sc_last_rd = %x, rmd: "
			       "adr %08x, flags/blen %08x\n",
				sc->sc_last_rd,
				rmd.rmd0, rmd.rmd1);
#endif

		if (++bix == sc->sc_nrbuf)
			bix = 0;
	}

	sc->sc_last_rd = bix;

	if_input(ifp, &ml);
}

void
am79900_tint(struct lance_softc *sc)
{
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	int bix;
	struct letmd tmd;

	bix = sc->sc_first_td;

	for (;;) {
		if (sc->sc_no_td <= 0)
			break;

		(*sc->sc_copyfromdesc)(sc, &tmd, LE_TMDADDR(sc, bix),
		    sizeof(tmd));

#ifdef LEDEBUG
		if (sc->sc_debug)
			printf("trans tmd: "
			    "adr %08x, flags/blen %08x\n",
			    tmd.tmd0, tmd.tmd1);
#endif

		if (tmd.tmd1 & LE_T1_OWN)
			break;

		ifq_clr_oactive(&ifp->if_snd);

		if (tmd.tmd1 & LE_T1_ERR) {
			if (tmd.tmd2 & LE_T2_BUFF)
				printf("%s: transmit buffer error\n",
				    sc->sc_dev.dv_xname);
			else if (tmd.tmd2 & LE_T2_UFLO)
				printf("%s: underflow\n", sc->sc_dev.dv_xname);
			if (tmd.tmd2 & (LE_T2_BUFF | LE_T2_UFLO)) {
				lance_reset(sc);
				return;
			}
			if (tmd.tmd2 & LE_T2_LCAR) {
				sc->sc_havecarrier = 0;
				if (sc->sc_nocarrier)
					(*sc->sc_nocarrier)(sc);
				else
					printf("%s: lost carrier\n",
					    sc->sc_dev.dv_xname);
			}
			if (tmd.tmd2 & LE_T2_LCOL)
				ifp->if_collisions++;
			if (tmd.tmd2 & LE_T2_RTRY) {
#ifdef LEDEBUG
				printf("%s: excessive collisions\n",
				    sc->sc_dev.dv_xname);
#endif
				ifp->if_collisions += 16;
			}
			ifp->if_oerrors++;
		} else {
			if (tmd.tmd1 & LE_T1_ONE)
				ifp->if_collisions++;
			else if (tmd.tmd1 & LE_T1_MORE)
				/* Real number is unknown. */
				ifp->if_collisions += 2;
		}

		if (++bix == sc->sc_ntbuf)
			bix = 0;

		--sc->sc_no_td;
	}

	sc->sc_first_td = bix;

	am79900_start(ifp);

	if (sc->sc_no_td == 0)
		ifp->if_timer = 0;
}

/*
 * Controller interrupt.
 */
int
am79900_intr(void *arg)
{
	struct lance_softc *sc = arg;
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	uint16_t isr;

	isr = (*sc->sc_rdcsr)(sc, LE_CSR0) | sc->sc_saved_csr0;
	sc->sc_saved_csr0 = 0;
#if defined(LEDEBUG) && LEDEBUG > 1
	if (sc->sc_debug)
		printf("%s: am79900_intr entering with isr=%04x\n",
		    sc->sc_dev.dv_xname, isr);
#endif
	if ((isr & LE_C0_INTR) == 0)
		return (0);

	(*sc->sc_wrcsr)(sc, LE_CSR0,
	    isr & (LE_C0_INEA | LE_C0_BABL | LE_C0_MISS | LE_C0_MERR |
		   LE_C0_RINT | LE_C0_TINT | LE_C0_IDON));
	if (isr & LE_C0_ERR) {
		if (isr & LE_C0_BABL) {
#ifdef LEDEBUG
			printf("%s: babble\n", sc->sc_dev.dv_xname);
#endif
			ifp->if_oerrors++;
		}
#if 0
		if (isr & LE_C0_CERR) {
			printf("%s: collision error\n",
			    sc->sc_dev.dv_xname);
			ifp->if_collisions++;
		}
#endif
		if (isr & LE_C0_MISS) {
#ifdef LEDEBUG
			printf("%s: missed packet\n", sc->sc_dev.dv_xname);
#endif
			ifp->if_ierrors++;
		}
		if (isr & LE_C0_MERR) {
			printf("%s: memory error\n", sc->sc_dev.dv_xname);
			lance_reset(sc);
			return (1);
		}
	}

	if ((isr & LE_C0_RXON) == 0) {
		printf("%s: receiver disabled\n", sc->sc_dev.dv_xname);
		ifp->if_ierrors++;
		lance_reset(sc);
		return (1);
	}
	if ((isr & LE_C0_TXON) == 0) {
		printf("%s: transmitter disabled\n", sc->sc_dev.dv_xname);
		ifp->if_oerrors++;
		lance_reset(sc);
		return (1);
	}

	/*
	 * Pretend we have carrier; if we don't this will be cleared
	 * shortly.
	 */
	sc->sc_havecarrier = 1;

	if (isr & LE_C0_RINT)
		am79900_rint(sc);
	if (isr & LE_C0_TINT)
		am79900_tint(sc);

	return (1);
}

/*
 * Setup output on interface.
 * Get another datagram to send off of the interface queue, and map it to the
 * interface before starting the output.
 * Called only at splnet or interrupt level.
 */
void
am79900_start(struct ifnet *ifp)
{
	struct lance_softc *sc = ifp->if_softc;
	int bix;
	struct mbuf *m;
	struct letmd tmd;
	int rp;
	int len;

	if (!(ifp->if_flags & IFF_RUNNING) || ifq_is_oactive(&ifp->if_snd))
		return;

	bix = sc->sc_last_td;

	for (;;) {
		rp = LE_TMDADDR(sc, bix);
		(*sc->sc_copyfromdesc)(sc, &tmd, rp, sizeof(tmd));

		if (tmd.tmd1 & LE_T1_OWN) {
			ifq_set_oactive(&ifp->if_snd);
			printf("missing buffer, no_td = %d, last_td = %d\n",
			    sc->sc_no_td, sc->sc_last_td);
		}

		m = ifq_dequeue(&ifp->if_snd);
		if (m == NULL)
			break;

#if NBPFILTER > 0
		/*
		 * If BPF is listening on this interface, let it see the packet
		 * before we commit it to the wire.
		 */
		if (ifp->if_bpf)
			bpf_mtap(ifp->if_bpf, m, BPF_DIRECTION_OUT);
#endif

		/*
		 * Copy the mbuf chain into the transmit buffer.
		 */
		len = lance_put(sc, LE_TBUFADDR(sc, bix), m);

#ifdef LEDEBUG
		if (len > ETHERMTU + sizeof(struct ether_header))
			printf("packet length %d\n", len);
#endif

		ifp->if_timer = 5;

		/*
		 * Init transmit registers, and set transmit start flag.
		 */
		tmd.tmd1 = LE_T1_OWN | LE_T1_STP | LE_T1_ENP | LE_T1_ONES |
		    (-len & 0xfff);
		tmd.tmd2 = 0;
		tmd.tmd3 = 0;

		(*sc->sc_copytodesc)(sc, &tmd, rp, sizeof(tmd));

#ifdef LEDEBUG
		if (sc->sc_debug > 1)
			am79900_xmit_print(sc, sc->sc_last_td);
#endif

		(*sc->sc_wrcsr)(sc, LE_CSR0, LE_C0_INEA | LE_C0_TDMD);

		if (++bix == sc->sc_ntbuf)
			bix = 0;

		if (++sc->sc_no_td == sc->sc_ntbuf) {
			ifq_set_oactive(&ifp->if_snd);
			break;
		}

	}

	sc->sc_last_td = bix;
}

#ifdef LEDEBUG
void
am79900_recv_print(struct lance_softc *sc, int no)
{
	struct lermd rmd;
	uint16_t len;
	struct ether_header eh;

	(*sc->sc_copyfromdesc)(sc, &rmd, LE_RMDADDR(sc, no), sizeof(rmd));
	len = (rmd.rmd2  & 0xfff) - 4;
	printf("%s: receive buffer %d, len = %d\n",
	    sc->sc_dev.dv_xname, no, len);
	printf("%s: status %04x\n", sc->sc_dev.dv_xname,
	    (*sc->sc_rdcsr)(sc, LE_CSR0));
	printf("%s: adr %08x, flags/blen %08x\n",
	    sc->sc_dev.dv_xname, rmd.rmd0, rmd.rmd1);
	if (len >= sizeof(eh)) {
		(*sc->sc_copyfrombuf)(sc, &eh, LE_RBUFADDR(sc, no), sizeof(eh));
		printf("%s: dst %s", sc->sc_dev.dv_xname,
			ether_sprintf(eh.ether_dhost));
		printf(" src %s type %04x\n", ether_sprintf(eh.ether_shost),
			ntohs(eh.ether_type));
	}
}

void
am79900_xmit_print(struct lance_softc *sc, int no)
{
	struct letmd tmd;
	uint16_t len;
	struct ether_header eh;

	(*sc->sc_copyfromdesc)(sc, &tmd, LE_TMDADDR(sc, no), sizeof(tmd));
	len = -(tmd.tmd1 & 0xfff);
	printf("%s: transmit buffer %d, len = %d\n",
	    sc->sc_dev.dv_xname, no, len);
	printf("%s: status %04x\n", sc->sc_dev.dv_xname,
	    (*sc->sc_rdcsr)(sc, LE_CSR0));
	printf("%s: adr %08x, flags/blen %08x\n",
	    sc->sc_dev.dv_xname, tmd.tmd0, tmd.tmd1);
	if (len >= sizeof(eh)) {
		(*sc->sc_copyfrombuf)(sc, &eh, LE_TBUFADDR(sc, no), sizeof(eh));
		printf("%s: dst %s", sc->sc_dev.dv_xname,
			ether_sprintf(eh.ether_dhost));
		printf(" src %s type %04x\n", ether_sprintf(eh.ether_shost),
		    ntohs(eh.ether_type));
	}
}
#endif /* LEDEBUG */
