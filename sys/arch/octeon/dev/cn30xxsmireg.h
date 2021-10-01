/*
 * THIS FILE IS AUTOMATICALLY GENERATED
 * DONT EDIT THIS FILE
 */

/*	$OpenBSD: cn30xxsmireg.h,v 1.1 2011/06/16 11:22:30 syuu Exp $	*/

/*
 * Copyright (c) 2007 Internet Initiative Japan, Inc.
 * All rights reserved.
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
 */

/*
 * Cavium Networks OCTEON CN30XX Hardware Reference Manual
 * CN30XX-HM-1.0
 * 18.3 SMI Registers
 */

#ifndef _CN30XXSMIREG_H_
#define _CN30XXSMIREG_H_

#define	SMI_CMD_OFFSET				0x00ULL
#define	SMI_WR_DAT_OFFSET			0x08ULL
#define	SMI_RD_DAT_OFFSET			0x10ULL
#define	SMI_CLK_OFFSET				0x18ULL
#define	SMI_EN_OFFSET				0x20ULL

/* SMI CMD */
#define SMI_CMD_63_17			0xfffffffffffe0000ULL
#define SMI_CMD_PHY_OP			0x0000000000010000ULL
#define SMI_CMD_15_13			0x000000000000e000ULL
#define SMI_CMD_PHY_ADR			0x0000000000001f00ULL
#define  SMI_CMD_PHY_ADR_SHIFT		8
#define SMI_CMD_7_5			0x00000000000000e0ULL
#define SMI_CMD_REG_ADR			0x000000000000001fULL
#define  SMI_CMD_REG_ADR_SHIFT		0

/* SMI_WR_DAT */
#define SMI_WR_DAT_63_18		0xfffffffffffc0000ULL
#define SMI_WR_DAT_PENDING		0x0000000000020000ULL
#define SMI_WR_DAT_VAL			0x0000000000010000ULL
#define SMI_WR_DAT_DAT			0x000000000000ffffULL

/* SMI_RD_DAT */
#define SMI_RD_DAT_63_18		0xfffffffffffc0000ULL
#define SMI_RD_DAT_PENDING		0x0000000000020000ULL
#define SMI_RD_DAT_VAL			0x0000000000010000ULL
#define SMI_RD_DAT_DAT			0x000000000000ffffULL

/* SMI_CLK */
#define SMI_CLK_63_21			0xffffffffffe00000ULL
#define SMI_CLK_SAMPLE_HI		0x00000000001f0000ULL
#define SMI_CLK_15_14			0x000000000000c000ULL
#define SMI_CLK_CLK_IDLE		0x0000000000002000ULL
#define SMI_CLK_PREAMBLE		0x0000000000001000ULL
#define SMI_CLK_SAMPLE			0x0000000000000f00ULL
#define SMI_CLK_PHASE			0x00000000000000ffULL

/* SMI_EN */
#define SMI_EN_63_1			0xfffffffffffffffeULL
#define SMI_EN_EN			0x0000000000000001ULL

/* XXX */

#endif /* _CN30XXSMIREG_H_ */
