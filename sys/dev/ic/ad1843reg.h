/*	$OpenBSD: ad1843reg.h,v 1.1 2005/01/02 19:25:41 kettenis Exp $	*/

/*
 * Copyright (c) 2005 Mark Kettenis
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

/*
 * AD1843 Codec register defenitions.
 */

#define AD1843_CODEC_STATUS		0
#define  AD1843_INIT			0x8000
#define  AD1843_PDNO			0x4000
#define  AD1843_REVISION_MASK		0x000f

#define AD1843_ADC_SOURCE_GAIN		2
#define  AD1843_LSS_MASK		0xe000
#define  AD1843_LSS_SHIFT		13
#define  AD1843_RSS_MASK		0x00e0
#define  AD1843_RSS_SHIFT		5
#define  AD1843_LMGE			0x1000
#define  AD1843_RMGE			0x0010
#define  AD1843_LIG_MASK		0x0f00
#define  AD1843_LIG_SHIFT		8
#define  AD1843_RIG_MASK		0x000f
#define  AD1843_RIG_SHIFT		0

#define AD1843_DAC2_TO_MIXER		3
#define  AD1843_LD2MM			0x8000
#define  AD1843_RD2MM			0x0080
#define  AD1843_LD2M_MASK		0x1f00
#define  AD1843_LD2M_SHIFT		8
#define  AD1843_RD2M_MASK		0x001f
#define  AD1843_RD2M_SHIFT		0

#define AD1843_MISC_SETTINGS		8
#define  AD1843_MNMM			0x8000
#define  AD1843_MNM_MASK		0x1f00
#define  AD1843_MNM_SHIFT		8
#define  AD1843_ALLMM			0x0080
#define  AD1843_MNOM			0x0040
#define  AD1843_HPOM			0x0020
#define  AD1843_HPOS			0x0010
#define  AD1843_SUMM			0x0008
#define  AD1843_DAC2T			0x0002
#define  AD1843_DAC1T			0x0001

#define AD1843_DAC1_ANALOG_GAIN		9
#define  AD1843_LDA1GM			0x8000
#define  AD1843_RDA1GM			0x0080
#define  AD1843_LDA1G_MASK		0x3f00
#define  AD1843_LDA1G_SHIFT		8
#define  AD1843_RDA1G_MASK		0x003f
#define  AD1843_RDA1G_SHIFT		0

#define AD1843_DAC1_DIGITAL_GAIN	11
#define  AD1843_LDA1AM			0x8000
#define  AD1843_RDA1AM			0x0080

#define AD1843_CHANNEL_SAMPLE_RATE	15
#define  AD1843_DA1C_SHIFT		8
#define  AD1843_ADRC_SHIFT		2
#define  AD1843_ADLC_SHIFT		0

#define AD1843_CLOCK1_SAMPLE_RATE	17
#define AD1843_CLOCK2_SAMPLE_RATE	20
#define AD1843_CLOCK3_SAMPLE_RATE	13

#define AD1843_SERIAL_INTERFACE		26
#define  AD1843_DA2F_MASK		0x0c00
#define  AD1843_DA2F_SHIFT		10
#define  AD1843_DA1F_MASK		0x0300
#define  AD1843_DA1F_SHIFT		8
#define  AD1843_ADTLK			0x0010
#define  AD1843_ADRF_MASK		0x000c
#define  AD1843_ADRF_SHIFT		2
#define  AD1843_ADLF_MASK		0x0003
#define  AD1843_ADLF_SHIFT		0
#define  AD1843_PCM8			0
#define  AD1843_PCM16			1
#define  AD1843_ULAW			2
#define  AD1843_ALAW			3
#define  AD1843_SCF			0x0080

#define AD1843_CHANNEL_POWER_DOWN	27
#define  AD1843_DFREE			0x8000
#define  AD1843_DDMEN			0x1000
#define  AD1843_DA2EN			0x0200
#define  AD1843_DA1EN			0x0100
#define  AD1843_ANAEN			0x0080
#define  AD1843_HPEN			0x0040
#define  AD1843_AAMEN			0x0010
#define  AD1843_ADREN			0x0002
#define  AD1843_ADLEN			0x0001

#define AD1843_FUNDAMENTAL_SETTINGS	28
#define  AD1843_PDNI			0x8000
#define  AD1843_ACEN			0x4000
#define  AD1843_C3EN			0x2000
#define  AD1843_C2EN			0x1000
#define  AD1843_C1EN			0x0800

#define AD1843_NREGS			32