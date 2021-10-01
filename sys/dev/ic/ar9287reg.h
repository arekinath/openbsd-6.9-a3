/*	$OpenBSD: ar9287reg.h,v 1.5 2019/02/01 16:15:07 stsp Exp $	*/

/*-
 * Copyright (c) 2009 Damien Bergamini <damien.bergamini@free.fr>
 * Copyright (c) 2008-2009 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

#define AR9287_MAX_CHAINS	2

#define AR9287_PHY_CCA_MIN_GOOD_VAL_2GHZ	(-127)
#define AR9287_PHY_CCA_MAX_GOOD_VAL_2GHZ	(-97)

/*
 * Analog registers.
 */
#define AR9287_AN_RF2G3_CH0		0x7808
#define AR9287_AN_RF2G3_CH1		0x785c
#define AR9287_AN_TXPC0			0x7898
#define AR9287_AN_TOP2			0x78b4

/* Bits for AR9287_AN_RF2G3_CH[01]. */
#define AR9287_AN_RF2G3_OB_PAL_OFF_M	0x0001c000
#define AR9287_AN_RF2G3_OB_PAL_OFF_S	14
#define AR9287_AN_RF2G3_OB_QAM_M	0x000e0000
#define AR9287_AN_RF2G3_OB_QAM_S	17
#define AR9287_AN_RF2G3_OB_PSK_M	0x00700000
#define AR9287_AN_RF2G3_OB_PSK_S	20
#define AR9287_AN_RF2G3_OB_CCK_M	0x03800000
#define AR9287_AN_RF2G3_OB_CCK_S	23
#define AR9287_AN_RF2G3_DB2_M		0x1c000000
#define AR9287_AN_RF2G3_DB2_S		26
#define AR9287_AN_RF2G3_DB1_M		0xe0000000
#define AR9287_AN_RF2G3_DB1_S		29

/* Bits for AR9287_AN_TXPC0. */
#define AR9287_AN_TXPC0_TXPCMODE_M		0x0000c000
#define AR9287_AN_TXPC0_TXPCMODE_S		14
#define AR9287_AN_TXPC0_TXPCMODE_NORMAL		0
#define AR9287_AN_TXPC0_TXPCMODE_TEST		1
#define AR9287_AN_TXPC0_TXPCMODE_TEMPSENSE	2
#define AR9287_AN_TXPC0_TXPCMODE_ATBTEST	3

/* Bits for AR9287_AN_TOP2. */
#define AR9287_AN_TOP2_XPABIAS_LVL_M	0xc0000000
#define AR9287_AN_TOP2_XPABIAS_LVL_S	30

/*
 * ROM layout used by AR9287 (2GHz only).
 */
#define AR9287_EEP_START_LOC		128
#define AR9287_HTC_EEP_START_LOC	256
#define AR9287_NUM_2G_CAL_PIERS		3
#define AR9287_NUM_2G_CCK_TARGET_POWERS	3
#define AR9287_NUM_2G_20_TARGET_POWERS	3
#define AR9287_NUM_2G_40_TARGET_POWERS	3
#define AR9287_NUM_CTLS			12
#define AR9287_NUM_BAND_EDGES		4
#define AR9287_NUM_PD_GAINS		4
#define AR9287_PD_GAINS_IN_MASK 	4
#define AR9287_PD_GAIN_ICEPTS		1
#define AR9287_MAX_RATE_POWER		63
#define AR9287_NUM_RATES		16

struct ar9287_base_eep_header {
	uint16_t	length;
	uint16_t	checksum;
	uint16_t	version;
	uint8_t		opCapFlags;
	uint8_t		eepMisc;
#define AR9287_EEPMISC_BIG_ENDIAN	0x01
#define AR9287_EEPMISC_WOW		0x02

	uint16_t	regDmn[2];
	uint8_t		macAddr[6];
	uint8_t		rxMask;
	uint8_t		txMask;
	uint16_t	rfSilent;
	uint16_t	blueToothOptions;
	uint16_t	deviceCap;
	uint32_t	binBuildNumber;
	uint8_t		deviceType;
	/* End of common header. */
	uint8_t		openLoopPwrCntl;
	int8_t		pwrTableOffset;
	int8_t		tempSensSlope;
	int8_t		tempSensSlopePalOn;
	uint8_t		futureBase[29];
} __packed;

struct ar9287_modal_eep_header {
	uint32_t	antCtrlChain[AR9287_MAX_CHAINS];
	uint32_t	antCtrlCommon;
	int8_t		antennaGainCh[AR9287_MAX_CHAINS];
	uint8_t		switchSettling;
	uint8_t		txRxAttenCh[AR9287_MAX_CHAINS];
	uint8_t		rxTxMarginCh[AR9287_MAX_CHAINS];
	int8_t		adcDesiredSize;
	uint8_t		txEndToXpaOff;
	uint8_t		txEndToRxOn;
	uint8_t		txFrameToXpaOn;
	uint8_t		thresh62;
	int8_t		noiseFloorThreshCh[AR9287_MAX_CHAINS];
	uint8_t		xpdGain;
	uint8_t		xpd;
	int8_t		iqCalICh[AR9287_MAX_CHAINS];
	int8_t		iqCalQCh[AR9287_MAX_CHAINS];
	uint8_t		pdGainOverlap;
	uint8_t		xpaBiasLvl;
	uint8_t		txFrameToDataStart;
	uint8_t		txFrameToPaOn;
	uint8_t		ht40PowerIncForPdadc;
	uint8_t		bswAtten[AR9287_MAX_CHAINS];
	uint8_t		bswMargin[AR9287_MAX_CHAINS];
	uint8_t		swSettleHt40;
	uint8_t		version;
	uint8_t		db1;
	uint8_t		db2;
	uint8_t		ob_cck;
	uint8_t		ob_psk;
	uint8_t		ob_qam;
	uint8_t		ob_pal_off;
	uint8_t		futureModal[30];
	struct		ar_spur_chan spurChans[AR_EEPROM_MODAL_SPURS];
} __packed;

struct ar9287_cal_data_per_freq {
	uint8_t	pwrPdg[AR9287_NUM_PD_GAINS][AR9287_PD_GAIN_ICEPTS];
	uint8_t	vpdPdg[AR9287_NUM_PD_GAINS][AR9287_PD_GAIN_ICEPTS];
} __packed;

union ar9287_cal_data_per_freq_u {
	struct ar_cal_data_per_freq_olpc	calDataOpen;
	struct ar9287_cal_data_per_freq		calDataClose;
} __packed;

struct ar9287_cal_ctl_data {
	struct ar_cal_ctl_edges
	    ctlEdges[AR9287_MAX_CHAINS][AR9287_NUM_BAND_EDGES];
} __packed;

struct ar9287_eeprom {
	struct	ar9287_base_eep_header baseEepHeader;
	uint8_t custData[32];
	struct	ar9287_modal_eep_header modalHeader;
	uint8_t	calFreqPier2G[AR9287_NUM_2G_CAL_PIERS];
	union	ar9287_cal_data_per_freq_u
	    calPierData2G[AR9287_MAX_CHAINS][AR9287_NUM_2G_CAL_PIERS];
	struct	ar_cal_target_power_leg
	    calTargetPowerCck[AR9287_NUM_2G_CCK_TARGET_POWERS];
	struct	ar_cal_target_power_leg
	    calTargetPower2G[AR9287_NUM_2G_20_TARGET_POWERS];
	struct	ar_cal_target_power_ht
	    calTargetPower2GHT20[AR9287_NUM_2G_20_TARGET_POWERS];
	struct	ar_cal_target_power_ht
	    calTargetPower2GHT40[AR9287_NUM_2G_40_TARGET_POWERS];
	uint8_t	ctlIndex[AR9287_NUM_CTLS];
	struct	ar9287_cal_ctl_data ctlData[AR9287_NUM_CTLS];
	uint8_t	padding;
} __packed;

/* Macro to "pack" registers to 16-bit to save some .rodata space. */
#define P(x)	(x)

/*
 * AR9287 1.1 initialization values.
 */
static const uint16_t ar9287_1_1_regs[] = {
	P(0x01030), P(0x01070), P(0x010b0), P(0x010f0), P(0x08014),
	P(0x0801c), P(0x08120), P(0x081d0), P(0x08318), P(0x09804),
	P(0x09820), P(0x09824), P(0x09828), P(0x09834), P(0x09838),
	P(0x09840), P(0x09844), P(0x09850), P(0x09858), P(0x0985c),
	P(0x09860), P(0x09864), P(0x09868), P(0x0986c), P(0x09914),
	P(0x09918), P(0x09924), P(0x09944), P(0x09960), P(0x0a960),
	P(0x09964), P(0x0c968), P(0x099b8), P(0x099bc), P(0x099c0),
	P(0x0a204), P(0x0a20c), P(0x0b20c), P(0x0a21c), P(0x0a230),
	P(0x0a250), P(0x0a358), P(0x0a3d8)
};

static const uint32_t ar9287_1_1_vals_2g40[] = {
	0x000002c0, 0x00000318, 0x00007c70, 0x00000000, 0x10801600,
	0x12e00057, 0x08f04810, 0x0000320a, 0x00006880, 0x000003c4,
	0x02020200, 0x01000e0e, 0x3a020001, 0x00000e0e, 0x00000007,
	0x206a012e, 0x037216a0, 0x6d4000e2, 0x7ec84d2e, 0x3139605e,
	0x00058d20, 0x0001ce00, 0x5ac640d0, 0x06903881, 0x00001130,
	0x00000016, 0xd00a8a0d, 0xefbc1010, 0x00000010, 0x00000010,
	0x00000210, 0x000003ce, 0x0000001c, 0x00000c00, 0x05eea6d4,
	0x00000444, 0x00000000, 0x00000000, 0x1883800a, 0x00000210,
	0x0004a000, 0x7999aa0e, 0x00000000
};

static const uint32_t ar9287_1_1_vals_2g20[] = {
	0x00000160, 0x0000018c, 0x00003e38, 0x00000000, 0x08400b00,
	0x12e0002b, 0x08f04810, 0x0000320a, 0x00003440, 0x00000300,
	0x02020200, 0x01000e0e, 0x3a020001, 0x00000e0e, 0x00000007,
	0x206a012e, 0x037216a0, 0x6c4000e2, 0x7ec84d2e, 0x31395d5e,
	0x00058d20, 0x0001ce00, 0x5ac640d0, 0x06903881, 0x00000898,
	0x0000000b, 0xd00a8a0d, 0xefbc1010, 0x00000010, 0x00000010,
	0x00000210, 0x000003ce, 0x0000001c, 0x00000c00, 0x05eea6d4,
	0x00000444, 0x00000000, 0x00000000, 0x1883800a, 0x00000108,
	0x0004a000, 0x7999aa0e, 0x00000000
};

static const uint16_t ar9287_1_1_cm_regs[] = {
	P(0x0000c), P(0x00030), P(0x00034), P(0x00040), P(0x00044),
	P(0x00048), P(0x0004c), P(0x00050), P(0x00054), P(0x00800),
	P(0x00804), P(0x00808), P(0x0080c), P(0x00810), P(0x00814),
	P(0x00818), P(0x0081c), P(0x00820), P(0x00824), P(0x01040),
	P(0x01044), P(0x01048), P(0x0104c), P(0x01050), P(0x01054),
	P(0x01058), P(0x0105c), P(0x01060), P(0x01064), P(0x01230),
	P(0x01270), P(0x01038), P(0x01078), P(0x010b8), P(0x010f8),
	P(0x01138), P(0x01178), P(0x011b8), P(0x011f8), P(0x01238),
	P(0x01278), P(0x012b8), P(0x012f8), P(0x01338), P(0x01378),
	P(0x013b8), P(0x013f8), P(0x01438), P(0x01478), P(0x014b8),
	P(0x014f8), P(0x01538), P(0x01578), P(0x015b8), P(0x015f8),
	P(0x01638), P(0x01678), P(0x016b8), P(0x016f8), P(0x01738),
	P(0x01778), P(0x017b8), P(0x017f8), P(0x0103c), P(0x0107c),
	P(0x010bc), P(0x010fc), P(0x0113c), P(0x0117c), P(0x011bc),
	P(0x011fc), P(0x0123c), P(0x0127c), P(0x012bc), P(0x012fc),
	P(0x0133c), P(0x0137c), P(0x013bc), P(0x013fc), P(0x0143c),
	P(0x0147c), P(0x04030), P(0x0403c), P(0x04024), P(0x04060),
	P(0x04064), P(0x07010), P(0x07020), P(0x07034), P(0x07038),
	P(0x08004), P(0x08008), P(0x0800c), P(0x08018), P(0x08020),
	P(0x08038), P(0x0803c), P(0x08048), P(0x08054), P(0x08058),
	P(0x0805c), P(0x08060), P(0x08064), P(0x08070), P(0x080c0),
	P(0x080c4), P(0x080c8), P(0x080cc), P(0x080d0), P(0x080d4),
	P(0x080d8), P(0x080e0), P(0x080e4), P(0x080e8), P(0x080ec),
	P(0x080f0), P(0x080f4), P(0x080f8), P(0x080fc), P(0x08100),
	P(0x08104), P(0x08108), P(0x0810c), P(0x08110), P(0x08118),
	P(0x0811c), P(0x08124), P(0x08128), P(0x0812c), P(0x08130),
	P(0x08134), P(0x08138), P(0x0813c), P(0x08144), P(0x08168),
	P(0x0816c), P(0x08170), P(0x08174), P(0x08178), P(0x0817c),
	P(0x081c0), P(0x081c4), P(0x081d4), P(0x081ec), P(0x081f0),
	P(0x081f4), P(0x081f8), P(0x081fc), P(0x08200), P(0x08204),
	P(0x08208), P(0x0820c), P(0x08210), P(0x08214), P(0x08218),
	P(0x0821c), P(0x08220), P(0x08224), P(0x08228), P(0x0822c),
	P(0x08230), P(0x08234), P(0x08238), P(0x0823c), P(0x08240),
	P(0x08244), P(0x08248), P(0x0824c), P(0x08250), P(0x08254),
	P(0x08258), P(0x0825c), P(0x08260), P(0x08264), P(0x08270),
	P(0x08274), P(0x08278), P(0x0827c), P(0x08284), P(0x08288),
	P(0x0828c), P(0x08294), P(0x08298), P(0x0829c), P(0x08300),
	P(0x08314), P(0x08328), P(0x0832c), P(0x08330), P(0x08334),
	P(0x08338), P(0x0833c), P(0x08340), P(0x08344), P(0x08360),
	P(0x08364), P(0x08368), P(0x08370), P(0x08374), P(0x08378),
	P(0x0837c), P(0x08380), P(0x08384), P(0x08390), P(0x08394),
	P(0x08398), P(0x0839c), P(0x083a0), P(0x09808), P(0x0980c),
	P(0x09810), P(0x09814), P(0x0981c), P(0x0982c), P(0x09830),
	P(0x0983c), P(0x0984c), P(0x0a84c), P(0x09854), P(0x09900),
	P(0x09904), P(0x09908), P(0x0990c), P(0x09910), P(0x0991c),
	P(0x09920), P(0x0a920), P(0x09928), P(0x0992c), P(0x09930),
	P(0x0a930), P(0x09934), P(0x09938), P(0x0993c), P(0x09948),
	P(0x0994c), P(0x09954), P(0x09958), P(0x09940), P(0x0c95c),
	P(0x09970), P(0x09974), P(0x09978), P(0x0997c), P(0x099a0),
	P(0x099a4), P(0x099a8), P(0x099ac), P(0x099b0), P(0x099b4),
	P(0x099c4), P(0x099c8), P(0x099cc), P(0x099d0), P(0x099dc),
	P(0x099e0), P(0x099e4), P(0x099e8), P(0x099ec), P(0x099f0),
	P(0x099fc), P(0x0a208), P(0x0a210), P(0x0a214), P(0x0a218),
	P(0x0a220), P(0x0a224), P(0x0a228), P(0x0a22c), P(0x0a234),
	P(0x0a238), P(0x0a23c), P(0x0a240), P(0x0a244), P(0x0a248),
	P(0x0a24c), P(0x0a254), P(0x0a258), P(0x0a25c), P(0x0a260),
	P(0x0a264), P(0x0b264), P(0x0a268), P(0x0a26c), P(0x0b26c),
	P(0x0d270), P(0x0a278), P(0x0a27c), P(0x0d35c), P(0x0d360),
	P(0x0d364), P(0x0d368), P(0x0d36c), P(0x0d370), P(0x0d374),
	P(0x0d378), P(0x0d37c), P(0x0d380), P(0x0d384), P(0x0a388),
	P(0x0a38c), P(0x0a390), P(0x0a394), P(0x0a398), P(0x0b398),
	P(0x0a39c), P(0x0a3c8), P(0x0a3cc), P(0x0a3d0), P(0x0a3d4),
	P(0x0a3dc), P(0x0a3e0), P(0x0a3e4), P(0x0a3e8), P(0x0a3ec),
	P(0x0a3f0), P(0x0a3f4), P(0x0b3f4), P(0x0a7d8), P(0x07800),
	P(0x07804), P(0x07808), P(0x0780c), P(0x07810), P(0x07814),
	P(0x07818), P(0x0781c), P(0x07820), P(0x07824), P(0x07828),
	P(0x0782c), P(0x07830), P(0x07834), P(0x07838), P(0x0783c),
	P(0x07840), P(0x07844), P(0x07848), P(0x07850), P(0x07854),
	P(0x07858), P(0x0785c), P(0x07860), P(0x07864), P(0x07868),
	P(0x0786c), P(0x07870), P(0x07874), P(0x07878), P(0x0787c),
	P(0x07880), P(0x07884), P(0x07888), P(0x0788c), P(0x07890),
	P(0x07894), P(0x07898), P(0x0789c), P(0x078a0), P(0x078a4),
	P(0x078a8), P(0x078ac), P(0x078b0), P(0x078b4), P(0x078b8)
};

static const uint32_t ar9287_1_1_cm_vals[] = {
	0x00000000, 0x00020015, 0x00000005, 0x00000000, 0x00000008,
	0x00000008, 0x00000010, 0x00000000, 0x0000001f, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x002ffc0f,
	0x002ffc0f, 0x002ffc0f, 0x002ffc0f, 0x002ffc0f, 0x002ffc0f,
	0x002ffc0f, 0x002ffc0f, 0x002ffc0f, 0x002ffc0f, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000002, 0x00000002, 0x0000001f, 0x00000000,
	0x00000000, 0x00000033, 0x00000000, 0x00000002, 0x000004c2,
	0x00000000, 0x00000000, 0x00000000, 0x00000700, 0x00000000,
	0x00000000, 0x00000000, 0x40000000, 0x00000000, 0x00000000,
	0x000fc78f, 0x0000000f, 0x00000000, 0x00000000, 0x2a80001a,
	0x05dc01e0, 0x1f402710, 0x01f40000, 0x00001e00, 0x00000000,
	0x00400000, 0xffffffff, 0x0000ffff, 0x003f3f3f, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00020000, 0x00020000,
	0x00000001, 0x00000052, 0x00000000, 0x00000168, 0x000100aa,
	0x00003210, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0xffffffff, 0x00000000,
	0x00000000, 0x18487320, 0xfaa4fa50, 0x00000100, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00100000,
	0x0010f400, 0x00000100, 0x0001e800, 0x00000000, 0x00000000,
	0x00000000, 0x400000ff, 0x00080922, 0x88a00010, 0x00000000,
	0x40000000, 0x003e4180, 0x00000000, 0x0000002c, 0x0000002c,
	0x000000ff, 0x00000000, 0x00000000, 0x00000000, 0x00000040,
	0x00000000, 0x00000000, 0x00000007, 0x00000302, 0x00000e00,
	0x00ff0000, 0x00000000, 0x000107ff, 0x01c81043, 0xffffffff,
	0xffffffff, 0x00000000, 0x00000000, 0x000000ff, 0x00000000,
	0x00000000, 0xffffffff, 0xffffffff, 0x0fffffff, 0x0fffffff,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xafe68e30,
	0xfd14e000, 0x9c0a9f6b, 0x00000000, 0x0000a000, 0x00000000,
	0x00200400, 0x0040233c, 0x0040233c, 0x00000044, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x10002310, 0x10000fff,
	0x04900000, 0x04900000, 0x00000001, 0x00000004, 0x00000000,
	0x00000000, 0x1e1f2022, 0x0a0b0c0d, 0x00000000, 0x9280c00a,
	0x00020028, 0x5f3ca3de, 0x0108ecff, 0x14750604, 0x004b6a8e,
	0x990bb514, 0x00000000, 0x00000001, 0x00000000, 0x00000000,
	0x00000001, 0x201fff00, 0x0c6f0000, 0x03051000, 0x00000820,
	0x06336f77, 0x6af6532f, 0x08f186c8, 0x00046384, 0x00000000,
	0x00000000, 0xaaaaaaaa, 0x3c466478, 0x0cc80caa, 0x00000000,
	0x00001042, 0x803e4788, 0x4080a333, 0x40206c10, 0x009c4060,
	0x01834061, 0x00000400, 0x000003b5, 0x233f7180, 0x20202020,
	0x20202020, 0x13c889af, 0x38490a20, 0x00000000, 0xfffffffc,
	0x00000000, 0x00000000, 0x0cdbd380, 0x0f0f0f01, 0xdfa91f01,
	0x00418a11, 0x00418a11, 0x00000000, 0x0e79e5c6, 0x0e79e5c6,
	0x00820820, 0x1ce739ce, 0x050701ce, 0x07ffffef, 0x0fffffe7,
	0x17ffffe5, 0x1fffffe4, 0x37ffffe3, 0x3fffffe3, 0x57ffffe3,
	0x5fffffe2, 0x7fffffe2, 0x7f3c7bba, 0xf3307ff0, 0x0c000000,
	0x20202020, 0x20202020, 0x1ce739ce, 0x000001ce, 0x000001ce,
	0x00000001, 0x00000246, 0x20202020, 0x20202020, 0x20202020,
	0x1ce739ce, 0x000001ce, 0x00000000, 0x18c43433, 0x00f70081,
	0x01036a1e, 0x00000000, 0x00000000, 0x000003f1, 0x00000800,
	0x6c35ffd2, 0x6db6c000, 0x6db6cb30, 0x6db6cb6c, 0x0501e200,
	0x0094128d, 0x976ee392, 0xf75ff6fc, 0x00040000, 0xdb003012,
	0x04924914, 0x21084210, 0x00140000, 0x0e4548d8, 0x54214514,
	0x02025830, 0x71c0d388, 0x934934a8, 0x00000000, 0x00000800,
	0x6c35ffd2, 0x6db6c000, 0x6db6cb30, 0x6db6cb6c, 0x0501e200,
	0x0094128d, 0x976ee392, 0xf75ff6fc, 0x00040000, 0xdb003012,
	0x04924914, 0x21084210, 0x001b6db0, 0x00376b63, 0x06db6db6,
	0x006d8000, 0x48100000, 0x00000000, 0x08000000, 0x0007ffd8,
	0x0007ffd8, 0x001c0020, 0x00060aeb, 0x40008080, 0x2a850160
};

static const struct athn_ini ar9287_1_1_ini = {
	nitems(ar9287_1_1_regs),
	ar9287_1_1_regs,
	NULL,	/* 2GHz only. */
	NULL,	/* 2GHz only. */
	ar9287_1_1_vals_2g40,
	ar9287_1_1_vals_2g20,
	nitems(ar9287_1_1_cm_regs),
	ar9287_1_1_cm_regs,
	ar9287_1_1_cm_vals
};

/*
 * AR9287 1.1 Tx gains.
 */
static const uint16_t ar9287_1_1_tx_gain_regs[] = {
	P(0x0a300), P(0x0a304), P(0x0a308), P(0x0a30c), P(0x0a310),
	P(0x0a314), P(0x0a318), P(0x0a31c), P(0x0a320), P(0x0a324),
	P(0x0a328), P(0x0a32c), P(0x0a330), P(0x0a334), P(0x0a338),
	P(0x0a33c), P(0x0a340), P(0x0a344), P(0x0a348), P(0x0a34c),
	P(0x0a350), P(0x0a354), P(0x0a780), P(0x0a784), P(0x0a788),
	P(0x0a78c), P(0x0a790), P(0x0a794), P(0x0a798), P(0x0a79c),
	P(0x0a7a0), P(0x0a7a4), P(0x0a7a8), P(0x0a7ac), P(0x0a7b0),
	P(0x0a7b4), P(0x0a7b8), P(0x0a7bc), P(0x0a7c0), P(0x0a7c4),
	P(0x0a7c8), P(0x0a7cc), P(0x0a7d0), P(0x0a7d4), P(0x0a274)
};

static const uint32_t ar9287_1_1_tx_gain_vals_2g[] = {
	0x00000000, 0x00004002, 0x00008004, 0x0000c00a, 0x0001000c,
	0x0001420b, 0x0001824a, 0x0001c44a, 0x0002064a, 0x0002484a,
	0x00028a4a, 0x0002cc4a, 0x00030e4a, 0x00034e8a, 0x00038e8c,
	0x0003cecc, 0x00040ed4, 0x00044edc, 0x00048ede, 0x0004cf1e,
	0x00050f5e, 0x00054f9e, 0x00000062, 0x00004064, 0x000080a4,
	0x0000c0aa, 0x000100ac, 0x000140b4, 0x000180f4, 0x0001c134,
	0x00020174, 0x0002417c, 0x0002817e, 0x0002c1be, 0x000301fe,
	0x000301fe, 0x000301fe, 0x000301fe, 0x000301fe, 0x000301fe,
	0x000301fe, 0x000301fe, 0x000301fe, 0x000301fe, 0x0a1aa000
};

static const struct athn_gain ar9287_1_1_tx_gain = {
	nitems(ar9287_1_1_tx_gain_regs),
	ar9287_1_1_tx_gain_regs,
	NULL,	/* 2GHz only. */
	ar9287_1_1_tx_gain_vals_2g
};

/*
 * AR9287 1.1 Rx gains.
 */
static const uint16_t ar9287_1_1_rx_gain_regs[] = {
	P(0x09a00), P(0x09a04), P(0x09a08), P(0x09a0c), P(0x09a10),
	P(0x09a14), P(0x09a18), P(0x09a1c), P(0x09a20), P(0x09a24),
	P(0x09a28), P(0x09a2c), P(0x09a30), P(0x09a34), P(0x09a38),
	P(0x09a3c), P(0x09a40), P(0x09a44), P(0x09a48), P(0x09a4c),
	P(0x09a50), P(0x09a54), P(0x09a58), P(0x09a5c), P(0x09a60),
	P(0x09a64), P(0x09a68), P(0x09a6c), P(0x09a70), P(0x09a74),
	P(0x09a78), P(0x09a7c), P(0x09a80), P(0x09a84), P(0x09a88),
	P(0x09a8c), P(0x09a90), P(0x09a94), P(0x09a98), P(0x09a9c),
	P(0x09aa0), P(0x09aa4), P(0x09aa8), P(0x09aac), P(0x09ab0),
	P(0x09ab4), P(0x09ab8), P(0x09abc), P(0x09ac0), P(0x09ac4),
	P(0x09ac8), P(0x09acc), P(0x09ad0), P(0x09ad4), P(0x09ad8),
	P(0x09adc), P(0x09ae0), P(0x09ae4), P(0x09ae8), P(0x09aec),
	P(0x09af0), P(0x09af4), P(0x09af8), P(0x09afc), P(0x09b00),
	P(0x09b04), P(0x09b08), P(0x09b0c), P(0x09b10), P(0x09b14),
	P(0x09b18), P(0x09b1c), P(0x09b20), P(0x09b24), P(0x09b28),
	P(0x09b2c), P(0x09b30), P(0x09b34), P(0x09b38), P(0x09b3c),
	P(0x09b40), P(0x09b44), P(0x09b48), P(0x09b4c), P(0x09b50),
	P(0x09b54), P(0x09b58), P(0x09b5c), P(0x09b60), P(0x09b64),
	P(0x09b68), P(0x09b6c), P(0x09b70), P(0x09b74), P(0x09b78),
	P(0x09b7c), P(0x09b80), P(0x09b84), P(0x09b88), P(0x09b8c),
	P(0x09b90), P(0x09b94), P(0x09b98), P(0x09b9c), P(0x09ba0),
	P(0x09ba4), P(0x09ba8), P(0x09bac), P(0x09bb0), P(0x09bb4),
	P(0x09bb8), P(0x09bbc), P(0x09bc0), P(0x09bc4), P(0x09bc8),
	P(0x09bcc), P(0x09bd0), P(0x09bd4), P(0x09bd8), P(0x09bdc),
	P(0x09be0), P(0x09be4), P(0x09be8), P(0x09bec), P(0x09bf0),
	P(0x09bf4), P(0x09bf8), P(0x09bfc), P(0x0aa00), P(0x0aa04),
	P(0x0aa08), P(0x0aa0c), P(0x0aa10), P(0x0aa14), P(0x0aa18),
	P(0x0aa1c), P(0x0aa20), P(0x0aa24), P(0x0aa28), P(0x0aa2c),
	P(0x0aa30), P(0x0aa34), P(0x0aa38), P(0x0aa3c), P(0x0aa40),
	P(0x0aa44), P(0x0aa48), P(0x0aa4c), P(0x0aa50), P(0x0aa54),
	P(0x0aa58), P(0x0aa5c), P(0x0aa60), P(0x0aa64), P(0x0aa68),
	P(0x0aa6c), P(0x0aa70), P(0x0aa74), P(0x0aa78), P(0x0aa7c),
	P(0x0aa80), P(0x0aa84), P(0x0aa88), P(0x0aa8c), P(0x0aa90),
	P(0x0aa94), P(0x0aa98), P(0x0aa9c), P(0x0aaa0), P(0x0aaa4),
	P(0x0aaa8), P(0x0aaac), P(0x0aab0), P(0x0aab4), P(0x0aab8),
	P(0x0aabc), P(0x0aac0), P(0x0aac4), P(0x0aac8), P(0x0aacc),
	P(0x0aad0), P(0x0aad4), P(0x0aad8), P(0x0aadc), P(0x0aae0),
	P(0x0aae4), P(0x0aae8), P(0x0aaec), P(0x0aaf0), P(0x0aaf4),
	P(0x0aaf8), P(0x0aafc), P(0x0ab00), P(0x0ab04), P(0x0ab08),
	P(0x0ab0c), P(0x0ab10), P(0x0ab14), P(0x0ab18), P(0x0ab1c),
	P(0x0ab20), P(0x0ab24), P(0x0ab28), P(0x0ab2c), P(0x0ab30),
	P(0x0ab34), P(0x0ab38), P(0x0ab3c), P(0x0ab40), P(0x0ab44),
	P(0x0ab48), P(0x0ab4c), P(0x0ab50), P(0x0ab54), P(0x0ab58),
	P(0x0ab5c), P(0x0ab60), P(0x0ab64), P(0x0ab68), P(0x0ab6c),
	P(0x0ab70), P(0x0ab74), P(0x0ab78), P(0x0ab7c), P(0x0ab80),
	P(0x0ab84), P(0x0ab88), P(0x0ab8c), P(0x0ab90), P(0x0ab94),
	P(0x0ab98), P(0x0ab9c), P(0x0aba0), P(0x0aba4), P(0x0aba8),
	P(0x0abac), P(0x0abb0), P(0x0abb4), P(0x0abb8), P(0x0abbc),
	P(0x0abc0), P(0x0abc4), P(0x0abc8), P(0x0abcc), P(0x0abd0),
	P(0x0abd4), P(0x0abd8), P(0x0abdc), P(0x0abe0), P(0x0abe4),
	P(0x0abe8), P(0x0abec), P(0x0abf0), P(0x0abf4), P(0x0abf8),
	P(0x0abfc), P(0x09848), P(0x0a848)
};

static const uint32_t ar9287_1_1_rx_gain_vals_2g[] = {
	0x0000a120, 0x0000a124, 0x0000a128, 0x0000a12c, 0x0000a130,
	0x0000a194, 0x0000a198, 0x0000a20c, 0x0000a210, 0x0000a284,
	0x0000a288, 0x0000a28c, 0x0000a290, 0x0000a294, 0x0000a2a0,
	0x0000a2a4, 0x0000a2a8, 0x0000a2ac, 0x0000a2b0, 0x0000a2b4,
	0x0000a2b8, 0x0000a2c4, 0x0000a708, 0x0000a70c, 0x0000a710,
	0x0000ab04, 0x0000ab08, 0x0000ab0c, 0x0000ab10, 0x0000ab14,
	0x0000ab18, 0x0000ab8c, 0x0000ab90, 0x0000ab94, 0x0000ab98,
	0x0000aba4, 0x0000aba8, 0x0000cb04, 0x0000cb08, 0x0000cb0c,
	0x0000cb10, 0x0000cb14, 0x0000cb18, 0x0000cb8c, 0x0000cb90,
	0x0000cf18, 0x0000cf24, 0x0000cf28, 0x0000d314, 0x0000d318,
	0x0000d38c, 0x0000d390, 0x0000d394, 0x0000d398, 0x0000d3a4,
	0x0000d3a8, 0x0000d3ac, 0x0000d3b0, 0x0000f380, 0x0000f384,
	0x0000f388, 0x0000f710, 0x0000f714, 0x0000f718, 0x0000fb10,
	0x0000fb14, 0x0000fb18, 0x0000fb8c, 0x0000fb90, 0x0000fb94,
	0x0000ff8c, 0x0000ff90, 0x0000ff94, 0x0000ffa0, 0x0000ffa4,
	0x0000ffa8, 0x0000ffac, 0x0000ffb0, 0x0000ffb4, 0x0000ffa1,
	0x0000ffa5, 0x0000ffa9, 0x0000ffad, 0x0000ffb1, 0x0000ffb5,
	0x0000ffb9, 0x0000ffc5, 0x0000ffc9, 0x0000ffcd, 0x0000ffd1,
	0x0000ffd5, 0x0000ffc2, 0x0000ffc6, 0x0000ffca, 0x0000ffce,
	0x0000ffd2, 0x0000ffd6, 0x0000ffda, 0x0000ffc7, 0x0000ffcb,
	0x0000ffcf, 0x0000ffd3, 0x0000ffd7, 0x0000ffdb, 0x0000ffdb,
	0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb,
	0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb,
	0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb,
	0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb,
	0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000a120, 0x0000a124,
	0x0000a128, 0x0000a12c, 0x0000a130, 0x0000a194, 0x0000a198,
	0x0000a20c, 0x0000a210, 0x0000a284, 0x0000a288, 0x0000a28c,
	0x0000a290, 0x0000a294, 0x0000a2a0, 0x0000a2a4, 0x0000a2a8,
	0x0000a2ac, 0x0000a2b0, 0x0000a2b4, 0x0000a2b8, 0x0000a2c4,
	0x0000a708, 0x0000a70c, 0x0000a710, 0x0000ab04, 0x0000ab08,
	0x0000ab0c, 0x0000ab10, 0x0000ab14, 0x0000ab18, 0x0000ab8c,
	0x0000ab90, 0x0000ab94, 0x0000ab98, 0x0000aba4, 0x0000aba8,
	0x0000cb04, 0x0000cb08, 0x0000cb0c, 0x0000cb10, 0x0000cb14,
	0x0000cb18, 0x0000cb8c, 0x0000cb90, 0x0000cf18, 0x0000cf24,
	0x0000cf28, 0x0000d314, 0x0000d318, 0x0000d38c, 0x0000d390,
	0x0000d394, 0x0000d398, 0x0000d3a4, 0x0000d3a8, 0x0000d3ac,
	0x0000d3b0, 0x0000f380, 0x0000f384, 0x0000f388, 0x0000f710,
	0x0000f714, 0x0000f718, 0x0000fb10, 0x0000fb14, 0x0000fb18,
	0x0000fb8c, 0x0000fb90, 0x0000fb94, 0x0000ff8c, 0x0000ff90,
	0x0000ff94, 0x0000ffa0, 0x0000ffa4, 0x0000ffa8, 0x0000ffac,
	0x0000ffb0, 0x0000ffb4, 0x0000ffa1, 0x0000ffa5, 0x0000ffa9,
	0x0000ffad, 0x0000ffb1, 0x0000ffb5, 0x0000ffb9, 0x0000ffc5,
	0x0000ffc9, 0x0000ffcd, 0x0000ffd1, 0x0000ffd5, 0x0000ffc2,
	0x0000ffc6, 0x0000ffca, 0x0000ffce, 0x0000ffd2, 0x0000ffd6,
	0x0000ffda, 0x0000ffc7, 0x0000ffcb, 0x0000ffcf, 0x0000ffd3,
	0x0000ffd7, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb,
	0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb,
	0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb,
	0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb,
	0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb, 0x0000ffdb,
	0x0000ffdb, 0x00001067, 0x00001067
};

static const struct athn_gain ar9287_1_1_rx_gain = {
	nitems(ar9287_1_1_rx_gain_regs),
	ar9287_1_1_rx_gain_regs,
	NULL,	/* 2GHz only. */
	ar9287_1_1_rx_gain_vals_2g
};
