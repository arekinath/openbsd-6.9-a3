/* Automatically generated from ofp.h, do not edit */
/*	$OpenBSD: ofp_map.c,v 1.1 2016/11/18 17:37:03 reyk Exp $	*/

/*
 * Copyright (c) 2013-2016 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2016 Kazuya GODA <goda@openbsd.org>
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

#include <sys/types.h>
#include <net/ofp.h>
#include "ofp_map.h"

struct constmap ofp_v_map[] = {
	{ OFP_V_0, "0" },
	{ OFP_V_1_0, "1_0" },
	{ OFP_V_1_1, "1_1" },
	{ OFP_V_1_2, "1_2" },
	{ OFP_V_1_3, "1_3" },
	{ OFP_V_1_4, "1_4" },
	{ OFP_V_1_5, "1_5" },
	{ 0 }
};
struct constmap ofp_t_map[] = {
	{ OFP_T_HELLO, "HELLO" },
	{ OFP_T_ERROR, "ERROR" },
	{ OFP_T_ECHO_REQUEST, "ECHO_REQUEST" },
	{ OFP_T_ECHO_REPLY, "ECHO_REPLY" },
	{ OFP_T_EXPERIMENTER, "EXPERIMENTER" },
	{ OFP_T_FEATURES_REQUEST, "FEATURES_REQUEST" },
	{ OFP_T_FEATURES_REPLY, "FEATURES_REPLY" },
	{ OFP_T_GET_CONFIG_REQUEST, "GET_CONFIG_REQUEST" },
	{ OFP_T_GET_CONFIG_REPLY, "GET_CONFIG_REPLY" },
	{ OFP_T_SET_CONFIG, "SET_CONFIG" },
	{ OFP_T_PACKET_IN, "PACKET_IN" },
	{ OFP_T_FLOW_REMOVED, "FLOW_REMOVED" },
	{ OFP_T_PORT_STATUS, "PORT_STATUS" },
	{ OFP_T_PACKET_OUT, "PACKET_OUT" },
	{ OFP_T_FLOW_MOD, "FLOW_MOD" },
	{ OFP_T_GROUP_MOD, "GROUP_MOD" },
	{ OFP_T_PORT_MOD, "PORT_MOD" },
	{ OFP_T_TABLE_MOD, "TABLE_MOD" },
	{ OFP_T_MULTIPART_REQUEST, "MULTIPART_REQUEST" },
	{ OFP_T_MULTIPART_REPLY, "MULTIPART_REPLY" },
	{ OFP_T_BARRIER_REQUEST, "BARRIER_REQUEST" },
	{ OFP_T_BARRIER_REPLY, "BARRIER_REPLY" },
	{ OFP_T_QUEUE_GET_CONFIG_REQUEST, "QUEUE_GET_CONFIG_REQUEST" },
	{ OFP_T_QUEUE_GET_CONFIG_REPLY, "QUEUE_GET_CONFIG_REPLY" },
	{ OFP_T_ROLE_REQUEST, "ROLE_REQUEST" },
	{ OFP_T_ROLE_REPLY, "ROLE_REPLY" },
	{ OFP_T_GET_ASYNC_REQUEST, "GET_ASYNC_REQUEST" },
	{ OFP_T_GET_ASYNC_REPLY, "GET_ASYNC_REPLY" },
	{ OFP_T_SET_ASYNC, "SET_ASYNC" },
	{ OFP_T_METER_MOD, "METER_MOD" },
	{ 0 }
};
struct constmap ofp_pktin_map[] = {
	{ OFP_PKTIN_REASON_NO_MATCH, "REASON_NO_MATCH" },
	{ OFP_PKTIN_REASON_ACTION, "REASON_ACTION" },
	{ OFP_PKTIN_REASON_TTL, "REASON_TTL" },
	{ 0 }
};
struct constmap ofp_port_map[] = {
	{ OFP_PORT_MAX, "MAX" },
	{ OFP_PORT_INPUT, "INPUT" },
	{ OFP_PORT_FLOWTABLE, "FLOWTABLE" },
	{ OFP_PORT_NORMAL, "NORMAL" },
	{ OFP_PORT_FLOOD, "FLOOD" },
	{ OFP_PORT_ALL, "ALL" },
	{ OFP_PORT_CONTROLLER, "CONTROLLER" },
	{ OFP_PORT_LOCAL, "LOCAL" },
	{ OFP_PORT_ANY, "ANY" },
	{ 0 }
};
struct constmap ofp_pktout_map[] = {
	{ OFP_PKTOUT_NO_BUFFER, "NO_BUFFER" },
	{ 0 }
};
struct constmap ofp_oxm_c_map[] = {
	{ OFP_OXM_C_NXM_0, "NXM_0" },
	{ OFP_OXM_C_NXM_1, "NXM_1" },
	{ OFP_OXM_C_OPENFLOW_BASIC, "OPENFLOW_BASIC" },
	{ OFP_OXM_C_OPENFLOW_EXPERIMENTER, "OPENFLOW_EXPERIMENTER" },
	{ 0 }
};
struct constmap ofp_xm_t_map[] = {
	{ OFP_XM_T_IN_PORT, "IN_PORT" },
	{ OFP_XM_T_IN_PHY_PORT, "IN_PHY_PORT" },
	{ OFP_XM_T_META, "META" },
	{ OFP_XM_T_ETH_DST, "ETH_DST" },
	{ OFP_XM_T_ETH_SRC, "ETH_SRC" },
	{ OFP_XM_T_ETH_TYPE, "ETH_TYPE" },
	{ OFP_XM_T_VLAN_VID, "VLAN_VID" },
	{ OFP_XM_T_VLAN_PCP, "VLAN_PCP" },
	{ OFP_XM_T_IP_DSCP, "IP_DSCP" },
	{ OFP_XM_T_IP_ECN, "IP_ECN" },
	{ OFP_XM_T_IP_PROTO, "IP_PROTO" },
	{ OFP_XM_T_IPV4_SRC, "IPV4_SRC" },
	{ OFP_XM_T_IPV4_DST, "IPV4_DST" },
	{ OFP_XM_T_TCP_SRC, "TCP_SRC" },
	{ OFP_XM_T_TCP_DST, "TCP_DST" },
	{ OFP_XM_T_UDP_SRC, "UDP_SRC" },
	{ OFP_XM_T_UDP_DST, "UDP_DST" },
	{ OFP_XM_T_SCTP_SRC, "SCTP_SRC" },
	{ OFP_XM_T_SCTP_DST, "SCTP_DST" },
	{ OFP_XM_T_ICMPV4_TYPE, "ICMPV4_TYPE" },
	{ OFP_XM_T_ICMPV4_CODE, "ICMPV4_CODE" },
	{ OFP_XM_T_ARP_OP, "ARP_OP" },
	{ OFP_XM_T_ARP_SPA, "ARP_SPA" },
	{ OFP_XM_T_ARP_TPA, "ARP_TPA" },
	{ OFP_XM_T_ARP_SHA, "ARP_SHA" },
	{ OFP_XM_T_ARP_THA, "ARP_THA" },
	{ OFP_XM_T_IPV6_SRC, "IPV6_SRC" },
	{ OFP_XM_T_IPV6_DST, "IPV6_DST" },
	{ OFP_XM_T_IPV6_FLABEL, "IPV6_FLABEL" },
	{ OFP_XM_T_ICMPV6_TYPE, "ICMPV6_TYPE" },
	{ OFP_XM_T_ICMPV6_CODE, "ICMPV6_CODE" },
	{ OFP_XM_T_IPV6_ND_TARGET, "IPV6_ND_TARGET" },
	{ OFP_XM_T_IPV6_ND_SLL, "IPV6_ND_SLL" },
	{ OFP_XM_T_IPV6_ND_TLL, "IPV6_ND_TLL" },
	{ OFP_XM_T_MPLS_LABEL, "MPLS_LABEL" },
	{ OFP_XM_T_MPLS_TC, "MPLS_TC" },
	{ OFP_XM_T_MPLS_BOS, "MPLS_BOS" },
	{ OFP_XM_T_PBB_ISID, "PBB_ISID" },
	{ OFP_XM_T_TUNNEL_ID, "TUNNEL_ID" },
	{ OFP_XM_T_IPV6_EXTHDR, "IPV6_EXTHDR" },
	{ 0 }
};
struct constmap ofp_config_map[] = {
	{ OFP_CONFIG_FRAG_NORMAL, "FRAG_NORMAL" },
	{ OFP_CONFIG_FRAG_DROP, "FRAG_DROP" },
	{ OFP_CONFIG_FRAG_REASM, "FRAG_REASM" },
	{ OFP_CONFIG_FRAG_MASK, "FRAG_MASK" },
	{ 0 }
};
struct constmap ofp_controller_maxlen_map[] = {
	{ OFP_CONTROLLER_MAXLEN_MAX, "MAX" },
	{ OFP_CONTROLLER_MAXLEN_NO_BUFFER, "NO_BUFFER" },
	{ 0 }
};
struct constmap ofp_instruction_t_map[] = {
	{ OFP_INSTRUCTION_T_GOTO_TABLE, "GOTO_TABLE" },
	{ OFP_INSTRUCTION_T_WRITE_META, "WRITE_META" },
	{ OFP_INSTRUCTION_T_WRITE_ACTIONS, "WRITE_ACTIONS" },
	{ OFP_INSTRUCTION_T_APPLY_ACTIONS, "APPLY_ACTIONS" },
	{ OFP_INSTRUCTION_T_CLEAR_ACTIONS, "CLEAR_ACTIONS" },
	{ OFP_INSTRUCTION_T_METER, "METER" },
	{ OFP_INSTRUCTION_T_EXPERIMENTER, "EXPERIMENTER" },
	{ 0 }
};
struct constmap ofp_portstate_map[] = {
	{ OFP_PORTSTATE_LINK_DOWN, "LINK_DOWN" },
	{ OFP_PORTSTATE_STP_LISTEN, "STP_LISTEN" },
	{ OFP_PORTSTATE_STP_LEARN, "STP_LEARN" },
	{ OFP_PORTSTATE_STP_FORWARD, "STP_FORWARD" },
	{ OFP_PORTSTATE_STP_BLOCK, "STP_BLOCK" },
	{ OFP_PORTSTATE_STP_MASK, "STP_MASK" },
	{ 0 }
};
struct constmap ofp_portconfig_map[] = {
	{ OFP_PORTCONFIG_PORT_DOWN, "PORT_DOWN" },
	{ OFP_PORTCONFIG_NO_STP, "NO_STP" },
	{ OFP_PORTCONFIG_NO_RECV, "NO_RECV" },
	{ OFP_PORTCONFIG_NO_RECV_STP, "NO_RECV_STP" },
	{ OFP_PORTCONFIG_NO_FLOOD, "NO_FLOOD" },
	{ OFP_PORTCONFIG_NO_FWD, "NO_FWD" },
	{ OFP_PORTCONFIG_NO_PACKET_IN, "NO_PACKET_IN" },
	{ 0 }
};
struct constmap ofp_portmedia_map[] = {
	{ OFP_PORTMEDIA_10MB_HD, "10MB_HD" },
	{ OFP_PORTMEDIA_10MB_FD, "10MB_FD" },
	{ OFP_PORTMEDIA_100MB_HD, "100MB_HD" },
	{ OFP_PORTMEDIA_100MB_FD, "100MB_FD" },
	{ OFP_PORTMEDIA_1GB_HD, "1GB_HD" },
	{ OFP_PORTMEDIA_1GB_FD, "1GB_FD" },
	{ OFP_PORTMEDIA_10GB_FD, "10GB_FD" },
	{ OFP_PORTMEDIA_COPPER, "COPPER" },
	{ OFP_PORTMEDIA_FIBER, "FIBER" },
	{ OFP_PORTMEDIA_AUTONEG, "AUTONEG" },
	{ OFP_PORTMEDIA_PAUSE, "PAUSE" },
	{ OFP_PORTMEDIA_PAUSE_ASYM, "PAUSE_ASYM" },
	{ 0 }
};
struct constmap ofp_pktin_reason_map[] = {
	{ OFP_PKTIN_REASON_NO_MATCH, "NO_MATCH" },
	{ OFP_PKTIN_REASON_ACTION, "ACTION" },
	{ OFP_PKTIN_REASON_TTL, "TTL" },
	{ 0 }
};
struct constmap ofp_swcap_map[] = {
	{ OFP_SWCAP_FLOW_STATS, "FLOW_STATS" },
	{ OFP_SWCAP_TABLE_STATS, "TABLE_STATS" },
	{ OFP_SWCAP_PORT_STATS, "PORT_STATS" },
	{ OFP_SWCAP_GROUP_STATS, "GROUP_STATS" },
	{ OFP_SWCAP_IP_REASM, "IP_REASM" },
	{ OFP_SWCAP_QUEUE_STATS, "QUEUE_STATS" },
	{ OFP_SWCAP_ARP_MATCH_IP, "ARP_MATCH_IP" },
	{ OFP_SWCAP_PORT_BLOCKED, "PORT_BLOCKED" },
	{ 0 }
};
struct constmap ofp_table_id_map[] = {
	{ OFP_TABLE_ID_MAX, "MAX" },
	{ OFP_TABLE_ID_ALL, "ALL" },
	{ 0 }
};
struct constmap ofp_match_map[] = {
	{ OFP_MATCH_STANDARD, "STANDARD" },
	{ OFP_MATCH_OXM, "OXM" },
	{ 0 }
};
struct constmap ofp_mp_t_map[] = {
	{ OFP_MP_T_DESC, "DESC" },
	{ OFP_MP_T_FLOW, "FLOW" },
	{ OFP_MP_T_AGGREGATE, "AGGREGATE" },
	{ OFP_MP_T_TABLE, "TABLE" },
	{ OFP_MP_T_PORT_STATS, "PORT_STATS" },
	{ OFP_MP_T_QUEUE, "QUEUE" },
	{ OFP_MP_T_GROUP, "GROUP" },
	{ OFP_MP_T_GROUP_DESC, "GROUP_DESC" },
	{ OFP_MP_T_GROUP_FEATURES, "GROUP_FEATURES" },
	{ OFP_MP_T_METER, "METER" },
	{ OFP_MP_T_METER_CONFIG, "METER_CONFIG" },
	{ OFP_MP_T_METER_FEATURES, "METER_FEATURES" },
	{ OFP_MP_T_TABLE_FEATURES, "TABLE_FEATURES" },
	{ OFP_MP_T_PORT_DESC, "PORT_DESC" },
	{ OFP_MP_T_EXPERIMENTER, "EXPERIMENTER" },
	{ 0 }
};
struct constmap ofp_action_map[] = {
	{ OFP_ACTION_OUTPUT, "OUTPUT" },
	{ OFP_ACTION_COPY_TTL_OUT, "COPY_TTL_OUT" },
	{ OFP_ACTION_COPY_TTL_IN, "COPY_TTL_IN" },
	{ OFP_ACTION_SET_MPLS_TTL, "SET_MPLS_TTL" },
	{ OFP_ACTION_DEC_MPLS_TTL, "DEC_MPLS_TTL" },
	{ OFP_ACTION_PUSH_VLAN, "PUSH_VLAN" },
	{ OFP_ACTION_POP_VLAN, "POP_VLAN" },
	{ OFP_ACTION_PUSH_MPLS, "PUSH_MPLS" },
	{ OFP_ACTION_POP_MPLS, "POP_MPLS" },
	{ OFP_ACTION_SET_QUEUE, "SET_QUEUE" },
	{ OFP_ACTION_GROUP, "GROUP" },
	{ OFP_ACTION_SET_NW_TTL, "SET_NW_TTL" },
	{ OFP_ACTION_DEC_NW_TTL, "DEC_NW_TTL" },
	{ OFP_ACTION_SET_FIELD, "SET_FIELD" },
	{ OFP_ACTION_PUSH_PBB, "PUSH_PBB" },
	{ OFP_ACTION_POP_PBB, "POP_PBB" },
	{ OFP_ACTION_EXPERIMENTER, "EXPERIMENTER" },
	{ 0 }
};
struct constmap ofp_flowcmd_map[] = {
	{ OFP_FLOWCMD_ADD, "ADD" },
	{ OFP_FLOWCMD_MODIFY, "MODIFY" },
	{ OFP_FLOWCMD_MODIFY_STRICT, "MODIFY_STRICT" },
	{ OFP_FLOWCMD_DELETE, "DELETE" },
	{ OFP_FLOWCMD_DELETE_STRICT, "DELETE_STRICT" },
	{ 0 }
};
struct constmap ofp_flowflag_map[] = {
	{ OFP_FLOWFLAG_SEND_FLOW_REMOVED, "SEND_FLOW_REMOVED" },
	{ OFP_FLOWFLAG_CHECK_OVERLAP, "CHECK_OVERLAP" },
	{ OFP_FLOWFLAG_RESET_COUNTS, "RESET_COUNTS" },
	{ OFP_FLOWFLAG_NO_PACKET_COUNTS, "NO_PACKET_COUNTS" },
	{ OFP_FLOWFLAG_NO_BYTE_COUNTS, "NO_BYTE_COUNTS" },
	{ 0 }
};
struct constmap ofp_flowrem_reason_map[] = {
	{ OFP_FLOWREM_REASON_IDLE_TIMEOUT, "IDLE_TIMEOUT" },
	{ OFP_FLOWREM_REASON_HARD_TIMEOUT, "HARD_TIMEOUT" },
	{ OFP_FLOWREM_REASON_DELETE, "DELETE" },
	{ OFP_FLOWREM_REASON_GROUP_DELETE, "GROUP_DELETE" },
	{ 0 }
};
struct constmap ofp_group_id_map[] = {
	{ OFP_GROUP_ID_MAX, "MAX" },
	{ OFP_GROUP_ID_ALL, "ALL" },
	{ OFP_GROUP_ID_ANY, "ANY" },
	{ 0 }
};
struct constmap ofp_errtype_map[] = {
	{ OFP_ERRTYPE_HELLO_FAILED, "HELLO_FAILED" },
	{ OFP_ERRTYPE_BAD_REQUEST, "BAD_REQUEST" },
	{ OFP_ERRTYPE_BAD_ACTION, "BAD_ACTION" },
	{ OFP_ERRTYPE_BAD_INSTRUCTION, "BAD_INSTRUCTION" },
	{ OFP_ERRTYPE_BAD_MATCH, "BAD_MATCH" },
	{ OFP_ERRTYPE_FLOW_MOD_FAILED, "FLOW_MOD_FAILED" },
	{ OFP_ERRTYPE_GROUP_MOD_FAILED, "GROUP_MOD_FAILED" },
	{ OFP_ERRTYPE_PORT_MOD_FAILED, "PORT_MOD_FAILED" },
	{ OFP_ERRTYPE_TABLE_MOD_FAILED, "TABLE_MOD_FAILED" },
	{ OFP_ERRTYPE_QUEUE_OP_FAILED, "QUEUE_OP_FAILED" },
	{ OFP_ERRTYPE_SWITCH_CFG_FAILED, "SWITCH_CFG_FAILED" },
	{ OFP_ERRTYPE_ROLE_REQUEST_FAILED, "ROLE_REQUEST_FAILED" },
	{ OFP_ERRTYPE_METER_MOD_FAILED, "METER_MOD_FAILED" },
	{ OFP_ERRTYPE_TABLE_FEATURES_FAILED, "TABLE_FEATURES_FAILED" },
	{ OFP_ERRTYPE_EXPERIMENTER, "EXPERIMENTER" },
	{ 0 }
};
struct constmap ofp_errflowmod_map[] = {
	{ OFP_ERRFLOWMOD_UNKNOWN, "UNKNOWN" },
	{ OFP_ERRFLOWMOD_TABLE_FULL, "TABLE_FULL" },
	{ OFP_ERRFLOWMOD_TABLE_ID, "TABLE_ID" },
	{ OFP_ERRFLOWMOD_OVERLAP, "OVERLAP" },
	{ OFP_ERRFLOWMOD_EPERM, "EPERM" },
	{ OFP_ERRFLOWMOD_BAD_TIMEOUT, "BAD_TIMEOUT" },
	{ OFP_ERRFLOWMOD_BAD_COMMAND, "BAD_COMMAND" },
	{ OFP_ERRFLOWMOD_BAD_FLAGS, "BAD_FLAGS" },
	{ 0 }
};
struct constmap ofp_errmatch_map[] = {
	{ OFP_ERRMATCH_BAD_TYPE, "BAD_TYPE" },
	{ OFP_ERRMATCH_BAD_LEN, "BAD_LEN" },
	{ OFP_ERRMATCH_BAD_TAG, "BAD_TAG" },
	{ OFP_ERRMATCH_BAD_DL_ADDR_MASK, "BAD_DL_ADDR_MASK" },
	{ OFP_ERRMATCH_BAD_NW_ADDR_MASK, "BAD_NW_ADDR_MASK" },
	{ OFP_ERRMATCH_BAD_WILDCARDS, "BAD_WILDCARDS" },
	{ OFP_ERRMATCH_BAD_FIELD, "BAD_FIELD" },
	{ OFP_ERRMATCH_BAD_VALUE, "BAD_VALUE" },
	{ OFP_ERRMATCH_BAD_MASK, "BAD_MASK" },
	{ OFP_ERRMATCH_BAD_PREREQ, "BAD_PREREQ" },
	{ OFP_ERRMATCH_DUP_FIELD, "DUP_FIELD" },
	{ OFP_ERRMATCH_EPERM, "EPERM" },
	{ 0 }
};
struct constmap ofp_errinst_map[] = {
	{ OFP_ERRINST_UNKNOWN_INST, "UNKNOWN_INST" },
	{ OFP_ERRINST_UNSUPPORTED_INST, "UNSUPPORTED_INST" },
	{ OFP_ERRINST_TABLE_ID, "TABLE_ID" },
	{ OFP_ERRINST_UNSUPP_META, "UNSUPP_META" },
	{ OFP_ERRINST_UNSUPP_META_MASK, "UNSUPP_META_MASK" },
	{ OFP_ERRINST_BAD_EXPERIMENTER, "BAD_EXPERIMENTER" },
	{ OFP_ERRINST_BAD_EXPERIMENTER_TYPE, "BAD_EXPERIMENTER_TYPE" },
	{ OFP_ERRINST_BAD_LEN, "BAD_LEN" },
	{ OFP_ERRINST_EPERM, "EPERM" },
	{ 0 }
};
struct constmap ofp_errreq_map[] = {
	{ OFP_ERRREQ_VERSION, "VERSION" },
	{ OFP_ERRREQ_TYPE, "TYPE" },
	{ OFP_ERRREQ_MULTIPART, "MULTIPART" },
	{ OFP_ERRREQ_EXPERIMENTER, "EXPERIMENTER" },
	{ OFP_ERRREQ_EXP_TYPE, "EXP_TYPE" },
	{ OFP_ERRREQ_EPERM, "EPERM" },
	{ OFP_ERRREQ_BAD_LEN, "BAD_LEN" },
	{ OFP_ERRREQ_BUFFER_EMPTY, "BUFFER_EMPTY" },
	{ OFP_ERRREQ_BUFFER_UNKNOWN, "BUFFER_UNKNOWN" },
	{ OFP_ERRREQ_TABLE_ID, "TABLE_ID" },
	{ OFP_ERRREQ_IS_SLAVE, "IS_SLAVE" },
	{ OFP_ERRREQ_PORT, "PORT" },
	{ OFP_ERRREQ_PACKET, "PACKET" },
	{ OFP_ERRREQ_MULTIPART_OVERFLOW, "MULTIPART_OVERFLOW" },
	{ 0 }
};
struct constmap ofp_table_featprop_map[] = {
	{ OFP_TABLE_FEATPROP_INSTRUCTION, "INSTRUCTION" },
	{ OFP_TABLE_FEATPROP_INSTRUCTION_MISS, "INSTRUCTION_MISS" },
	{ OFP_TABLE_FEATPROP_NEXT_TABLES, "NEXT_TABLES" },
	{ OFP_TABLE_FEATPROP_NEXT_TABLES_MISS, "NEXT_TABLES_MISS" },
	{ OFP_TABLE_FEATPROP_WRITE_ACTIONS, "WRITE_ACTIONS" },
	{ OFP_TABLE_FEATPROP_WRITE_ACTIONS_MISS, "WRITE_ACTIONS_MISS" },
	{ OFP_TABLE_FEATPROP_APPLY_ACTIONS, "APPLY_ACTIONS" },
	{ OFP_TABLE_FEATPROP_APPLY_ACTIONS_MISS, "APPLY_ACTIONS_MISS" },
	{ OFP_TABLE_FEATPROP_MATCH, "MATCH" },
	{ OFP_TABLE_FEATPROP_WILDCARDS, "WILDCARDS" },
	{ OFP_TABLE_FEATPROP_WRITE_SETFIELD, "WRITE_SETFIELD" },
	{ OFP_TABLE_FEATPROP_WRITE_SETFIELD_MISS, "WRITE_SETFIELD_MISS" },
	{ OFP_TABLE_FEATPROP_APPLY_SETFIELD, "APPLY_SETFIELD" },
	{ OFP_TABLE_FEATPROP_APPLY_SETFIELD_MISS, "APPLY_SETFIELD_MISS" },
	{ OFP_TABLE_FEATPROP_EXPERIMENTER, "EXPERIMENTER" },
	{ OFP_TABLE_FEATPROP_EXPERIMENTER_MISS, "EXPERIMENTER_MISS" },
	{ 0 }
};