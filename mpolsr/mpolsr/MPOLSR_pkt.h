/***************************************************************************
 *   Copyright (C) 2004 by Francisco J. Ros                                *
 *   fjrm@dif.um.es                                                        *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

///
/// \file	MPOLSR_pkt.h
/// \brief	This file contains all declarations of %MPOLSR packets and messages,
///		including all related contants and macros.
///

#ifndef __MPOLSR_pkt_h__
#define __MPOLSR_pkt_h__

#include "packet.h"

/********** Message types **********/

/// %MPOLSR HELLO message type.
#define MPOLSR_HELLO_MSG		1
/// %MPOLSR TC message type.
#define MPOLSR_TC_MSG		2
/// %MPOLSR MID message type.
#define MPOLSR_MID_MSG		3

/********** Packets stuff **********/

/// Accessor to the %MPOLSR packet.
#define PKT_MPOLSR(p)		MPOLSR_pkt::access(p)

///
/// \brief Size of the addresses we are using.
///
/// You should always use this macro when interested in calculate addresses'
/// sizes. By default IPv4 addresses are supposed, but you can change to
/// IPv6 ones by recompiling with MPOLSR_IPv6 constant defined.
///
#ifdef MPOLSR_IPv6
#define ADDR_SIZE	16
#else
#define ADDR_SIZE	4
#endif

/// Maximum number of messages per packet.
#define MPOLSR_MAX_MSGS		4

/// Maximum number of hellos per message (4 possible link types * 3 possible nb types).
#define MPOLSR_MAX_HELLOS		12

/// Maximum number of addresses advertised on a message.
#define MPOLSR_MAX_ADDRS		64

/// Size (in bytes) of packet header.
#define MPOLSR_PKT_HDR_SIZE	4

/// Size (in bytes) of message header.
#define MPOLSR_MSG_HDR_SIZE	12

/// Size (in bytes) of hello header.
#define MPOLSR_HELLO_HDR_SIZE	4

/// Size (in bytes) of hello_msg header.
#define MPOLSR_HELLO_MSG_HDR_SIZE	4

/// Size (in bytes) of tc header.
#define MPOLSR_TC_HDR_SIZE	4

/// Auxiliary struct which is part of the %MPOLSR HELLO message (struct MPOLSR_hello).
typedef struct MPOLSR_hello_msg {

        /// Link code.
	u_int8_t	link_code_;
	/// Reserved.
	u_int8_t	reserved_;
	/// Size of this link message.
	u_int16_t	link_msg_size_;
	/// List of interface addresses of neighbor nodes.
	nsaddr_t	nb_iface_addrs_[MPOLSR_MAX_ADDRS];
	/// Number of interface addresses contained in nb_iface_addrs_.
	int		count;
	
	inline u_int8_t&	link_code()		{ return link_code_; }
	inline u_int8_t&	reserved()		{ return reserved_; }
	inline u_int16_t&	link_msg_size()		{ return link_msg_size_; }
	inline nsaddr_t&	nb_iface_addr(int i)	{ return nb_iface_addrs_[i]; }
	
	inline u_int32_t size() { return MPOLSR_HELLO_MSG_HDR_SIZE + count*ADDR_SIZE; }

} MPOLSR_hello_msg;

/// %MPOLSR HELLO message.
typedef struct MPOLSR_hello {

	/// Reserved.
	u_int16_t	reserved_;
	/// HELLO emission interval in mantissa/exponent format.
	u_int8_t	htime_;
	/// Willingness of a node for forwarding packets on behalf of other nodes.
	u_int8_t	willingness_;
	/// List of MPOLSR_hello_msg.
	MPOLSR_hello_msg	hello_body_[MPOLSR_MAX_HELLOS];
	/// Number of MPOLSR_hello_msg contained in hello_body_.
	int		count;
	
	inline u_int16_t&	reserved()		{ return reserved_; }
	inline u_int8_t&	htime()			{ return htime_; }
	inline u_int8_t&	willingness()		{ return willingness_; }
	inline MPOLSR_hello_msg&	hello_msg(int i)	{ return hello_body_[i]; }
	
	inline u_int32_t size() {
		u_int32_t sz = MPOLSR_HELLO_HDR_SIZE;
		for (int i = 0; i < count; i++)
			sz += hello_msg(i).size();
		return sz;
	}
	
} MPOLSR_hello;

/// %MPOLSR TC message.
typedef struct MPOLSR_tc {

        /// Advertised Neighbor Sequence Number.
	u_int16_t	ansn_;
	/// Reserved.
	u_int16_t	reserved_;
	/// List of neighbors' main addresses.
	nsaddr_t	nb_main_addrs_[MPOLSR_MAX_ADDRS];
	/// Number of neighbors' main addresses contained in nb_main_addrs_.
	int		count;
        
	inline	u_int16_t&	ansn()			{ return ansn_; }
	inline	u_int16_t&	reserved()		{ return reserved_; }
	inline	nsaddr_t&	nb_main_addr(int i)	{ return nb_main_addrs_[i]; }
	
	inline	u_int32_t size() { return MPOLSR_TC_HDR_SIZE + count*ADDR_SIZE; }

} MPOLSR_tc;

/// %MPOLSR MID message.
typedef struct MPOLSR_mid {

	/// List of interface addresses.
	nsaddr_t	iface_addrs_[MPOLSR_MAX_ADDRS];
	/// Number of interface addresses contained in iface_addrs_.
	int		count;
	
	inline nsaddr_t&	iface_addr(int i)	{ return iface_addrs_[i]; }
	
	inline u_int32_t	size()			{ return count*ADDR_SIZE; }
	
} MPOLSR_mid;

/// %MPOLSR message.
typedef struct MPOLSR_msg {

	u_int8_t	msg_type_;	///< Message type.
	u_int8_t	vtime_;		///< Validity time.
	u_int16_t	msg_size_;	///< Message size (in bytes).
	nsaddr_t	orig_addr_;	///< Main address of the node which generated this message.
	u_int8_t	ttl_;		///< Time to live (in hops).
	u_int8_t	hop_count_;	///< Number of hops which the message has taken.
	u_int16_t	msg_seq_num_;	///< Message sequence number.
	union {
		MPOLSR_hello	hello_;
		MPOLSR_tc		tc_;
		MPOLSR_mid	mid_;
	} msg_body_;			///< Message body.
	
	inline	u_int8_t&	msg_type()	{ return msg_type_; }
	inline	u_int8_t&	vtime()		{ return vtime_; }
	inline	u_int16_t&	msg_size()	{ return msg_size_; }
	inline	nsaddr_t&	orig_addr()	{ return orig_addr_; }
	inline	u_int8_t&	ttl()		{ return ttl_; }
	inline	u_int8_t&	hop_count()	{ return hop_count_; }
	inline	u_int16_t&	msg_seq_num()	{ return msg_seq_num_; }
	inline	MPOLSR_hello&	hello()		{ return msg_body_.hello_; }
	inline	MPOLSR_tc&	tc()		{ return msg_body_.tc_; }
	inline	MPOLSR_mid&	mid()		{ return msg_body_.mid_; }
	
	inline u_int32_t size() {
		u_int32_t sz = MPOLSR_MSG_HDR_SIZE;
		if (msg_type() == MPOLSR_HELLO_MSG)
			sz += hello().size();
		else if (msg_type() == MPOLSR_TC_MSG)
			sz += tc().size();
		else if (msg_type() == MPOLSR_MID_MSG)
			sz += mid().size();
		return sz;
	}

} MPOLSR_msg;

/// %MPOLSR packet.
typedef struct MPOLSR_pkt {

	u_int16_t	pkt_len_;			///< Packet length (in bytes).
	u_int16_t	pkt_seq_num_;			///< Packet sequence number.
	MPOLSR_msg	pkt_body_[MPOLSR_MAX_MSGS];	///< Packet body.
	int		count;				///< Number of MPOLSR_msg contained in pkt_body_.
	
	inline	u_int16_t&	pkt_len()	{ return pkt_len_; }
	inline	u_int16_t&	pkt_seq_num()	{ return pkt_seq_num_; }
	inline	MPOLSR_msg&	msg(int i)	{ return pkt_body_[i]; }
	
	static int offset_;
	inline static int& offset() { return offset_; }
	inline static struct MPOLSR_pkt* access(const Packet* p) {
		return (struct MPOLSR_pkt*)p->access(offset_);
	}

} MPOLSR_pkt;

#endif
