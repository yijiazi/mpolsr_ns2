/*              Copyright (C) 2010
	*             Multipath Extension by Jiazi Yi,                            *
 	*                   2007   Ecole Polytech of Nantes, France               * 
 	*                   jiazi.yi@univ-nantes.fr				   *
 	****************************************************************************
 	*    	This program is distributed in the hope that it will be useful,				*
	*    	but WITHOUT ANY WARRANTY; without even the implied warranty of				*
	*    	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 					*
 	**************************************************************************
*/
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
/// \file	MPOLSR.cc
/// \brief	Implementation of MPOLSR agent and related classes.
///
/// This is the main file of this software because %MPOLSR's behaviour is
/// implemented here.
///

#include "mpolsr/MPOLSR.h"
#include "mpolsr/MPOLSR_pkt.h"
#include "mpolsr/MPOLSR_printer.h"
#include "mpolsr/hdr_sr.h"
//#include "mpolsr/Srpacket.h"
#include "math.h"
#include "limits.h"
#include "address.h"
#include "ip.h"
#include "cmu-trace.h"
#include "map"
#include "set"
#include <iostream>

using namespace std;

/// Length (in bytes) of UDP header.
#define UDP_HDR_LEN	8

///
/// \brief Function called by MAC layer when cannot deliver a packet.
///
/// \param p Packet which couldn't be delivered.
/// \param arg MPOLSR agent passed for a callback.
///
static void
mpolsr_mac_failed_callback(Packet *p, void *arg) {
  ((MPOLSR*)arg)->mac_failed(p);
}


/********** TCL Hooks **********/


int MPOLSR_pkt::offset_;
static class MPOLSRHeaderClass : public PacketHeaderClass {
public:
	MPOLSRHeaderClass() : PacketHeaderClass("PacketHeader/MPOLSR", sizeof(MPOLSR_pkt)) {
		bind_offset(&MPOLSR_pkt::offset_);
	}
} class_rtProtoMPOLSR_hdr;

static class MPOLSRClass : public TclClass {
public:
	MPOLSRClass() : TclClass("Agent/MPOLSR") {}
	TclObject* create(int argc, const char*const* argv) {
		// argv has the following structure:
		// <tcl-object> <tcl-object> Agent/MPOLSR create-shadow <id>
		// e.g: _o17 _o17 Agent/MPOLSR create-shadow 0
		// argv[4] is the address of the node
		assert(argc == 5);
		return new MPOLSR((nsaddr_t)Address::instance().str2addr(argv[4]));
	}
} class_rtProtoMPOLSR;

///
/// \brief Interface with TCL interpreter.
///
/// From your TCL scripts or shell you can invoke commands on this MPOLSR
/// routing agent thanks to this function. Currently you can call "start",
/// "print_rtable", "print_linkset", "print_nbset", "print_nb2hopset",
/// "print_mprset", "print_mprselset" and "print_topologyset" commands.
///
/// \param argc Number of arguments.
/// \param argv Arguments.
/// \return TCL_OK or TCL_ERROR.
///
int
MPOLSR::command(int argc, const char*const* argv) {
	if (argc == 2) {
		// Starts all timers
		if (strcasecmp(argv[1], "start") == 0) {
			hello_timer_.resched(0.0);
			tc_timer_.resched(0.0);
			mid_timer_.resched(0.0);
			
			return TCL_OK;
    		}
		// Prints routing table
		else if (strcasecmp(argv[1], "print_rtable") == 0) {
			if (logtarget_ != NULL) {
				sprintf(logtarget_->pt_->buffer(), "P %f _%d_ Routing Table",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()));
				logtarget_->pt_->dump();
				rtable_.print(logtarget_);
			}
			else {
				fprintf(stdout, "%f _%d_ If you want to print this routing table "
					"you must create a trace file in your tcl script",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()));
			}
			return TCL_OK;
		}
		// Prints link set
		else if (strcasecmp(argv[1], "print_linkset") == 0) {
			if (logtarget_ != NULL) {
				sprintf(logtarget_->pt_->buffer(), "P %f _%d_ Link Set",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()));
				logtarget_->pt_->dump();
				MPOLSR_printer::print_linkset(logtarget_, linkset());
			}
			else {
				fprintf(stdout, "%f _%d_ If you want to print this link set "
					"you must create a trace file in your tcl script",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()));
			}
			return TCL_OK;
		}
		// Prints neighbor set
		else if (strcasecmp(argv[1], "print_nbset") == 0) {
			if (logtarget_ != NULL) {
				sprintf(logtarget_->pt_->buffer(), "P %f _%d_ Neighbor Set",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()));
				logtarget_->pt_->dump();
				MPOLSR_printer::print_nbset(logtarget_, nbset());
			}
			else {
				fprintf(stdout, "%f _%d_ If you want to print this neighbor set "
					"you must create a trace file in your tcl script",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()));
			}
			return TCL_OK;
		}
		// Prints 2-hop neighbor set
		else if (strcasecmp(argv[1], "print_nb2hopset") == 0) {
			if (logtarget_ != NULL) {
				sprintf(logtarget_->pt_->buffer(), "P %f _%d_ Neighbor2hop Set",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()));
				logtarget_->pt_->dump();
				MPOLSR_printer::print_nb2hopset(logtarget_, nb2hopset());
			}
			else {
				fprintf(stdout, "%f _%d_ If you want to print this neighbor2hop set "
					"you must create a trace file in your tcl script",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()));
			}
			return TCL_OK;
		}
		// Prints MPR set
		else if (strcasecmp(argv[1], "print_mprset") == 0) {
			if (logtarget_ != NULL) {
				sprintf(logtarget_->pt_->buffer(), "P %f _%d_ MPR Set",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()));
				logtarget_->pt_->dump();
				MPOLSR_printer::print_mprset(logtarget_, mprset());
			}
			else {
				fprintf(stdout, "%f _%d_ If you want to print this mpr set "
					"you must create a trace file in your tcl script",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()));
			}
			return TCL_OK;
		}
		// Prints MPR selector set
		else if (strcasecmp(argv[1], "print_mprselset") == 0) {
			if (logtarget_ != NULL) {
				sprintf(logtarget_->pt_->buffer(), "P %f _%d_ MPR Selector Set",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()));
				logtarget_->pt_->dump();
				MPOLSR_printer::print_mprselset(logtarget_, mprselset());
			}
			else {
				fprintf(stdout, "%f _%d_ If you want to print this mpr selector set "
					"you must create a trace file in your tcl script",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()));
			}
			return TCL_OK;
		}
		// Prints topology set
		else if (strcasecmp(argv[1], "print_topologyset") == 0) {
			if (logtarget_ != NULL) {
				sprintf(logtarget_->pt_->buffer(), "P %f _%d_ Topology Set",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()));
				logtarget_->pt_->dump();
				MPOLSR_printer::print_topologyset(logtarget_, topologyset());
			}
			else {
				fprintf(stdout, "%f _%d_ If you want to print this topology set "
					"you must create a trace file in your tcl script",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()));
			}
			return TCL_OK;
		}
	}
	else if (argc == 3) {
		// Obtains the corresponding dmux to carry packets to upper layers
		if (strcmp(argv[1], "port-dmux") == 0) {
    			dmux_ = (PortClassifier*)TclObject::lookup(argv[2]);
			if (dmux_ == NULL) {
				fprintf(stderr, "%s: %s lookup of %s failed\n", __FILE__, argv[1], argv[2]);
				return TCL_ERROR;
			}
			return TCL_OK;
    		}
		// Obtains the corresponding tracer
		else if (strcmp(argv[1], "log-target") == 0 || strcmp(argv[1], "tracetarget") == 0) {
			logtarget_ = (Trace*)TclObject::lookup(argv[2]);
			if (logtarget_ == NULL)
				return TCL_ERROR;
			return TCL_OK;
		}
	}
      	else if (strcasecmp(argv[1], "add-ll") == 0) {
		TclObject* obj;
		  if( (obj = TclObject::lookup(argv[2])) == 0) {
		    fprintf(stderr, "DSRAgent: %s lookup of %s failed\n", argv[1],
			    argv[2]);
		    return TCL_ERROR;
		  }
		  ll = (NsObject*) obj;
		  if( (obj = TclObject::lookup(argv[3])) == 0) {
		    fprintf(stderr, "DSRAgent: %s lookup of %s failed\n", argv[1],
			    argv[3]);
		    return TCL_ERROR;
		  }
		  ifq = (CMUPriQueue *) obj;
		  return TCL_OK;

	}
	// Pass the command up to the base class
	return Agent::command(argc, argv);
}


/********** Timers **********/


///
/// \brief Sends a HELLO message and reschedules the HELLO timer.
/// \param e The event which has expired.
///
void
MPOLSR_HelloTimer::expire(Event* e) {
	agent_->send_hello();
	agent_->set_hello_timer();
}

///
/// \brief Sends a TC message (if there exists any MPR selector) and reschedules the TC timer.
/// \param e The event which has expired.
///
void
MPOLSR_TcTimer::expire(Event* e) {
	if (agent_->mprselset().size() > 0)
		agent_->send_tc();
	agent_->set_tc_timer();
}

///
/// \brief Sends a MID message (if the node has more than one interface) and resets the MID timer.
/// \warning Currently it does nothing because there is no support for multiple interfaces.
/// \param e The event which has expired.
///
void
MPOLSR_MidTimer::expire(Event* e) {
#ifdef MULTIPLE_IFACES_SUPPORT
	agent_->send_mid();
	agent_->set_mid_timer();
#endif
}

///
/// \brief Removes tuple_ if expired. Else timer is rescheduled to expire at tuple_->time().
///
/// The task of actually removing the tuple is left to the MPOLSR agent.
///
/// \param e The event which has expired.
///
void
MPOLSR_DupTupleTimer::expire(Event* e) {
	if (tuple_->time() < CURRENT_TIME) {
		agent_->rm_dup_tuple(tuple_);
		delete tuple_;
		delete this;
	}
	else
		resched(DELAY(tuple_->time()));
}

///
/// \brief Removes tuple_ if expired. Else if symmetric time
/// has expired then it is assumed a neighbor loss and agent_->nb_loss()
/// is called. In this case the timer is rescheduled to expire at
/// tuple_->time(). Otherwise the timer is rescheduled to expire at
/// the minimum between tuple_->time() and tuple_->sym_time().
///
/// The task of actually removing the tuple is left to the MPOLSR agent.
///
/// \param e The event which has expired.
///
void
MPOLSR_LinkTupleTimer::expire(Event* e) {
	double now	= CURRENT_TIME;
	
	if (tuple_->time() < now) {
		agent_->rm_link_tuple(tuple_);
		delete tuple_;
		delete this;
	}
	else if (tuple_->sym_time() < now) {
		if (first_time_)
			first_time_ = false;
		else
			agent_->nb_loss(tuple_);
		resched(DELAY(tuple_->time()));
	}
	else
		resched(DELAY(MIN(tuple_->time(), tuple_->sym_time())));
}

///
/// \brief Removes tuple_ if expired. Else the timer is rescheduled to expire at tuple_->time().
///
/// The task of actually removing the tuple is left to the MPOLSR agent.
///
/// \param e The event which has expired.
///
void
MPOLSR_Nb2hopTupleTimer::expire(Event* e) {
	if (tuple_->time() < CURRENT_TIME) {
		agent_->rm_nb2hop_tuple(tuple_);
		delete tuple_;
		delete this;
	}
	else
		resched(DELAY(tuple_->time()));
}

///
/// \brief Removes tuple_ if expired. Else the timer is rescheduled to expire at tuple_->time().
///
/// The task of actually removing the tuple is left to the MPOLSR agent.
///
/// \param e The event which has expired.
///
void
MPOLSR_MprSelTupleTimer::expire(Event* e) {
	if (tuple_->time() < CURRENT_TIME) {
		agent_->rm_mprsel_tuple(tuple_);
		delete tuple_;
		delete this;
	}
	else
		resched(DELAY(tuple_->time()));
}

///
/// \brief Removes tuple_ if expired. Else the timer is rescheduled to expire at tuple_->time().
///
/// The task of actually removing the tuple is left to the MPOLSR agent.
///
/// \param e The event which has expired.
///
void
MPOLSR_TopologyTupleTimer::expire(Event* e) {
	if (tuple_->time() < CURRENT_TIME) {
		agent_->rm_topology_tuple(tuple_);
		delete tuple_;
		delete this;
	}
	else
		resched(DELAY(tuple_->time()));
}

///
/// \brief Removes tuple_ if expired. Else timer is rescheduled to expire at tuple_->time().
/// \warning Actually this is never invoked because there is no support for multiple interfaces.
/// \param e The event which has expired.
///
void
MPOLSR_IfaceAssocTupleTimer::expire(Event* e) {
	if (tuple_->time() < CURRENT_TIME) {
		agent_->rm_ifaceassoc_tuple(tuple_);
		delete tuple_;
		delete this;
	}
	else
		resched(DELAY(tuple_->time()));
}

///
/// \brief Sends a control packet which must bear every message in the MPOLSR agent's buffer.
///
/// The task of actually sending the packet is left to the MPOLSR agent.
///
/// \param e The event which has expired.
///
void
MPOLSR_MsgTimer::expire(Event* e) {
	agent_->send_pkt();
	delete this;
}


/********** MPOLSR class **********/


///
/// \brief Creates necessary timers, binds TCL-available variables and do
/// some more initializations.
/// \param id Identifier for the MPOLSR agent. It will be used as the address
/// of this routing agent.
///
MPOLSR::MPOLSR(nsaddr_t id) :	Agent(PT_MPOLSR),
				hello_timer_(this),
				tc_timer_(this),
				mid_timer_(this) {

	// Enable usage of some of the configuration variables from Tcl.
	//
	// Note: Do NOT change the values of these variables in the constructor
	// after binding them! The desired default values should be set in
	// ns-X.XX/tcl/lib/ns-default.tcl instead.
	bind("willingness_", &willingness_);
	bind("hello_ival_", &hello_ival_);
	bind("tc_ival_", &tc_ival_);
	bind("mid_ival_", &mid_ival_);
	bind_bool("use_mac_", &use_mac_);
	
	// Do some initializations
	ra_addr_	= id;
	pkt_seq_	= MPOLSR_MAX_SEQ_NUM;
	msg_seq_	= MPOLSR_MAX_SEQ_NUM;
	ansn_		= MPOLSR_MAX_SEQ_NUM;

	packet_count_ 	= 0;
}

///
/// \brief	This function is called whenever a packet is received. It identifies
///		the type of the received packet and process it accordingly.
///
/// If it is an %MPOLSR packet then it is processed. In other case, if it is a data packet
/// then it is forwarded.
///
/// \param	p the received packet.
/// \param	h a handler (not used).
///
void
MPOLSR::recv(Packet* p, Handler* h) {
	struct hdr_cmn* ch	= HDR_CMN(p);
	struct hdr_ip* ih	= HDR_IP(p);
	struct hdr_sr* srh	= HDR_SR(p);   //the head for source routing

//	printf ("reciving...\n");
//	for(;;)
//	if(ifq->prq_length()>10)
//	printf("%d \t ", ifq->prq_length());

	nsaddr_t dest = ih->daddr();
	
	if (ih->saddr() == ra_addr()) {
		// If there exists a loop, must drop the packet
		if (ch->num_forwards() > 0) {
			drop(p, DROP_RTR_ROUTE_LOOP);
			return;
		}
		// else if this is a packet I am originating, must add IP header
		else if (ch->num_forwards() == 0){
	//		printf("from the top...No11. %d,%d\n", packet_count_,ih->saddr());
			ch->size() += IP_HDR_LEN;
		//	ch->error() = 0;
			
			
			//check the flag of routing table. If it is out of date, recompute the routing table
			if(m_rtable_.get_flag(dest) == true){
				m_rtable_computation(p);
			}

			//this must be an outgoing packet, it doesn't have a SR header on it
			srh->init();

			//here we must chose one route from the routing table
			m_rtable_t::iterator temp_it = m_rtable_.lookup(ih->daddr());

			//if there is no route, we must drop the packet and return
			if(temp_it == (*m_rtable_.m_rt()).end()){
				debug("%f: Node %d can not forward a packet destined to %d\n",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()),
					MPOLSR::node_id(ih->daddr()));
				drop(p, DROP_RTR_NO_ROUTE);
				return;
			}
			
			//now find a route
			for (int j = 0;j<packet_count_%MAX_ROUTE;j++)
				temp_it++;

			packet_count_++;
			//now we must fill the source route
			sr_addr* temp_addrs;
			temp_addrs = srh->addrs();
			
			MPOLSR_m_rt_entry* m_entry = (*temp_it).second;
			for(int i = 0;i<MAX_SR_LEN;i++){
				*temp_addrs = m_entry->addr_[i];
				temp_addrs++;
			}
			
		}
	}
	
	// If it is an MPOLSR packet, must process it
	if (ch->ptype() == PT_MPOLSR)
		recv_mpolsr(p);
	// Otherwise, must forward the packet (unless TTL has reached zero)
	else {
		ih->ttl_--;
		if (ih->ttl_ == 0) {
			drop(p, DROP_RTR_TTL);
			return;
		}
//		printf("call forward... \n");
//		forward_data(p);
		m_forward_data(p);
	}
}

///
/// \brief Processes an incoming %MPOLSR packet following RFC 3626 specification.
/// \param p received packet.
///
void
MPOLSR::recv_mpolsr(Packet* p) {
	struct hdr_ip* ih	= HDR_IP(p);
	MPOLSR_pkt* op		= PKT_MPOLSR(p);
	
	// All routing messages are sent from and to port RT_PORT,
	// so we check it.
	assert(ih->sport() == RT_PORT);
	assert(ih->dport() == RT_PORT);
	
//	printf("Receiving MPOLSR packets...\n");
	// If the packet contains no messages must be silently discarded.
	// There could exist a message with an empty body, so the size of
	// the packet would be pkt-hdr-size + msg-hdr-size.
	if (op->pkt_len() < MPOLSR_PKT_HDR_SIZE + MPOLSR_MSG_HDR_SIZE) {
		Packet::free(p);
		return;
	}
	
	assert(op->count >= 0 && op->count <= MPOLSR_MAX_MSGS);
	for (int i = 0; i < op->count; i++) {
		MPOLSR_msg& msg = op->msg(i);
		
		// If ttl is less than or equal to zero, or
		// the receiver is the same as the originator,
		// the message must be silently dropped
		if (msg.ttl() <= 0 || msg.orig_addr() == ra_addr())
			continue;
		
		// If the message has been processed it must not be
		// processed again
		bool do_forwarding = true;
		MPOLSR_dup_tuple* duplicated = state_.find_dup_tuple(msg.orig_addr(), msg.msg_seq_num());
		if (duplicated == NULL) {
			// Process the message according to its type
			if (msg.msg_type() == MPOLSR_HELLO_MSG)
				process_hello(msg, ra_addr(), ih->saddr());
			else if (msg.msg_type() == MPOLSR_TC_MSG)
				process_tc(msg, ih->saddr());
			else if (msg.msg_type() == MPOLSR_MID_MSG)
				process_mid(msg, ih->saddr());
			else {
				debug("%f: Node %d can not process MPOLSR packet because does not "
					"implement MPOLSR type (%x)\n",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()),
					msg.msg_type());
			}
		}
		else {
			// If the message has been considered for forwarding, it should
			// not be retransmitted again
			for (addr_list_t::iterator it = duplicated->iface_list().begin();
				it != duplicated->iface_list().end();
				it++) {
				if (*it == ra_addr()) {
					do_forwarding = false;
					break;
				}
			}
		}
			
		if (do_forwarding) {
			// HELLO messages are never forwarded.
			// TC and MID messages are forwarded using the default algorithm.
			// Remaining messages are also forwarded using the default algorithm.
			if (msg.msg_type() != MPOLSR_HELLO_MSG)
				forward_default(p, msg, duplicated, ra_addr());
		}

	}
	
	// After processing all MPOLSR messages, we must recompute routing table,for unipath routing
//	rtable_computation();
	
	//for multipath rouitng, instead of recompute the routing table, just set the flag
	m_rtable_.set_flag(true);
	
	// Release resources
	Packet::free(p);
}

///
/// \brief Computates MPR set of a node following RFC 3626 hints.
///
void
MPOLSR::mpr_computation() {
	// MPR computation should be done for each interface. See section 8.3.1
	// (RFC 3626) for details.
	
	state_.clear_mprset();
//	printf("computing mpr\n");
	
	nbset_t N; nb2hopset_t N2;
	// N is the subset of neighbors of the node, which are
	// neighbor "of the interface I"
	for (nbset_t::iterator it = nbset().begin(); it != nbset().end(); it++)
		if ((*it)->status() == MPOLSR_STATUS_SYM) // I think that we need this check
			N.push_back(*it);
	
	// N2 is the set of 2-hop neighbors reachable from "the interface
	// I", excluding:
	// (i)   the nodes only reachable by members of N with willingness WILL_NEVER
	// (ii)  the node performing the computation
	// (iii) all the symmetric neighbors: the nodes for which there exists a symmetric
	//       link to this node on some interface.
	for (nb2hopset_t::iterator it = nb2hopset().begin(); it != nb2hopset().end(); it++) {
		MPOLSR_nb2hop_tuple* nb2hop_tuple = *it;
		bool ok = true;
		MPOLSR_nb_tuple* nb_tuple = state_.find_sym_nb_tuple(nb2hop_tuple->nb_main_addr());
		if (nb_tuple == NULL)
			ok = false;
		else {
			nb_tuple = state_.find_nb_tuple(nb2hop_tuple->nb_main_addr(), MPOLSR_WILL_NEVER);
			if (nb_tuple != NULL)
				ok = false;
			else {
				nb_tuple = state_.find_sym_nb_tuple(nb2hop_tuple->nb2hop_addr());
				if (nb_tuple != NULL)
					ok = false;
			}
		}

		if (ok)
			N2.push_back(nb2hop_tuple);
	}
	
	// 1. Start with an MPR set made of all members of N with
	// N_willingness equal to WILL_ALWAYS
	for (nbset_t::iterator it = N.begin(); it != N.end(); it++) {
		MPOLSR_nb_tuple* nb_tuple = *it;
		if (nb_tuple->willingness() == MPOLSR_WILL_ALWAYS)
			state_.insert_mpr_addr(nb_tuple->nb_main_addr());
	}
	
	// 2. Calculate D(y), where y is a member of N, for all nodes in N.
	// We will do this later.
	
	// 3. Add to the MPR set those nodes in N, which are the *only*
	// nodes to provide reachability to a node in N2. Remove the
	// nodes from N2 which are now covered by a node in the MPR set.
	mprset_t foundset;
	std::set<nsaddr_t> deleted_addrs;
	for (nb2hopset_t::iterator it = N2.begin(); it != N2.end(); it++) {
		MPOLSR_nb2hop_tuple* nb2hop_tuple1 = *it;
		
		mprset_t::iterator pos = foundset.find(nb2hop_tuple1->nb2hop_addr());
		if (pos != foundset.end())
			continue;
		
		bool found = false;
		for (nbset_t::iterator it2 = N.begin(); it2 != N.end(); it2++) {
			if ((*it2)->nb_main_addr() == nb2hop_tuple1->nb_main_addr()) {
				found = true;
				break;
			}
		}
		if (!found)
			continue;
		
		found = false;
		for (nb2hopset_t::iterator it2 = it + 1; it2 != N2.end(); it2++) {
			MPOLSR_nb2hop_tuple* nb2hop_tuple2 = *it2;
			if (nb2hop_tuple1->nb2hop_addr() == nb2hop_tuple2->nb2hop_addr()) {
				foundset.insert(nb2hop_tuple1->nb2hop_addr());
				found = true;
				break;
			}
		}
		if (!found) {
			state_.insert_mpr_addr(nb2hop_tuple1->nb_main_addr());
			
			for (nb2hopset_t::iterator it2 = it + 1; it2 != N2.end(); it2++) {
				MPOLSR_nb2hop_tuple* nb2hop_tuple2 = *it2;
				if (nb2hop_tuple1->nb_main_addr() == nb2hop_tuple2->nb_main_addr()) {
					deleted_addrs.insert(nb2hop_tuple2->nb2hop_addr());
					it2 = N2.erase(it2);
					it2--;
				}
			}
			it = N2.erase(it);
			it--;
		}
		
		for (std::set<nsaddr_t>::iterator it2 = deleted_addrs.begin();
			it2 != deleted_addrs.end();
			it2++) {
			for (nb2hopset_t::iterator it3 = N2.begin();
				it3 != N2.end();
				it3++) {
				if ((*it3)->nb2hop_addr() == *it2) {
					it3 = N2.erase(it3);
					it3--;
					// I have to reset the external iterator because it
					// may have been invalidated by the latter deletion
					it = N2.begin();
					it--;
				}
			}
		}
		deleted_addrs.clear();
	}
	
	// 4. While there exist nodes in N2 which are not covered by at
	// least one node in the MPR set:
	while (N2.begin() != N2.end()) {
		// 4.1. For each node in N, calculate the reachability, i.e., the
		// number of nodes in N2 which are not yet covered by at
		// least one node in the MPR set, and which are reachable
		// through this 1-hop neighbor
		map<int, std::vector<MPOLSR_nb_tuple*> > reachability;
		set<int> rs;
		for (nbset_t::iterator it = N.begin(); it != N.end(); it++) {
			MPOLSR_nb_tuple* nb_tuple = *it;
			int r = 0;
			for (nb2hopset_t::iterator it2 = N2.begin(); it2 != N2.end(); it2++) {
				MPOLSR_nb2hop_tuple* nb2hop_tuple = *it2;
				if (nb_tuple->nb_main_addr() == nb2hop_tuple->nb_main_addr())
					r++;
			}
			rs.insert(r);
			reachability[r].push_back(nb_tuple);
		}
		
		// 4.2. Select as a MPR the node with highest N_willingness among
		// the nodes in N with non-zero reachability. In case of
		// multiple choice select the node which provides
		// reachability to the maximum number of nodes in N2. In
		// case of multiple nodes providing the same amount of
		// reachability, select the node as MPR whose D(y) is
		// greater. Remove the nodes from N2 which are now covered
		// by a node in the MPR set.
		MPOLSR_nb_tuple* max = NULL;
		int max_r = 0;
		for (set<int>::iterator it = rs.begin(); it != rs.end(); it++) {
			int r = *it;
			if (r > 0) {
				for (std::vector<MPOLSR_nb_tuple*>::iterator it2 = reachability[r].begin();
					it2 != reachability[r].end();
					it2++) {
					MPOLSR_nb_tuple* nb_tuple = *it2;
					if (max == NULL || nb_tuple->willingness() > max->willingness()) {
						max = nb_tuple;
						max_r = r;
					}
					else if (nb_tuple->willingness() == max->willingness()) {
						if (r > max_r) {
							max = nb_tuple;
							max_r = r;
						}
						else if (r == max_r) {
							if (degree(nb_tuple) > degree(max)) {
								max = nb_tuple;
								max_r = r;
							}
						}
					}
				}
			}
		}
		if (max != NULL) {
			state_.insert_mpr_addr(max->nb_main_addr());
			std::set<nsaddr_t> nb2hop_addrs;
			for (nb2hopset_t::iterator it = N2.begin(); it != N2.end(); it++) {
				MPOLSR_nb2hop_tuple* nb2hop_tuple = *it;
				if (nb2hop_tuple->nb_main_addr() == max->nb_main_addr()) {
					nb2hop_addrs.insert(nb2hop_tuple->nb2hop_addr());
					it = N2.erase(it);
					it--;
				}
			}
			for (nb2hopset_t::iterator it = N2.begin(); it != N2.end(); it++) {
				MPOLSR_nb2hop_tuple* nb2hop_tuple = *it;
				std::set<nsaddr_t>::iterator it2 =
					nb2hop_addrs.find(nb2hop_tuple->nb2hop_addr());
				if (it2 != nb2hop_addrs.end()) {
					it = N2.erase(it);
					it--;
				}
			}
		}
	}
}

///
/// \brief Creates the routing table of the node following RFC 3626 hints.
///
void
MPOLSR::rtable_computation() {
	// 1. All the entries from the routing table are removed.
	rtable_.clear();
	
	// 2. The new routing entries are added starting with the
	// symmetric neighbors (h=1) as the destination nodes.
	for (nbset_t::iterator it = nbset().begin(); it != nbset().end(); it++) {
		MPOLSR_nb_tuple* nb_tuple = *it;
		if (nb_tuple->status() == MPOLSR_STATUS_SYM) {
			bool nb_main_addr = false;
			MPOLSR_link_tuple* lt = NULL;
			for (linkset_t::iterator it2 = linkset().begin(); it2 != linkset().end(); it2++) {
				MPOLSR_link_tuple* link_tuple = *it2;
				if (get_main_addr(link_tuple->nb_iface_addr()) == nb_tuple->nb_main_addr() && link_tuple->time() >= CURRENT_TIME) {
					lt = link_tuple;
					rtable_.add_entry(link_tuple->nb_iface_addr(),
							link_tuple->nb_iface_addr(),
							link_tuple->local_iface_addr(),
							1);
					if (link_tuple->nb_iface_addr() == nb_tuple->nb_main_addr())
						nb_main_addr = true;
				}
			}
			if (!nb_main_addr && lt != NULL) {
				rtable_.add_entry(nb_tuple->nb_main_addr(),
						lt->nb_iface_addr(),
						lt->local_iface_addr(),
						1);
			}
		}
	}
	
	// N2 is the set of 2-hop neighbors reachable from this node, excluding:
	// (i)   the nodes only reachable by members of N with willingness WILL_NEVER
	// (ii)  the node performing the computation
	// (iii) all the symmetric neighbors: the nodes for which there exists a symmetric
	//       link to this node on some interface.
	for (nb2hopset_t::iterator it = nb2hopset().begin(); it != nb2hopset().end(); it++) {
		MPOLSR_nb2hop_tuple* nb2hop_tuple = *it;
		bool ok = true;
		MPOLSR_nb_tuple* nb_tuple = state_.find_sym_nb_tuple(nb2hop_tuple->nb_main_addr());
		if (nb_tuple == NULL)
			ok = false;
		else {
			nb_tuple = state_.find_nb_tuple(nb2hop_tuple->nb_main_addr(), MPOLSR_WILL_NEVER);
			if (nb_tuple != NULL)
				ok = false;
			else {
				nb_tuple = state_.find_sym_nb_tuple(nb2hop_tuple->nb2hop_addr());
				if (nb_tuple != NULL)
					ok = false;
			}
		}

		// 3. For each node in N2 create a new entry in the routing table
		if (ok) {
			MPOLSR_rt_entry* entry = rtable_.lookup(nb2hop_tuple->nb_main_addr());
			assert(entry != NULL);
			rtable_.add_entry(nb2hop_tuple->nb2hop_addr(),
					entry->next_addr(),
					entry->iface_addr(),
					2);
		}
	}
	
	for (u_int32_t h = 2; ; h++) {
		bool added = false;
		
		// 4.1. For each topology entry in the topology table, if its
		// T_dest_addr does not correspond to R_dest_addr of any
		// route entry in the routing table AND its T_last_addr
		// corresponds to R_dest_addr of a route entry whose R_dist
		// is equal to h, then a new route entry MUST be recorded in
		// the routing table (if it does not already exist)
		for (topologyset_t::iterator it = topologyset().begin();
			it != topologyset().end();
			it++) {
			//printf("computing tc set\n");
			MPOLSR_topology_tuple* topology_tuple = *it;
			MPOLSR_rt_entry* entry1 = rtable_.lookup(topology_tuple->dest_addr());
			MPOLSR_rt_entry* entry2 = rtable_.lookup(topology_tuple->last_addr());
			if (entry1 == NULL && entry2 != NULL && entry2->dist() == h) {
				rtable_.add_entry(topology_tuple->dest_addr(),
						entry2->next_addr(),
						entry2->iface_addr(),
						h+1);
				added = true;
			}
		}
		
		// 5. For each entry in the multiple interface association base
		// where there exists a routing entry such that:
		//	R_dest_addr  == I_main_addr  (of the multiple interface association entry)
		// AND there is no routing entry such that:
		//	R_dest_addr  == I_iface_addr
		// then a route entry is created in the routing table
		for (ifaceassocset_t::iterator it = ifaceassocset().begin();
			it != ifaceassocset().end();
			it++) {
			MPOLSR_iface_assoc_tuple* tuple = *it;
			MPOLSR_rt_entry* entry1 = rtable_.lookup(tuple->main_addr());
			MPOLSR_rt_entry* entry2 = rtable_.lookup(tuple->iface_addr());
			if (entry1 != NULL && entry2 == NULL) {
				rtable_.add_entry(tuple->iface_addr(),
						entry1->next_addr(),
						entry1->iface_addr(),
						entry1->dist());
				added = true;
			}
		}

		if (!added)
			break;
	}
}

void 
MPOLSR::m_rtable_computation(Packet* p){
		struct hdr_cmn* ch	= HDR_CMN(p);
		struct hdr_ip* ih	= HDR_IP(p);
		struct hdr_sr* srh	= HDR_SR(p);   //the head for source routing
		
		struct sr_addr addrs_[MAX_SR_LEN];
		double start_time, end_time;
		int sr_count_ = 0;
		bool type_flag = false;
	
		printf("\n packet ID:%d",ch->uid_);
			
		map<nsaddr_t,Dijkstra_node*>::iterator n_it,n_it_d;
		
		//destination
		nsaddr_t dest = ih->daddr();
		//source
		nsaddr_t source = ra_addr();
		
		//clear the old entries
		m_rtable_.rm_entry(dest);
	
		//gather the topology info: topology set, nb set, 2nbset
		/*			MPOLSR_topology_tuple* topology_tuple = new MPOLSR_topology_tuple;
				topology_tuple->dest_addr() = addr; 
				topology_tuple->last_addr() = msg.orig_addr();
				topology_tuple->seq()		= tc.ansn();
				topology_tuple->time()		= now + MPOLSR::emf_to_seconds(msg.vtime());
				topology_tuple->weight()	= 1;//initialize the weight
				add_topology_tuple(topology_tuple);
		*/
	
		start_time = CURRENT_TIME;
		topologyset_t	n_topologyset_; 
		MPOLSR_topology_tuple* tt;
		for (topologyset_t::iterator it = topologyset().begin(); it != topologyset().end(); it++){
			tt = new MPOLSR_topology_tuple;
			tt->dest_addr() = (*it)->dest_addr_;
			tt->last_addr() = (*it)->last_addr_;
			tt->weight() = 1;	
			if(tt->dest_addr()==ra_addr()||tt->last_addr()==ra_addr()){
				delete tt;
				continue;
			}
			n_topologyset_.push_back(tt);
		}
		for (nbset_t::iterator it = nbset().begin();it!=nbset().end();it++){
			tt = new MPOLSR_topology_tuple;
			tt->dest_addr() = (*it)->nb_main_addr_;
			tt->last_addr() = ra_addr();
			tt->weight() = 1;
			n_topologyset_.push_back(tt);
			//printf("%d, %d|\t", tt->last_addr(),tt->dest_addr());
		}
		for(nb2hopset_t::iterator it = nb2hopset().begin();it!=nb2hopset().end();it++){
			tt = new MPOLSR_topology_tuple;
			tt->dest_addr() = (*it)->nb2hop_addr_;
			tt->last_addr() = (*it)->nb_main_addr_;
			tt->weight() = 1;
			if(tt->dest_addr()==ra_addr()||tt->last_addr()==ra_addr()){
				delete tt;
				continue;
			}
			n_topologyset_.push_back(tt);
		}
		
		//get the node map
		map<nsaddr_t, Dijkstra_node*> node_map_;
	
		//add the node itself
		pair<map<nsaddr_t,Dijkstra_node*>::iterator,bool> ret;
		Dijkstra_node* node = new Dijkstra_node;
		(*node).addr_ = ra_addr();
		(*node).weight_ = MAX_WEIGHT;
		(*node).node_type = 0;
		ret = node_map_.insert(pair<nsaddr_t,Dijkstra_node*>((*node).addr_,node));
		
		for (topologyset_t::iterator it = n_topologyset_.begin(); it != n_topologyset_.end(); it++){
			//unvisited_.insert(pair<nsaddr_t,float>((*it)->dest_addr_,MAX_WEIGHT));
			//	unvisited_.insert(pair<nsaddr_t,float>((*it)->last_addr_,MAX_WEIGHT));
			pair<map<nsaddr_t,Dijkstra_node*>::iterator,bool> ret;
			
			Dijkstra_node* node = new Dijkstra_node;
			(*node).addr_ = (*it)->last_addr_;
			(*node).weight_ = MAX_WEIGHT;
			(*node).node_type = 0;
					ret = node_map_.insert(pair<nsaddr_t,Dijkstra_node*>((*node).addr_,node));
			if (ret.second == false)	
				delete node;
			
			
			node = new Dijkstra_node;
			(*node).addr_ = (*it)->dest_addr_;
			(*node).weight_ = MAX_WEIGHT;
			(*node).node_type = 0;
					ret = node_map_.insert(pair<nsaddr_t,Dijkstra_node*>((*node).addr_,node));
			if(ret.second == false)
				delete node;
	
			(**it).weight_ = 1;
			//node_set_.insert(node);
		}
	/*
		//for test print the node set
		int test0 = 0;
		for(n_it = node_map_.begin();n_it != node_map_.end();n_it++){
			printf("%d\t",(*n_it).first);
			//test0++;
		}*/
		printf("\n");
		/*
		//	0 for T (temporary) type, 1 for P type
		//initialize set the source to P type
		n_it = node_map_.find(source);
		(*(*n_it).second).node_type = P_TYPE;
		(*(*n_it).second).weight_ = 0;
		*/
		Dijkstra_node *node_n, *node_t;
		
		for (int i = 0;i<MAX_ROUTE;i++){
			n_it = node_map_.find(source);
			(*(*n_it).second).node_type = P_TYPE;
			(*(*n_it).second).weight_ = 0;
			for(;;){
				//1. renew all the weight_ of T type nodes
				
				for(topologyset_t::iterator it = n_topologyset_.begin(); it != n_topologyset_.end(); it++){
					for(n_it = node_map_.begin();n_it != node_map_.end();n_it++){
				/*		Dijkstra_node node_s, node_d;
						node_s = *(*n_it).second;
						//this part still need to be modified for uni-path protocol
						if((node_s.node_type == P_TYPE) && ((node_s.addr_ == (*it)->last_addr_)||(node_s.addr_ == (*it)->dest_addr_))){
							if (node_s.addr_ == (*it)->last_addr_)
								n_it_d = node_map_.find((*it)->dest_addr_);
							else
								n_it_d = node_map_.find((*it)->last_addr_);
							
							node_d = *(*n_it_d).second;
							if (node_s.weight_ + (*it)->weight_ < node_d.weight_){
								node_d.weight_ = node_s.weight_ + (*it)->weight_;
								node_d.pre_addr_ = node_s.addr_;
							}
							
						}*/
						Dijkstra_node *node_s, *node_d;
						node_s = (*n_it).second;
						//this part still need to be modified for uni-direction protocol
						if(((*node_s).node_type == P_TYPE) && (((*node_s).addr_ == (*it)->last_addr_)||((*node_s).addr_ == (*it)->dest_addr_))){
							if ((*node_s).addr_ == (*it)->last_addr_)
								n_it_d = node_map_.find((*it)->dest_addr_);
							else
								n_it_d = node_map_.find((*it)->last_addr_);
							
							node_d = (*n_it_d).second;
							if ((*node_s).weight_ + (*it)->weight_ < (*node_d).weight_){
								(*node_d).weight_ = (*node_s).weight_ + (*it)->weight_;
								(*node_d).pre_addr_ = (*node_s).addr_;
							}
						}
						
					}
				}
				
				//2. find the T type node with the min weight_, and set it to P type
				//Dijkstra_node node_n, *node_t;
				//n_it = node_map_.begin();
				//node_t = (*n_it).second;
				int counter = 0;
				node_t = (*node_map_.begin()).second; //intitilize
				for(n_it = node_map_.begin();n_it != node_map_.end(); n_it++){
					node_n = (*n_it).second;
					if((*node_n).node_type == T_TYPE){
						if (counter == 0) //the first rotation
							node_t = node_n;
						if ((*node_t).weight_ > (*node_n).weight_){
							node_t = node_n;
						}
						counter++;
					}
				}
	
				//the weight is MAX, no route
				if((*node_t).weight_ >= MAX_WEIGHT){
					printf("\nthere is no route found from %d to %d!!", source,dest);
					//m_rtable_.set_flag(dest, false);
					type_flag = false;
					return;
					break;
				}
				
				//set to P_TYPE
				(*node_t).node_type = P_TYPE;
	/*
				//now renew the weight of the topology tuple for multipath algorithm
				for(topologyset_t::iterator it = topologyset().begin(); it != topologyset().end(); it++){
					if((*it)->last_addr_ == (*node_t).addr_){
						(*it)->weight_ = tuple_weight((*it)->weight_);
						printf("%f %d-> %d\n",(*it)->weight_, (*node_t).addr_, (*it)->dest_addr());
					}
				}*/
				
		
				
				//3. found the route to the destination
				if((*node_t).addr_ == dest){
					printf("\nI got one!");
					type_flag = true;
					break;
				}
				
				type_flag = false;
				for(n_it = node_map_.begin();n_it != node_map_.end(); n_it++){
					node_n = (*n_it).second;
					if((*node_n).node_type == T_TYPE)
						type_flag = true;
					//(*node_n).node_type = T_TYPE;
					//(*node_n).weight_ = 0;
				}
				if(type_flag == false){
					printf("\nthere is no route found from %d to %d!!", source,dest);
					
					break;
				}
				
			}
	
			if (type_flag == false)
				break;
			//construct the routing entry
			MPOLSR_m_rt_entry* m_rt_entry = new MPOLSR_m_rt_entry;
			std::vector<sr_addr> addr_stack;
			//while((*node_t).addr_ != source)
			do	{
				sr_addr* sr_ = new sr_addr;
				(*sr_).addr = (*node_t).addr_;
				addr_stack.push_back(*sr_);
	
				//now renew the weight of the topology tuple for multipath algorithm
				for(topologyset_t::iterator it = n_topologyset_.begin(); it != n_topologyset_.end(); it++){
					if((*it)->last_addr_ == (*node_t).addr_){
					//	printf("%f %d-> %d\t",(*it)->weight_, (*node_t).addr_, (*it)->dest_addr());
						(*it)->weight_ = tuple_weight((*it)->weight_);
						//(*it)->weight_ = (*it)->weight_*2;
			
					}
				}
				
				node_t = node_map_.find((*node_t).pre_addr_)->second;
			} while((*node_t).addr_ != source);
	
				/*		for(topologyset_t::iterator tit = topologyset().begin(); tit != topologyset().end(); tit++){
					printf("%d--->%d, weight:%f\n", (*tit)->last_addr_, (*tit)->dest_addr_, (*tit)->weight_);
				}*/
			//add itself
			sr_addr* sr_ = new sr_addr;
			(*sr_).addr = ra_addr();
			addr_stack.push_back(*sr_);
			
			int i = 0;
			printf("from %d to %d:\t",ra_addr(),dest);
			while(addr_stack.empty() == false){
				(*m_rt_entry).addr_[i].addr = addr_stack.back().addr;
				printf("%d->\t",addr_stack.back().addr);
				addr_stack.pop_back();
				i++;
			}
			
			//add the entry to routing table
			m_rtable_.add_entry(m_rt_entry,dest);
	
			
	
			//reset all the nodes for next rotation
			for(n_it = node_map_.begin();n_it != node_map_.end(); n_it++){
					node_n = (*n_it).second;
				(*node_n).node_type = T_TYPE;
				(*node_n).weight_ = MAX_WEIGHT;
			}
		}
		//finish the computation, set the flag
		m_rtable_.set_flag(dest, false);
		end_time = CURRENT_TIME; 
	
	//	delete *n_topologyset_;

	
}
///
/// \brief Processes a HELLO message following RFC 3626 specification.
///
/// Link sensing and population of the Neighbor Set, 2-hop Neighbor Set and MPR
/// Selector Set are performed.
///
/// \param msg the %MPOLSR message which contains the HELLO message.
/// \param receiver_iface the address of the interface where the message was received from.
/// \param sender_iface the address of the interface where the message was sent from.
///
void
MPOLSR::process_hello(MPOLSR_msg& msg, nsaddr_t receiver_iface, nsaddr_t sender_iface) {
	//printf("processing hello...\n");
	assert(msg.msg_type() == MPOLSR_HELLO_MSG);

        link_sensing(msg, receiver_iface, sender_iface);
	populate_nbset(msg);
	populate_nb2hopset(msg);
	mpr_computation();
	populate_mprselset(msg);
}

///
/// \brief Processes a TC message following RFC 3626 specification.
///
/// The Topology Set is updated (if needed) with the information of
/// the received TC message.
///
/// \param msg the %MPOLSR message which contains the TC message.
/// \param sender_iface the address of the interface where the message was sent from.
///
void
MPOLSR::process_tc(MPOLSR_msg& msg, nsaddr_t sender_iface) {
	assert(msg.msg_type() == MPOLSR_TC_MSG);
	double now	= CURRENT_TIME;
	MPOLSR_tc& tc	= msg.tc();
	
//	printf("processing tc...\n");
	
	// 1. If the sender interface of this message is not in the symmetric
	// 1-hop neighborhood of this node, the message MUST be discarded.
	MPOLSR_link_tuple* link_tuple = state_.find_sym_link_tuple(sender_iface, now);
	if (link_tuple == NULL)
		return;
	
	// 2. If there exist some tuple in the topology set where:
	// 	T_last_addr == originator address AND
	// 	T_seq       >  ANSN,
	// then further processing of this TC message MUST NOT be
	// performed.
	MPOLSR_topology_tuple* topology_tuple =
		state_.find_newer_topology_tuple(msg.orig_addr(), tc.ansn());
	if (topology_tuple != NULL)
		return;
	
	// 3. All tuples in the topology set where:
	//	T_last_addr == originator address AND
	//	T_seq       <  ANSN
	// MUST be removed from the topology set.
	state_.erase_older_topology_tuples(msg.orig_addr(), tc.ansn());

	// 4. For each of the advertised neighbor main address received in
	// the TC message:
	for (int i = 0; i < tc.count; i++) {
		assert(i >= 0 && i < MPOLSR_MAX_ADDRS);
		nsaddr_t addr = tc.nb_main_addr(i);
		// 4.1. If there exist some tuple in the topology set where:
		// 	T_dest_addr == advertised neighbor main address, AND
		// 	T_last_addr == originator address,
		// then the holding time of that tuple MUST be set to:
		// 	T_time      =  current time + validity time.
		MPOLSR_topology_tuple* topology_tuple =
			state_.find_topology_tuple(addr, msg.orig_addr());
		if (topology_tuple != NULL)
			topology_tuple->time() = now + MPOLSR::emf_to_seconds(msg.vtime());
		// 4.2. Otherwise, a new tuple MUST be recorded in the topology
		// set where:
		//	T_dest_addr = advertised neighbor main address,
		//	T_last_addr = originator address,
		//	T_seq       = ANSN,
		//	T_time      = current time + validity time.
		else {
			MPOLSR_topology_tuple* topology_tuple = new MPOLSR_topology_tuple;
			topology_tuple->dest_addr()	= addr; 
			topology_tuple->last_addr()	= msg.orig_addr();
			topology_tuple->seq()		= tc.ansn();
			topology_tuple->time()		= now + MPOLSR::emf_to_seconds(msg.vtime());
			topology_tuple->weight()	= 1;//initialize the weight
			add_topology_tuple(topology_tuple);
			// Schedules topology tuple deletion
			MPOLSR_TopologyTupleTimer* topology_timer =
				new MPOLSR_TopologyTupleTimer(this, topology_tuple);
			topology_timer->resched(DELAY(topology_tuple->time()));
		}
	}
}

///
/// \brief Processes a MID message following RFC 3626 specification.
///
/// The Interface Association Set is updated (if needed) with the information
/// of the received MID message.
///
/// \param msg the %MPOLSR message which contains the MID message.
/// \param sender_iface the address of the interface where the message was sent from.
///
void
MPOLSR::process_mid(MPOLSR_msg& msg, nsaddr_t sender_iface) {
	assert(msg.msg_type() == MPOLSR_MID_MSG);
	double now	= CURRENT_TIME;
	MPOLSR_mid& mid	= msg.mid();
	
	// 1. If the sender interface of this message is not in the symmetric
	// 1-hop neighborhood of this node, the message MUST be discarded.
	MPOLSR_link_tuple* link_tuple = state_.find_sym_link_tuple(sender_iface, now);
	if (link_tuple == NULL)
		return;
	
	// 2. For each interface address listed in the MID message
	for (int i = 0; i < mid.count; i++) {
		bool updated = false;
		for (ifaceassocset_t::iterator it = ifaceassocset().begin();
			it != ifaceassocset().end();
			it++) {
			MPOLSR_iface_assoc_tuple* tuple = *it;
			if (tuple->iface_addr() == mid.iface_addr(i)
				&& tuple->main_addr() == msg.orig_addr()) {
				tuple->time()	= now + MPOLSR::emf_to_seconds(msg.vtime());
				updated		= true;
			}			
		}
		if (!updated) {
			MPOLSR_iface_assoc_tuple* tuple	= new MPOLSR_iface_assoc_tuple;
			tuple->iface_addr()		= msg.mid().iface_addr(i);
			tuple->main_addr()		= msg.orig_addr();
			tuple->time()			= now + MPOLSR::emf_to_seconds(msg.vtime());
			add_ifaceassoc_tuple(tuple);
			// Schedules iface association tuple deletion
			MPOLSR_IfaceAssocTupleTimer* ifaceassoc_timer =
				new MPOLSR_IfaceAssocTupleTimer(this, tuple);
			ifaceassoc_timer->resched(DELAY(tuple->time()));
		}
	}
}

///
/// \brief MPOLSR's default forwarding algorithm.
///
/// See RFC 3626 for details.
///
/// \param p the %MPOLSR packet which has been received.
/// \param msg the %MPOLSR message which must be forwarded.
/// \param dup_tuple NULL if the message has never been considered for forwarding,
/// or a duplicate tuple in other case.
/// \param local_iface the address of the interface where the message was received from.
///
void
MPOLSR::forward_default(Packet* p, MPOLSR_msg& msg, MPOLSR_dup_tuple* dup_tuple, nsaddr_t local_iface) {
	double now		= CURRENT_TIME;
	struct hdr_ip* ih	= HDR_IP(p);
	
	// If the sender interface address is not in the symmetric
	// 1-hop neighborhood the message must not be forwarded
	MPOLSR_link_tuple* link_tuple = state_.find_sym_link_tuple(ih->saddr(), now);
	if (link_tuple == NULL)
		return;

	// If the message has already been considered for forwarding,
	// it must not be retransmitted again
	if (dup_tuple != NULL && dup_tuple->retransmitted()) {
		debug("%f: Node %d does not forward a message received"
			" from %d because it is duplicated\n",
			CURRENT_TIME,
			MPOLSR::node_id(ra_addr()),
			MPOLSR::node_id(dup_tuple->addr()));
		return;
	}
	
	// If the sender interface address is an interface address
	// of a MPR selector of this node and ttl is greater than 1,
	// the message must be retransmitted
	bool retransmitted = false;
	if (msg.ttl() > 1) {
		MPOLSR_mprsel_tuple* mprsel_tuple =
			state_.find_mprsel_tuple(get_main_addr(ih->saddr()));
		if (mprsel_tuple != NULL) {
			MPOLSR_msg& new_msg = msg;
			new_msg.ttl()--;
			new_msg.hop_count()++;
			// We have to introduce a random delay to avoid
			// synchronization with neighbors.
			enque_msg(new_msg, JITTER);
			retransmitted = true;
		}
	}
	
	// Update duplicate tuple...
	if (dup_tuple != NULL) {
		dup_tuple->time()		= now + MPOLSR_DUP_HOLD_TIME;
		dup_tuple->retransmitted()	= retransmitted;
		dup_tuple->iface_list().push_back(local_iface);
	}
	// ...or create a new one
	else {
		MPOLSR_dup_tuple* new_dup = new MPOLSR_dup_tuple;
		new_dup->addr()			= msg.orig_addr();
		new_dup->seq_num()		= msg.msg_seq_num();
		new_dup->time()			= now + MPOLSR_DUP_HOLD_TIME;
		new_dup->retransmitted()	= retransmitted;
		new_dup->iface_list().push_back(local_iface);
		add_dup_tuple(new_dup);
		// Schedules dup tuple deletion
		MPOLSR_DupTupleTimer* dup_timer =
			new MPOLSR_DupTupleTimer(this, new_dup);
		dup_timer->resched(DELAY(new_dup->time()));
	}
}

///
/// \brief Forwards a data packet to the appropiate next hop indicated by the routing table.
///
/// \param p the packet which must be forwarded.
///
void
MPOLSR::forward_data(Packet* p) {
	struct hdr_cmn* ch	= HDR_CMN(p);
	struct hdr_ip* ih	= HDR_IP(p);
	printf("forwarding data..\n");

	if (ch->direction() == hdr_cmn::UP &&
		((u_int32_t)ih->daddr() == IP_BROADCAST || ih->daddr() == ra_addr())) {
		dmux_->recv(p, 0);
		return;
	}
	else {
		ch->direction()	= hdr_cmn::DOWN;
		ch->addr_type()	= NS_AF_INET;
		if ((u_int32_t)ih->daddr() == IP_BROADCAST)
			ch->next_hop()	= IP_BROADCAST;
		else {
			MPOLSR_rt_entry* entry = rtable_.lookup(ih->daddr());
			if (entry == NULL) {
				debug("%f: Node %d can not forward a packet destined to %d\n",
					CURRENT_TIME,
					MPOLSR::node_id(ra_addr()),
					MPOLSR::node_id(ih->daddr()));
				drop(p, DROP_RTR_NO_ROUTE);
				return;
			}
			else {
				entry = rtable_.find_send_entry(entry);
				assert(entry != NULL);
				ch->next_hop() = entry->next_addr();
				if (USE_MAC) {
					ch->xmit_failure_	= mpolsr_mac_failed_callback;
					ch->xmit_failure_data_	= (void*)this;
				}
			}
		}

		Scheduler::instance().schedule(target_, p, 0.0);
		//target_->recv(p);
	}
}

///
///\brief forward a data packet for multipath routing
///
void
MPOLSR::m_forward_data(Packet* p){
	struct hdr_cmn* ch	= HDR_CMN(p);
	struct hdr_ip* ih	= HDR_IP(p);
	struct hdr_sr* srh = HDR_SR(p);

	struct sr_addr* local_sr;
	int i;
	bool flag = false;
//	ch->uid_ = 0;

	if (ch->direction() == hdr_cmn::UP &&
		((u_int32_t)ih->daddr() == IP_BROADCAST || ih->daddr() == ra_addr())) {
		dmux_->recv(p, 0);
		return;
	}
	else{
		ch->direction()	= hdr_cmn::DOWN;
		ch->addr_type()	= NS_AF_INET;
		if ((u_int32_t)ih->daddr() == IP_BROADCAST)
			ch->next_hop()	= IP_BROADCAST;
		else{
  			printf("\nQueue_length:\t%f\t%d\t%d\t%d", CURRENT_TIME, ch->uid(),ra_addr(), ifq->prq_length());			
			local_sr = srh->addrs();
			for(i = 0;i<MAX_SR_LEN;i++,local_sr++){
				if((*local_sr).addr== ra_addr()){
					local_sr++;
					break;
				}
			}	
			ch->next_hop() = (*local_sr).addr;

			//check the neighbor
			for(nbset_t::iterator it = nbset().begin();it!=nbset().end();it++){
				if((*it)->nb_main_addr_==(*local_sr).addr){
					flag = true;
					break;
				}
			}
			if (flag == false){
				printf("\n%d has no neighbor %d from %d to %d.",ra_addr(),ch->next_hop(),  ih->saddr(),ih->daddr()); 
		//		ch->xmit_reason_ = 1;

		
				resend_data(p);
				return;
			}

			
	//		printf("\nforward from %d to %d",ra_addr(),ch->next_hop());
			if (USE_MAC) {
				ch->xmit_failure_	= mpolsr_mac_failed_callback;
				ch->xmit_failure_data_	= (void*)this;
			}
			//srh.addrs_;
			
		}
	}
	

	Scheduler::instance().schedule(target_, p, 0.0);
	
}

void MPOLSR::resend_data(Packet* p){
	struct hdr_cmn* ch	= HDR_CMN(p);
	struct hdr_ip* ih	= HDR_IP(p);
	struct hdr_sr* srh	= HDR_SR(p);   //the head for source routing

	nsaddr_t source = ra_addr();
	
	nsaddr_t dest = ih->daddr();
	//change the source address
	ih->saddr() = source;
	printf("\nrecomputing...");
	if(m_rtable_.get_flag(dest) == true){
		m_rtable_computation(p);
	}

	//here we must chose one route from the routing table
	m_rtable_t::iterator temp_it = m_rtable_.lookup(ih->daddr());

	//if there is no route, we must drop the packet and return
	if(temp_it == (*m_rtable_.m_rt()).end()){
		debug("%f: Node %d can not forward a packet destined to %d\n",
			CURRENT_TIME,
			MPOLSR::node_id(ra_addr()),
			MPOLSR::node_id(ih->daddr()));
		drop(p, DROP_RTR_NO_ROUTE);
		return;
	}
			
	//now find a route
	for (int j = 0;j<packet_count_%MAX_ROUTE;j++)
		temp_it++;

		packet_count_++;
		//now we must fill the source route
		sr_addr* temp_addrs;
		temp_addrs = srh->addrs();
			
		MPOLSR_m_rt_entry* m_entry = (*temp_it).second;
		for(int i = 0;i<MAX_SR_LEN;i++){
			*temp_addrs = m_entry->addr_[i];
			temp_addrs++;
		}	

	ih->ttl_--;
	if (ih->ttl_ == 0) {
		drop(p, DROP_RTR_TTL);
		return;
	}
//		printf("call forward... \n");
//		forward_data(p);
	m_forward_data(p);
}

///
/// \brief Enques an %MPOLSR message which will be sent with a delay of (0, delay].
///
/// This buffering system is used in order to piggyback several %MPOLSR messages in
/// a same %MPOLSR packet.
///
/// \param msg the %MPOLSR message which must be sent.
/// \param delay maximum delay the %MPOLSR message is going to be buffered.
///
void
MPOLSR::enque_msg(MPOLSR_msg& msg, double delay) {
	assert(delay >= 0);
	
	msgs_.push_back(msg);
	MPOLSR_MsgTimer* timer = new MPOLSR_MsgTimer(this);
	timer->resched(delay);
}

///
/// \brief Creates as many %MPOLSR packets as needed in order to send all buffered
/// %MPOLSR messages.
///
/// Maximum number of messages which can be contained in an %MPOLSR packet is
/// dictated by MPOLSR_MAX_MSGS constant.
///
void
MPOLSR::send_pkt() {
	int num_msgs = msgs_.size();
	if (num_msgs == 0)
		return;
//	printf("sending pkt...\n");
	// Calculates the number of needed packets
	int num_pkts = (num_msgs%MPOLSR_MAX_MSGS == 0) ? num_msgs/MPOLSR_MAX_MSGS :
		(num_msgs/MPOLSR_MAX_MSGS + 1);
	
	for (int i = 0; i < num_pkts; i++) {
		Packet* p		= allocpkt();
		struct hdr_cmn* ch	= HDR_CMN(p);
		struct hdr_ip* ih	= HDR_IP(p);
		MPOLSR_pkt* op		= PKT_MPOLSR(p);
		
		op->pkt_len()		= MPOLSR_PKT_HDR_SIZE;
		op->pkt_seq_num()	= pkt_seq();
	
		int j = 0;
		for (std::vector<MPOLSR_msg>::iterator it = msgs_.begin(); it != msgs_.end(); it++) {
			if (j == MPOLSR_MAX_MSGS)
				break;
			
			op->pkt_body_[j++]	= *it;
			op->count		= j;
			op->pkt_len()		+= (*it).size();
			
			it = msgs_.erase(it);
			it--;
		}
	
		ch->ptype()		= PT_MPOLSR;
		ch->direction()		= hdr_cmn::DOWN;
		ch->size()		= IP_HDR_LEN + UDP_HDR_LEN + op->pkt_len();
		ch->error()		= 0;
		ch->next_hop()		= IP_BROADCAST;
		ch->addr_type()		= NS_AF_INET;
		if (USE_MAC) {
			ch->xmit_failure_	= mpolsr_mac_failed_callback;
			ch->xmit_failure_data_	= (void*)this;
		}

		ih->saddr()	= ra_addr();
		ih->daddr()	= IP_BROADCAST;
		ih->sport()	= RT_PORT;
		ih->dport()	= RT_PORT;
		ih->ttl()	= IP_DEF_TTL;
		
		Scheduler::instance().schedule(target_, p, 0.0);
	}
}

///
/// \brief Creates a new %MPOLSR HELLO message which is buffered to be sent later on.
///
void
MPOLSR::send_hello() {
	MPOLSR_msg msg;
//	printf("sending hello...\n");
	double now		= CURRENT_TIME;
	msg.msg_type()		= MPOLSR_HELLO_MSG;
	msg.vtime()		= MPOLSR::seconds_to_emf(MPOLSR_NEIGHB_HOLD_TIME);
	msg.orig_addr()		= ra_addr();
	msg.ttl()		= 1;
	msg.hop_count()		= 0;
	msg.msg_seq_num()	= msg_seq();
	
	msg.hello().reserved()		= 0;
	msg.hello().htime()		= MPOLSR::seconds_to_emf(hello_ival());
	msg.hello().willingness()	= willingness();
	msg.hello().count		= 0;
	
	map<u_int8_t, int> linkcodes_count;
	for (linkset_t::iterator it = linkset().begin(); it != linkset().end(); it++) {
		MPOLSR_link_tuple* link_tuple = *it;
		if (link_tuple->local_iface_addr() == ra_addr() && link_tuple->time() >= now) {
			u_int8_t link_type, nb_type, link_code;
			
			// Establishes link type
			if (USE_MAC&& link_tuple->lost_time() >= now)
				link_type = MPOLSR_LOST_LINK;
			else if (link_tuple->sym_time() >= now)
				link_type = MPOLSR_SYM_LINK;
			else if (link_tuple->asym_time() >= now)
				link_type = MPOLSR_ASYM_LINK;
			else
				link_type = MPOLSR_LOST_LINK;
			// Establishes neighbor type.
			if (state_.find_mpr_addr(get_main_addr(link_tuple->nb_iface_addr())))
				nb_type = MPOLSR_MPR_NEIGH;
			else {
				bool ok = false;
				for (nbset_t::iterator nb_it = nbset().begin();
					nb_it != nbset().end();
					nb_it++) {
					MPOLSR_nb_tuple* nb_tuple = *nb_it;
					if (nb_tuple->nb_main_addr() == link_tuple->nb_iface_addr()) {
						if (nb_tuple->status() == MPOLSR_STATUS_SYM)
							nb_type = MPOLSR_SYM_NEIGH;
						else if (nb_tuple->status() == MPOLSR_STATUS_NOT_SYM)
							nb_type = MPOLSR_NOT_NEIGH;
						else {
							fprintf(stderr, "There is a neighbor tuple"
								" with an unknown status!\n");
							exit(1);
						}
						ok = true;
						break;
					}
				}
				if (!ok) {
					fprintf(stderr, "Link tuple has no corresponding"
						" Neighbor tuple\n");
					//exit(1);

				}
			}

			int count = msg.hello().count;
			link_code = (link_type & 0x03) | ((nb_type << 2) & 0x0f);
			map<u_int8_t, int>::iterator pos = linkcodes_count.find(link_code);
			if (pos == linkcodes_count.end()) {
				linkcodes_count[link_code] = count;
				assert(count >= 0 && count < MPOLSR_MAX_HELLOS);
				msg.hello().hello_msg(count).count = 0;
				msg.hello().hello_msg(count).link_code() = link_code;
				msg.hello().hello_msg(count).reserved() = 0;
				msg.hello().count++;
			}
			else
				count = (*pos).second;
			
			int i = msg.hello().hello_msg(count).count;
			assert(count >= 0 && count < MPOLSR_MAX_HELLOS);
			assert(i >= 0 && i < MPOLSR_MAX_ADDRS);
			
			msg.hello().hello_msg(count).nb_iface_addr(i) =
				link_tuple->nb_iface_addr();
			msg.hello().hello_msg(count).count++;
			msg.hello().hello_msg(count).link_msg_size() =
				msg.hello().hello_msg(count).size();
		}
	}
	
	msg.msg_size() = msg.size();
	
	enque_msg(msg, JITTER);
}

///
/// \brief Creates a new %MPOLSR TC message which is buffered to be sent later on.
///
void
MPOLSR::send_tc() {
//	printf("sending tc............................................\n");
	MPOLSR_msg msg;
	msg.msg_type()		= MPOLSR_TC_MSG;
	msg.vtime()		= MPOLSR::seconds_to_emf(MPOLSR_TOP_HOLD_TIME);
	msg.orig_addr()		= ra_addr();
	msg.ttl()		= 255;
	msg.hop_count()		= 0;
	msg.msg_seq_num()	= msg_seq();
	
	msg.tc().ansn()		= ansn_;
	msg.tc().reserved()	= 0; 
	msg.tc().count		= 0;
	
	//the original for OLSR 
	//add the link to mprselecter to tc message
	for (mprselset_t::iterator it = mprselset().begin(); it != mprselset().end(); it++) {
		MPOLSR_mprsel_tuple* mprsel_tuple = *it;
		int count = msg.tc().count;

		assert(count >= 0 && count < MPOLSR_MAX_ADDRS);
		msg.tc().nb_main_addr(count) = mprsel_tuple->main_addr();
		msg.tc().count++;
	}
	
/*
	//midified for MPOLSR
	//add the link to all the neighbors to tc message
	for (nbset_t::iterator it = nbset().begin(); it != nbset().end(); it++){
		MPOLSR_nb_tuple* nb_tuple = *it;
		int count = msg.tc().count;
		assert (count >= 0 && count < MPOLSR_MAX_ADDRS);
		msg.tc().nb_main_addr(count) = nb_tuple->nb_main_addr();
		msg.tc().count ++;
	}
*/
	msg.msg_size()		= msg.size();
	
	enque_msg(msg, JITTER);
}

///
/// \brief Creates a new %MPOLSR MID message which is buffered to be sent later on.
/// \warning This message is never invoked because there is no support for multiple interfaces.
///
void
MPOLSR::send_mid() {
	MPOLSR_msg msg;
	msg.msg_type()		= MPOLSR_MID_MSG;
	msg.vtime()		= MPOLSR::seconds_to_emf(MPOLSR_MID_HOLD_TIME);
	msg.orig_addr()		= ra_addr();
	msg.ttl()		= 255;
	msg.hop_count()		= 0;
	msg.msg_seq_num()	= msg_seq();
	
	msg.mid().count		= 0;
	//foreach iface in this_node do
	//	msg.mid().iface_addr(i) = iface
	//	msg.mid().count++
	//done
	
	msg.msg_size()		= msg.size();
	
	enque_msg(msg, JITTER);
}

///
/// \brief	Updates Link Set according to a new received HELLO message (following RFC 3626
///		specification). Neighbor Set is also updated if needed.
///
/// \param msg the MPOLSR message which contains the HELLO message.
/// \param receiver_iface the address of the interface where the message was received from.
/// \param sender_iface the address of the interface where the message was sent from.
///
void
MPOLSR::link_sensing(MPOLSR_msg& msg, nsaddr_t receiver_iface, nsaddr_t sender_iface) {
	MPOLSR_hello& hello	= msg.hello();
	double now		= CURRENT_TIME;
	bool updated		= false;
	bool created		= false;
	
	MPOLSR_link_tuple* link_tuple = state_.find_link_tuple(sender_iface);
	if (link_tuple == NULL) {
		// We have to create a new tuple
		link_tuple = new MPOLSR_link_tuple;
		link_tuple->nb_iface_addr()	= sender_iface;
		link_tuple->local_iface_addr()	= receiver_iface;
		link_tuple->sym_time()		= now - 1;
		link_tuple->lost_time()		= 0.0;
		link_tuple->time()		= now + MPOLSR::emf_to_seconds(msg.vtime());
		add_link_tuple(link_tuple, hello.willingness());
		created = true;
	}
	else
		updated = true;
	
 	link_tuple->asym_time() = now + MPOLSR::emf_to_seconds(msg.vtime());
	assert(hello.count >= 0 && hello.count <= MPOLSR_MAX_HELLOS);
	for (int i = 0; i < hello.count; i++) {
		MPOLSR_hello_msg& hello_msg = hello.hello_msg(i);
		int lt = hello_msg.link_code() & 0x03;
		int nt = hello_msg.link_code() >> 2;
		
		// We must not process invalid advertised links
		if ((lt == MPOLSR_SYM_LINK && nt == MPOLSR_NOT_NEIGH) ||
			(nt != MPOLSR_SYM_NEIGH && nt != MPOLSR_MPR_NEIGH
			&& nt != MPOLSR_NOT_NEIGH))
			continue;
		
		assert(hello_msg.count >= 0 && hello_msg.count <= MPOLSR_MAX_ADDRS);
		for (int j = 0; j < hello_msg.count; j++) {
			if (hello_msg.nb_iface_addr(j) == receiver_iface) {
				if (lt == MPOLSR_LOST_LINK) {
					link_tuple->sym_time() = now - 1;
					updated = true;
				}
				else if (lt == MPOLSR_SYM_LINK || lt == MPOLSR_ASYM_LINK) {
					link_tuple->sym_time()	=
						now + MPOLSR::emf_to_seconds(msg.vtime());
					link_tuple->time()	=
						link_tuple->sym_time() + MPOLSR_NEIGHB_HOLD_TIME;
					link_tuple->lost_time()	= 0.0;
					updated = true;
				}
				break;
			}
		}
		
	}
	link_tuple->time() = MAX(link_tuple->time(), link_tuple->asym_time());
	
	if (updated)
		updated_link_tuple(link_tuple);
	
	// Schedules link tuple deletion
	if (created && link_tuple != NULL) {
		MPOLSR_LinkTupleTimer* link_timer =
			new MPOLSR_LinkTupleTimer(this, link_tuple);
		link_timer->resched(DELAY(MIN(link_tuple->time(), link_tuple->sym_time())));
	}
}

///
/// \brief	Updates the Neighbor Set according to the information contained in a new received
///		HELLO message (following RFC 3626).
///
/// \param msg the %MPOLSR message which contains the HELLO message.
///
void
MPOLSR::populate_nbset(MPOLSR_msg& msg) {
	MPOLSR_hello& hello = msg.hello();
	
	MPOLSR_nb_tuple* nb_tuple = state_.find_nb_tuple(msg.orig_addr());
	if (nb_tuple != NULL)
		nb_tuple->willingness() = hello.willingness();
	else
		{
			MPOLSR_nb_tuple* nb_tuple		= new MPOLSR_nb_tuple;
			nb_tuple->nb_main_addr()	= msg.orig_addr();
			nb_tuple->willingness()		= hello.willingness();
			//if (tuple->sym_time() >= now)
				nb_tuple->status() = MPOLSR_STATUS_SYM;
			//else
		//		nb_tuple->status() = MPOLSR_STATUS_NOT_SYM;
			add_nb_tuple(nb_tuple);			
		//	printf("\nhahaha");
			//getchar();
			
		}
}

///
/// \brief	Updates the 2-hop Neighbor Set according to the information contained in a new
///		received HELLO message (following RFC 3626).
///
/// \param msg the %MPOLSR message which contains the HELLO message.
///
void
MPOLSR::populate_nb2hopset(MPOLSR_msg& msg) {
	double now		= CURRENT_TIME;
	MPOLSR_hello& hello	= msg.hello();
	
	for (linkset_t::iterator it_lt = linkset().begin(); it_lt != linkset().end(); it_lt++) {
		MPOLSR_link_tuple* link_tuple = *it_lt;
		if (get_main_addr(link_tuple->nb_iface_addr()) == msg.orig_addr()) {
			if (link_tuple->sym_time() >= now) {
				assert(hello.count >= 0 && hello.count <= MPOLSR_MAX_HELLOS);
				for (int i = 0; i < hello.count; i++) {
					MPOLSR_hello_msg& hello_msg = hello.hello_msg(i);
					int nt = hello_msg.link_code() >> 2;
					assert(hello_msg.count >= 0 &&
						hello_msg.count <= MPOLSR_MAX_ADDRS);
					
					for (int j = 0; j < hello_msg.count; j++) {
						nsaddr_t nb2hop_addr = hello_msg.nb_iface_addr(j);
						if (nt == MPOLSR_SYM_NEIGH || nt == MPOLSR_MPR_NEIGH) {
							// if the main address of the 2-hop
							// neighbor address = main address of
							// the receiving node: silently
							// discard the 2-hop neighbor address
							if (nb2hop_addr != ra_addr()) {
								// Otherwise, a 2-hop tuple is created
								MPOLSR_nb2hop_tuple* nb2hop_tuple =
									state_.find_nb2hop_tuple(msg.orig_addr(), nb2hop_addr);
								if (nb2hop_tuple == NULL) {
									nb2hop_tuple =
										new MPOLSR_nb2hop_tuple;
									nb2hop_tuple->nb_main_addr() =
										msg.orig_addr();
									nb2hop_tuple->nb2hop_addr() =
										nb2hop_addr;
									add_nb2hop_tuple(nb2hop_tuple);
									nb2hop_tuple->time() =
										now + MPOLSR::emf_to_seconds(msg.vtime());
									// Schedules nb2hop tuple
									// deletion
									MPOLSR_Nb2hopTupleTimer* nb2hop_timer =
										new MPOLSR_Nb2hopTupleTimer(this, nb2hop_tuple);
									nb2hop_timer->resched(DELAY(nb2hop_tuple->time()));
								}
								else {
									nb2hop_tuple->time() =
										now + MPOLSR::emf_to_seconds(msg.vtime());
								}
								
							}
						}
						else if (nt == MPOLSR_NOT_NEIGH) {
							// For each 2-hop node listed in the HELLO
							// message with Neighbor Type equal to
							// NOT_NEIGH all 2-hop tuples where:
							// N_neighbor_main_addr == Originator
							// Address AND N_2hop_addr  == main address
							// of the 2-hop neighbor are deleted.
							state_.erase_nb2hop_tuples(msg.orig_addr(),
								nb2hop_addr);
						}
					}
				}
			}
		}
	}
}

///
/// \brief	Updates the MPR Selector Set according to the information contained in a new
///		received HELLO message (following RFC 3626).
///
/// \param msg the %MPOLSR message which contains the HELLO message.
///
void
MPOLSR::populate_mprselset(MPOLSR_msg& msg) {
	double now		= CURRENT_TIME;
	MPOLSR_hello& hello	= msg.hello();
	
	assert(hello.count >= 0 && hello.count <= MPOLSR_MAX_HELLOS);
	for (int i = 0; i < hello.count; i++) {
		MPOLSR_hello_msg& hello_msg = hello.hello_msg(i);
		int nt = hello_msg.link_code() >> 2;
		if (nt == MPOLSR_MPR_NEIGH) {
			assert(hello_msg.count >= 0 && hello_msg.count <= MPOLSR_MAX_ADDRS);
			for (int j = 0; j < hello_msg.count; j++) {
				if (hello_msg.nb_iface_addr(j) == ra_addr()) {
					// We must create a new entry into the mpr selector set
					MPOLSR_mprsel_tuple* mprsel_tuple =
						state_.find_mprsel_tuple(msg.orig_addr());
					if (mprsel_tuple == NULL) {
						mprsel_tuple = new MPOLSR_mprsel_tuple;
						mprsel_tuple->main_addr() = msg.orig_addr();
						mprsel_tuple->time() =
							now + MPOLSR::emf_to_seconds(msg.vtime());
						add_mprsel_tuple(mprsel_tuple);
						// Schedules mpr selector tuple deletion
						MPOLSR_MprSelTupleTimer* mprsel_timer =
							new MPOLSR_MprSelTupleTimer(this, mprsel_tuple);
						mprsel_timer->resched(DELAY(mprsel_tuple->time()));
					}
					else
						mprsel_tuple->time() =
							now + MPOLSR::emf_to_seconds(msg.vtime());
				}
			}
		}
	}
}

///
/// \brief	Drops a given packet because it couldn't be delivered to the corresponding
///		destination by the MAC layer. This may cause a neighbor loss, and appropiate
///		actions are then taken.
///
/// \param p the packet which couldn't be delivered by the MAC layer.
///
void
MPOLSR::mac_failed(Packet* p) {
	double now		= CURRENT_TIME;
	struct hdr_ip* ih	= HDR_IP(p);
	struct hdr_cmn* ch	= HDR_CMN(p);
	
	printf("\n%f: Node %d MAC Layer detects a breakage on link to %d\n",
		now,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(ch->next_hop()));
	
	if ((u_int32_t)ih->daddr() == IP_BROADCAST) {
		drop(p, DROP_RTR_MAC_CALLBACK);
		return;
	}
	
	MPOLSR_link_tuple* link_tuple = state_.find_link_tuple(ch->next_hop());
	if (link_tuple != NULL) {
		link_tuple->lost_time()	= now + MPOLSR_NEIGHB_HOLD_TIME;
		link_tuple->time()	= now + MPOLSR_NEIGHB_HOLD_TIME;
		nb_loss(link_tuple);
//		getchar();
	}

//	resend_data(p);
	drop(p, DROP_RTR_MAC_CALLBACK);
}

///
/// \brief Schedule the timer used for sending HELLO messages.
///
void
MPOLSR::set_hello_timer() {
	hello_timer_.resched((double)(hello_ival() - JITTER));
}

///
/// \brief Schedule the timer used for sending TC messages.
///
void
MPOLSR::set_tc_timer() {
	tc_timer_.resched((double)(tc_ival() - JITTER));
}

///
/// \brief Schedule the timer used for sending MID messages.
///
void
MPOLSR::set_mid_timer() {
	mid_timer_.resched((double)(mid_ival() - JITTER));
}

///
/// \brief Performs all actions needed when a neighbor loss occurs.
///
/// Neighbor Set, 2-hop Neighbor Set, MPR Set and MPR Selector Set are updated.
///
/// \param tuple link tuple with the information of the link to the neighbor which has been lost.
///
void
MPOLSR::nb_loss(MPOLSR_link_tuple* tuple) {
	debug("%f: Node %d detects neighbor %d loss\n",
		CURRENT_TIME,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->nb_iface_addr()));
	
	//updated_link_tuple(tuple);
	//state_.erase_link_tuple(tuple);
	//state_.erase_nb_tuple(get_main_addr(tuple->nb_iface_addr()));
	rm_link_tuple(tuple);
	state_.erase_nb2hop_tuples(get_main_addr(tuple->nb_iface_addr()));
	state_.erase_mprsel_tuples(get_main_addr(tuple->nb_iface_addr()));
	
	mpr_computation();
	
 //	rtable_computation();//this is for unipath routing
 	
 	//for multipath routing, just set the out_of_date flag
 	m_rtable_.set_flag(true);
}

///
/// \brief Adds a duplicate tuple to the Duplicate Set.
///
/// \param tuple the duplicate tuple to be added.
///
void
MPOLSR::add_dup_tuple(MPOLSR_dup_tuple* tuple) {
	/*debug("%f: Node %d adds dup tuple: addr = %d seq_num = %d\n",
		CURRENT_TIME,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->addr()),
		tuple->seq_num());*/
	
	state_.insert_dup_tuple(tuple);
}

///
/// \brief Removes a duplicate tuple from the Duplicate Set.
///
/// \param tuple the duplicate tuple to be removed.
///
void
MPOLSR::rm_dup_tuple(MPOLSR_dup_tuple* tuple) {
	/*debug("%f: Node %d removes dup tuple: addr = %d seq_num = %d\n",
		CURRENT_TIME,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->addr()),
		tuple->seq_num());*/
	
	state_.erase_dup_tuple(tuple);
}

///
/// \brief Adds a link tuple to the Link Set (and an associated neighbor tuple to the Neighbor Set).
///
/// \param tuple the link tuple to be added.
/// \param willingness willingness of the node which is going to be inserted in the Neighbor Set.
///
void
MPOLSR::add_link_tuple(MPOLSR_link_tuple* tuple, u_int8_t  willingness) {
	double now = CURRENT_TIME;

	debug("%f: Node %d adds link tuple: nb_addr = %d\n",
		now,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->nb_iface_addr()));

	state_.insert_link_tuple(tuple);
	// Creates associated neighbor tuple
	MPOLSR_nb_tuple* nb_tuple		= new MPOLSR_nb_tuple;
	nb_tuple->nb_main_addr()	= get_main_addr(tuple->nb_iface_addr());
	nb_tuple->willingness()		= willingness;
	if (tuple->sym_time() >= now)
		nb_tuple->status() = MPOLSR_STATUS_SYM;
	else
		nb_tuple->status() = MPOLSR_STATUS_NOT_SYM;
	add_nb_tuple(nb_tuple);
}

///
/// \brief Removes a link tuple from the Link Set.
///
/// \param tuple the link tuple to be removed.
///
void
MPOLSR::rm_link_tuple(MPOLSR_link_tuple* tuple) {
	nsaddr_t nb_addr	= get_main_addr(tuple->nb_iface_addr());
	double now		= CURRENT_TIME;
	
	debug("%f: Node %d removes link tuple: nb_addr = %d\n",
		now,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->nb_iface_addr()));
	// Prints this here cause we are not actually calling rm_nb_tuple() (efficiency stuff)
	debug("%f: Node %d removes neighbor tuple: nb_addr = %d\n",
		now,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(nb_addr));

	state_.erase_link_tuple(tuple);
	
	MPOLSR_nb_tuple* nb_tuple = state_.find_nb_tuple(nb_addr);
	state_.erase_nb_tuple(nb_tuple);
	delete nb_tuple;
//	delete tuple;
}

///
/// \brief	This function is invoked when a link tuple is updated. Its aim is to
///		also update the corresponding neighbor tuple if it is needed.
///
/// \param tuple the link tuple which has been updated.
///
void
MPOLSR::updated_link_tuple(MPOLSR_link_tuple* tuple) {
	double now = CURRENT_TIME;
	
	// Each time a link tuple changes, the associated neighbor tuple must be recomputed
	MPOLSR_nb_tuple* nb_tuple =
		state_.find_nb_tuple(get_main_addr(tuple->nb_iface_addr()));
	if (nb_tuple != NULL) {
		if (USE_MAC&& tuple->lost_time() >= now)
			nb_tuple->status() = MPOLSR_STATUS_NOT_SYM;
		else if (tuple->sym_time() >= now)
			nb_tuple->status() = MPOLSR_STATUS_SYM;
		else
			nb_tuple->status() = MPOLSR_STATUS_NOT_SYM;
	
	
	debug("%f: Node %d has updated link tuple: nb_addr = %d status = %s\n",
		now,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->nb_iface_addr()),
		((nb_tuple->status() == MPOLSR_STATUS_SYM) ? "sym" : "not_sym"));
		}
}

///
/// \brief Adds a neighbor tuple to the Neighbor Set.
///
/// \param tuple the neighbor tuple to be added.
///
void
MPOLSR::add_nb_tuple(MPOLSR_nb_tuple* tuple) {
	debug("%f: Node %d adds neighbor tuple: nb_addr = %d status = %s\n",
		CURRENT_TIME,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->nb_main_addr()),
		((tuple->status() == MPOLSR_STATUS_SYM) ? "sym" : "not_sym"));
	
	state_.insert_nb_tuple(tuple);
}

///
/// \brief Removes a neighbor tuple from the Neighbor Set.
///
/// \param tuple the neighbor tuple to be removed.
///
void
MPOLSR::rm_nb_tuple(MPOLSR_nb_tuple* tuple) {
	debug("%f: Node %d removes neighbor tuple: nb_addr = %d status = %s\n",
		CURRENT_TIME,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->nb_main_addr()),
		((tuple->status() == MPOLSR_STATUS_SYM) ? "sym" : "not_sym"));
	
	state_.erase_nb_tuple(tuple);
}

///
/// \brief Adds a 2-hop neighbor tuple to the 2-hop Neighbor Set.
///
/// \param tuple the 2-hop neighbor tuple to be added.
///
void
MPOLSR::add_nb2hop_tuple(MPOLSR_nb2hop_tuple* tuple) {
	debug("%f: Node %d adds 2-hop neighbor tuple: nb_addr = %d nb2hop_addr = %d\n",
		CURRENT_TIME,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->nb_main_addr()),
		MPOLSR::node_id(tuple->nb2hop_addr()));

	state_.insert_nb2hop_tuple(tuple);
}

///
/// \brief Removes a 2-hop neighbor tuple from the 2-hop Neighbor Set.
///
/// \param tuple the 2-hop neighbor tuple to be removed.
///
void
MPOLSR::rm_nb2hop_tuple(MPOLSR_nb2hop_tuple* tuple) {
	debug("%f: Node %d removes 2-hop neighbor tuple: nb_addr = %d nb2hop_addr = %d\n",
		CURRENT_TIME,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->nb_main_addr()),
		MPOLSR::node_id(tuple->nb2hop_addr()));

	state_.erase_nb2hop_tuple(tuple);
}

///
/// \brief Adds an MPR selector tuple to the MPR Selector Set.
///
/// Advertised Neighbor Sequence Number (ANSN) is also updated.
///
/// \param tuple the MPR selector tuple to be added.
///
void
MPOLSR::add_mprsel_tuple(MPOLSR_mprsel_tuple* tuple) {
	debug("%f: Node %d adds MPR selector tuple: nb_addr = %d\n",
		CURRENT_TIME,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->main_addr()));

	state_.insert_mprsel_tuple(tuple);
	ansn_ = (ansn_ + 1)%(MPOLSR_MAX_SEQ_NUM + 1);
}

///
/// \brief Removes an MPR selector tuple from the MPR Selector Set.
///
/// Advertised Neighbor Sequence Number (ANSN) is also updated.
///
/// \param tuple the MPR selector tuple to be removed.
///
void
MPOLSR::rm_mprsel_tuple(MPOLSR_mprsel_tuple* tuple) {
	debug("%f: Node %d removes MPR selector tuple: nb_addr = %d\n",
		CURRENT_TIME,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->main_addr()));

	state_.erase_mprsel_tuple(tuple);
	ansn_ = (ansn_ + 1)%(MPOLSR_MAX_SEQ_NUM + 1);
}

///
/// \brief Adds a topology tuple to the Topology Set.
///
/// \param tuple the topology tuple to be added.
///
void
MPOLSR::add_topology_tuple(MPOLSR_topology_tuple* tuple) {
	debug("%f: Node %d adds topology tuple: dest_addr = %d last_addr = %d seq = %d\n",
		CURRENT_TIME,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->dest_addr()),
		MPOLSR::node_id(tuple->last_addr()),
		tuple->seq());

	state_.insert_topology_tuple(tuple);
}

///
/// \brief Removes a topology tuple from the Topology Set.
///
/// \param tuple the topology tuple to be removed.
///
void
MPOLSR::rm_topology_tuple(MPOLSR_topology_tuple* tuple) {
	debug("%f: Node %d removes topology tuple: dest_addr = %d last_addr = %d seq = %d\n",
		CURRENT_TIME,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->dest_addr()),
		MPOLSR::node_id(tuple->last_addr()),
		tuple->seq());

	state_.erase_topology_tuple(tuple);
}

///
/// \brief Adds an interface association tuple to the Interface Association Set.
///
/// \param tuple the interface association tuple to be added.
///
void
MPOLSR::add_ifaceassoc_tuple(MPOLSR_iface_assoc_tuple* tuple) {
	debug("%f: Node %d adds iface association tuple: main_addr = %d iface_addr = %d\n",
		CURRENT_TIME,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->main_addr()),
		MPOLSR::node_id(tuple->iface_addr()));

	state_.insert_ifaceassoc_tuple(tuple);
}

///
/// \brief Removes an interface association tuple from the Interface Association Set.
///
/// \param tuple the interface association tuple to be removed.
///
void
MPOLSR::rm_ifaceassoc_tuple(MPOLSR_iface_assoc_tuple* tuple) {
	debug("%f: Node %d removes iface association tuple: main_addr = %d iface_addr = %d\n",
		CURRENT_TIME,
		MPOLSR::node_id(ra_addr()),
		MPOLSR::node_id(tuple->main_addr()),
		MPOLSR::node_id(tuple->iface_addr()));

	state_.erase_ifaceassoc_tuple(tuple);
}

///
/// \brief Gets the main address associated with a given interface address.
///
/// \param iface_addr the interface address.
/// \return the corresponding main address.
///
nsaddr_t
MPOLSR::get_main_addr(nsaddr_t iface_addr) {
	MPOLSR_iface_assoc_tuple* tuple =
		state_.find_ifaceassoc_tuple(iface_addr);
	
	if (tuple != NULL)
		return tuple->main_addr();
	return iface_addr;
}

///
/// \brief Determines which sequence number is bigger (as it is defined in RFC 3626).
///
/// \param s1 a sequence number.
/// \param s2 a sequence number.
/// \return true if s1 > s2, false in other case.
///
bool
MPOLSR::seq_num_bigger_than(u_int16_t s1, u_int16_t s2) {
	return (s1 > s2 && s1-s2 <= MPOLSR_MAX_SEQ_NUM/2)
		|| (s2 > s1 && s2-s1 > MPOLSR_MAX_SEQ_NUM/2);
}

///
/// \brief This auxiliary function (defined in RFC 3626) is used for calculating the MPR Set.
///
/// \param tuple the neighbor tuple which has the main address of the node we are going to calculate its degree to.
/// \return the degree of the node.
///
int
MPOLSR::degree(MPOLSR_nb_tuple* tuple) {
	int degree = 0;
	for (nb2hopset_t::iterator it = nb2hopset().begin(); it != nb2hopset().end(); it++) {
		MPOLSR_nb2hop_tuple* nb2hop_tuple = *it;
		if (nb2hop_tuple->nb_main_addr() == tuple->nb_main_addr()) {
			MPOLSR_nb_tuple* nb_tuple =
				state_.find_nb_tuple(nb2hop_tuple->nb_main_addr());
			if (nb_tuple == NULL)
				degree++;
		}
	}
	return degree;
}

///
/// \brief Converts a decimal number of seconds to the mantissa/exponent format.
///
/// \param seconds decimal number of seconds we want to convert.
/// \return the number of seconds in mantissa/exponent format.
///
u_int8_t
MPOLSR::seconds_to_emf(double seconds) {
	// This implementation has been taken from unik-mpolsrd-0.4.5 (mantissa.c),
	// licensed under the GNU Public License (GPL)
	
	int a, b = 0;
 	while (seconds/MPOLSR_C >= pow((double)2, (double)b))
		b++;
	b--;
	
	if (b < 0) {
		a = 1;
		b = 0;
	}
	else if (b > 15) {
		a = 15;
		b = 15;
	}
	else {
		a = (int)(16*((double)seconds/(MPOLSR_C*(double)pow(2, b))-1));
		while (a >= 16) {
			a -= 16;
			b++;
		}
	}
	
	return (u_int8_t)(a*16+b);
}

///
/// \brief Converts a number of seconds in the mantissa/exponent format to a decimal number.
///
/// \param mpolsr_format number of seconds in mantissa/exponent format.
/// \return the decimal number of seconds.
///
double
MPOLSR::emf_to_seconds(u_int8_t mpolsr_format) {
	// This implementation has been taken from unik-mpolsrd-0.4.5 (mantissa.c),
	// licensed under the GNU Public License (GPL)
	int a = mpolsr_format >> 4;
	int b = mpolsr_format - a*16;
	return (double)(MPOLSR_C*(1+(double)a/16)*(double)pow(2,b));
}

///
/// \brief Returns the identifier of a node given the address of the attached MPOLSR agent.
///
/// \param addr the address of the MPOLSR routing agent.
/// \return the identifier of the node.
///
int
MPOLSR::node_id(nsaddr_t addr) {
	// Preventing a bad use for this function
        if ((u_int32_t)addr == IP_BROADCAST)
		return addr;
	// Getting node id
	Node* node = Node::get_node_by_address(addr);
	assert(node != NULL);
	return node->nodeid();
}

///
///\brief Renew the weight of a topology tuple, for K-path Dijkstra
///
float
MPOLSR::tuple_weight(float a){
	return 2*a+0.0;
}
