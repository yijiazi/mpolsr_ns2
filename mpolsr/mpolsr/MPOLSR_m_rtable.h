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

///
///\file MPOLSR_m_rtable.h
///\brief	Header file for multipath routing table
///
#ifndef __MPOLSR_m_rtable_h__
#define __MPOLSR_m_rtable_h__
//#include <mpolsr/MPOLSR.h>
#include "MPOLSR_repositories.h"
#include <trace.h>
#include <map>
#include "cmu-trace.h"

///
///\brief defines m_rtable_t as a map of MPOLSR_m_rt_entry, whose key is the destination address.
///The routing table is thus defined as pairs: [dest address, entry]. 
//typedef std::map<nsaddr_t, MPOLSR_m_rt_entry*> m_rtable_t;


//typedef std::vector<MPOLSR_m_rt_entry*> 	m_rtable_t;
typedef std::multimap<nsaddr_t,MPOLSR_m_rt_entry*> m_rtable_t;


///
///\brief This class is a representation of the MPOLSR´s multipath routing table
///
class MPOLSR_m_rtable{
	m_rtable_t m_rt_;
	
	//the flag, to see if the table need to be recomputed.
	bool out_of_date[MAX_NODE];

public:
	MPOLSR_m_rtable();
	~MPOLSR_m_rtable();

	m_rtable_t* m_rt();
	void 	set_flag(int id,bool flag);
	void 	set_flag(bool flag);
	bool	get_flag(int id);
	void 	clear();
	void 	rm_entry(nsaddr_t des);
	void	add_entry(MPOLSR_m_rt_entry* entry,nsaddr_t addr);
	m_rtable_t::iterator 	lookup(nsaddr_t dest);
	
	u_int32_t	size();
	void 	print(Trace*);

};

#endif
