import csv
from pox.core import core
from pox.lib.util import dpidToStr
from pox.lib.recoco import Timer

import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pprint
from pox.openflow.of_json import *
import os

log = core.getLogger()
try:
	#Remove if the file exists
	os.remove("blocking.csv")
except:
	log.info("File already deleted")

def _timer_func():
	try:
		#Read the .csv file
		mycsv = csv.reader(open('blocking.csv', 'rb'))
		mycsv.next()
		log.debug("------------------------------------------")
		for row in mycsv:
			log.info("src : %s   dst : %s",row[0],row[1])
			i = row[0] 		#Src Ip
			j = row[1]		#Dst IP
			#connection is the connection between switch and controller
			for connection in core.openflow._connections.values():		# returns list if multiple switches
				#Install flow table entry 
				#src_ip = i, dst_ip = j, IP protocol, TCP protocol
				#Action is undefined, hence action is set to drop
				connection.send(of.ofp_flow_mod(match=of.ofp_match(nw_proto=6,dl_type=0x800, nw_src=i, nw_dst=j)))
		
	except Exception as e:
		log.debug("Exception")
	
	log.info("------------------------------------------")
	

#Call repeatedly after 0.1 secs
Timer(0.1, _timer_func, recurring=True)
