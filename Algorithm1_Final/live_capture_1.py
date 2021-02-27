'''
Authors : Chinmay, Salil, Swarali
Live Capture
Algorithm 1
'''

import pyshark as py
import csv
interfacen ="any"
op = "live.pcap"

packet = {}
'''
Packet contains the counter for src->dst IP
packet = {
	src1 : {
		dst1 : counter
		dst2 : counter
	},
	src2 : {
		dst1 : counter
		dst2 : counter
	}
}

packet[s][d] gives counter for src->dst
'''

blocked = {}
'''
blocked contains all the malicious src and dst IP sets
blocked = {
	src1 : [dst1, dst2, ...],
	src2s : [dst1, dst2, ...]
}
'''

def blocking(src ,dst):
	global blocked
	
	if not blocked.has_key(src):
		blocked[src] = []
		
	if dst not in blocked[src]:
		#Add dst to src array
		blocked[src].append(dst)
	
	
def write_csv():
	global blocked
	#print("In write_csv")
	#Create .csv file in Pox folder
	with open('../pox/blocking.csv', 'w') as file:
		mycsv = csv.writer(file)
		#Write initial row ie headers
		mycsv.writerow(["src_ip","dst_ip"])
		for i in blocked:
			for j in blocked[i]:
				#Write the src and dst IPs
				mycsv.writerow([i,j])


#Pyshark live Capture on interface "any"
cap1 = py.LiveCapture(interface = interfacen, output_file = op)


while True:
	#Capture 50 packets for analysis
	cap1.sniff(packet_count=50)
	for i in cap1:
		try:
			#Check if packet is tcp with 3 layers and IP should not be loopback address
			if((len(i.layers)==3 or len(i.layers)==4) and i.layers[2].layer_name=='tcp' and i.ip.addr != "127.0.0.1"):
				#Check if the host is already blocked
				if blocked.has_key(i.ip.src):
					if i.ip.dst in blocked[i.ip.src]:
						#print("Host is blocked with IP : "+ i.ip.src)
						continue
				#Get TCP flags and convert HEX to Decimal
				x = int(i.layers[2].flags,16)
			
				last_count = 0
				if x == 2:
					#SYN Packet
					s = i.ip.src
					d = i.ip.dst
					if packet.has_key(s):
						temp = packet[s]
						if temp.has_key(d):
							#Get previous count
							last_count = temp[d]
						else: 
							last_count = 0
					else:
						packet[s] = {}
					
					#Increment counter for src->dst
					count = last_count + 1
					packet[s][d] = count
					last_count = 0
					
					#If counter > threshold call blocking with src and dst IP
					if count > 10:
						blocking(s,d)
			
				elif x == 16:
					#ACK packet
					s = i.ip.src
					d = i.ip.dst
					if packet.has_key(s):
						temp = packet[s]
						if temp.has_key(d):
							#Reset counter for src->dst
							packet[s][d]=0
			
				elif x == 18:
					#SYN-ACK Packet
					pass
		except Exception as e:
			print("Exception", e)
			
	#Write src and dst IP to csv				
	write_csv()
	print(packet)
	print(blocked)		
