'''
Authors : Chinmay, Salil, Swarali
Live Capture
Algorithm 2
'''

import pickle
import pandas as pd
import numpy as np
import pyshark as py
import csv

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

interfacen ="any"
op = "live.pcap"
				
names2 =['window_size', 'flags_urg', 'ack', 'stream' ]
infile=open('./Naive_Bayes_Model','rb')
model=pickle.load(infile)
#Pyshark live Capture on interface "any"
cap1 = py.LiveCapture(interface = interfacen, output_file = op)

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
				
				
while(True):
	#Capture 50 packets for analysis
	cap1.sniff(packet_count =50)
	for i in cap1:
		try:
			#Check if packet is tcp with 3 layers and IP should not be loopback address
			if((len(i.layers)==3 or len(i.layers)==4) and i.layers[2].layer_name=='tcp' and i.ip.addr != "127.0.0.1"):
				#Check if the host is already blocked
				if blocked.has_key(i.ip.src):
					if i.ip.dst in blocked[i.ip.src]:
						#print("Host is blocked with IP : "+ i.ip.src)
						continue
				print(packet)
				# Create an empty array
				arr = []
				for j in range(4):
					#Getthe values for all fields in names2 array 
					val = i.layers[2].get_field_value(names2[j])
					arr.append(val)
		
				arr = np.array(arr)			#Convert intp numpy array
				arr = pd.to_numeric(arr)	#Convert into numeric form
				arr = np.expand_dims(arr,0)	#Convert into 2D array
				p = model.predict(arr)		#Predict using the trained model
						
				last_count = 0
				temp = {}
				#Check if packet is abnormal 0->abnormal 1->normal
				if p[0] == 0:
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
					if count > 30:
						blocking(s,d)
			
		except Exception as e:
			print("Exception",e)
		
	#Write src and dst IP to csv	
	write_csv()
	print(packet)
	print(blocked)
		

