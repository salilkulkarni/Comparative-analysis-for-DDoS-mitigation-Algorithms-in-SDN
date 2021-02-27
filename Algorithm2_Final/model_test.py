import pickle
import pandas as pd
import numpy as np
import pyshark as py

infile=open('./Naive_Bayes_Model','rb')
model=pickle.load(infile)

window_size = 1975808
flags_urg = 4717865
ack = 4717865
stream = 0
 

a = [window_size,flags_urg,ack,stream]
a = np.array(a)  		#Convert into numpy array
a = np.expand_dims(a,0) #Convert into 2D array
p = model.predict(a)
print("Predicted Value  : ",p)
