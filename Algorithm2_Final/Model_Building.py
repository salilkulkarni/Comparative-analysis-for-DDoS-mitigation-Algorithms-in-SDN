import numpy as np
import pandas as pd
import pickle
from sklearn import metrics
from sklearn.naive_bayes import GaussianNB
from sklearn import preprocessing

df_dda = pd.read_csv('./CSV/trial.csv')
#Remove class column
pred_1 = df_dda.drop("class",axis=1)
df_target = df_dda["class"]
model = GaussianNB()
model = model.fit(pred_1, df_target)
predicted = model.predict(pred_1)
print("Predicted values : ",predicted)

#Dump the model into file
filename= 'Naive_Bayes_Model'
outfile=open(filename,'wb')
pickle.dump(model,outfile)
outfile.close()
