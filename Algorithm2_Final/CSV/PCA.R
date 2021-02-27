library(caTools)
library(rpart)
library(e1071)

myfile <-read.csvmydata <- read.csv(file = "C:\\Users\\salil\\Downloads\\rand_pca.csv", header = TRUE,sep = ",")
View(myfile)

myfil.pca <-prcomp(myfile,center = TRUE, scale. = TRUE)

summary(myfil.pca)

str(myfil.pca)
