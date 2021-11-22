import os


T = 2048
K= 2048
for val in range(0,4):
    string = "./BM " + str(K) + " " + str(T) + ">" + "BM_" + str(K) + "_" +str(T)+".txt" 
    os.system(string)
    string = "./AR " + str(K) + " " + str(T) + ">" + "AR_" + str(K) + "_" +str(T)+".txt"
    os.system(string)
    string = "./IR " + str(K) + " " + str(T) + ">" + "IR_" + str(K) + "_" +str(T)+".txt"
    os.system(string)
    T*=2

K = 1024
T = 2048
for val in range(0,3) : 
    string = "./BM " + str(K) + " " + str(T) + ">" + "BM_" + str(K) + "_" +str(T)+".txt"
    os.system(string)
    string = "./AR " + str(K) + " " + str(T) + ">" + "AR_" + str(K) + "_" +str(T)+".txt"
    os.system(string)
    string = "./IR " + str(K) + " " + str(T) + ">" + "IR_" + str(K) + "_" +str(T)+".txt"
    os.system(string)
    K*=2
    

