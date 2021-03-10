import numpy as np
import pandas as pd
from sklearn import preprocessing
from time import time
from PIL import Image
import matplotlib.pyplot as plt
import tensorflow as tf
import cv2
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

class kddcup99:
    """
    Class for the kddcup99 intrusion detection dataset.
    """
     

    def converter(self, s):
        if (s == 'icmp'): return 0.0
        elif (s == 'tcp'): return 1.0
        elif (s == 'udp'): return 2.0
        elif (s == 'IRC'): return 0.0
        elif (s == 'X11'): return 1.0
        elif (s == 'Z39_50'): return 2.0
        elif (s == 'aol'): return 3.0
        elif (s == 'atuh'): return 4.0
        elif (s == 'bgp'): return 5.0
        elif (s == 'courier'): return 6.0
        elif (s == 'csnet_ns'): return 7.0
        elif (s == 'ctf'): return 8.0
        elif (s == 'daytime'): return 9.0
        elif (s == 'discard'): return 10.0
        elif (s == 'domain'): return 11.0
        elif (s == 'domain_u'): return 12.0
        elif (s == 'echo'): return 13.0
        elif (s == 'eco_i'): return 14.0
        elif (s == 'ecr_i'): return 15.0
        elif (s == 'efs'): return 16.0
        elif (s == 'exec'): return 17.0
        elif (s == 'finger'): return 18.0
        elif (s == 'ftp'): return 19.0
        elif (s == 'ftp_data'): return 20.0
        elif (s == 'gopher'): return 21.0
        elif (s == 'harvest'): return 22.0
        elif (s == 'hostname'): return 23.0
        elif (s == 'http'): return 24.0
        elif (s == 'http_278'): return 25.0
        elif (s == 'http_443'): return 26.0
        elif (s == 'http_800'): return 27.0
        elif (s == 'imap4'): return 28.0
        elif (s == 'iso_tsap'): return 29.0
        elif (s == 'klogin'): return 30.0
        elif (s == 'kshell'): return 31.0
        elif (s == 'ldap'): return 32.0
        elif (s == 'link'): return 33.0
        elif (s == 'login'): return 34.0
        elif (s == 'mtp'): return 35.0
        elif (s == 'name'): return 36.0
        elif (s == 'netbios_'): return 37.0
        elif (s == 'netstat'): return 38.0
        elif (s == 'nnsp'): return 39.0
        elif (s == 'nntp'): return 40.0
        elif (s == 'ntp_u'): return 41.0
        elif (s == 'other'): return 42.0
        elif (s == 'pm_dump'): return 43.0
        elif (s == 'pop_2'): return 44.0
        elif (s == 'pop_3'): return 45.0
        elif (s == 'printer'): return 46.0
        elif (s == 'private'): return 47.0
        elif (s == 'red_i'): return 48.0
        elif (s == 'remote_j'): return 49.0
        elif (s == 'rje'): return 50.0
        elif (s == 'shell'): return 51.0
        elif (s == 'smtp'): return 52.0
        elif (s == 'sql_net'): return 53.0
        elif (s == 'ssh'): return 54.0
        elif (s == 'sunrpc'): return 55.0
        elif (s == 'supdup'): return 56.0
        elif (s == 'systat'): return 57.0
        elif (s == 'telnet'): return 58.0
        elif (s == 'tftp_u'): return 59.0
        elif (s == 'tim_i'): return 60.0
        elif (s == 'time'): return 61.0
        elif (s == 'urh_i'): return 62.0
        elif (s == 'urp_i'): return 63.0
        elif (s == 'uucp'): return 64.0
        elif (s == 'uucp_pat'): return 65.0
        elif (s == 'vmnet'): return 66.0
        elif (s == 'whois'): return 67.0
        elif (s == 'OTH'): return 0.0
        elif (s == 'REJ'): return 1.0
        elif (s == 'RSTO'): return 2.0
        elif (s == 'RSTR'): return 3.0
        elif (s == 'S0'): return 4.0
        elif (s == 'S1'): return 5.0
        elif (s == 'S2'): return 6.0
        elif (s == 'S3'): return 7.0
        elif (s == 'SF'): return 8.0
        elif (s == 'Sh'): return 9.0
        elif (s == 'back'): return 0.0
        elif (s == 'buffer_overflow'): return 1.0
        elif (s == 'ftp_write'): return 2.0
        elif (s == 'guess_passwd'): return 3.0
        elif (s == 'imap'): return 4.0
        elif (s == 'ipsweep'): return 5.0
        elif (s == 'land'): return 6.0
        elif (s == 'loadmodule'): return 7.0
        elif (s == 'multihop'): return 8.0
        elif (s == 'neptune'): return 9.0
        elif (s == 'nmap'): return 10.0
        elif (s == 'normal'): return 11.0
        elif (s == 'perl'): return 12.0
        elif (s == 'phf'): return 13.0
        elif (s == 'pod'): return 14.0
        elif (s == 'portsweep'): return 15.0
        elif (s == 'rootkit'): return 16.0
        elif (s == 'satan'): return 17.0
        elif (s == 'smurf'): return 18.0
        elif (s == 'spy'): return 19.0
        elif (s == 'teardrop'): return 20.0
        elif (s == 'warezclient'): return 21.0
        elif (s == 'warezmaster'): return 22.0
        else: return -1.0

    def __init__(self):
        # Load kddcup99 data
        col_names = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot", 
             "num_failed_logins", "logged_in", "lnum_compromised", "lroot_shell", "lsu_attempted", "lnum_root", "lnum_file_creations", 
             "lnum_shells", "lnum_access_files", "lnum_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count", 
             "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", 
             "srv_diff_host_rate", "dst_host_count","dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
             "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", 
             "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"]
        print("loading data")
        overall_acc=0
        data = pd.read_csv("/home/srinivas/Desktop/kddcup99_csv.csv", delimiter=",", converters={1: self.converter, 2: self.converter, 3: self.converter},header=None, names = col_names)
        min_max_scaler = preprocessing.MinMaxScaler()
        data[['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot','num_failed_logins',
'logged_in','lnum_compromised','lroot_shell','lsu_attempted','lnum_root','lnum_file_creations','lnum_shells','lnum_access_files','lnum_outbound_cmds',
'is_host_login','is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
'dst_host_rerror_rate','dst_host_srv_rerror_rate']]= min_max_scaler.fit_transform(data[['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot','num_failed_logins',
'logged_in','lnum_compromised','lroot_shell','lsu_attempted','lnum_root','lnum_file_creations','lnum_shells','lnum_access_files','lnum_outbound_cmds',
'is_host_login','is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
'dst_host_rerror_rate','dst_host_srv_rerror_rate']])
        data_test = pd.read_csv("/home/srinivas/Desktop/kddcup_corrected.csv", delimiter=",", converters={1: self.converter, 2: self.converter, 3: self.converter},header=None, names = col_names)
        min_max_scaler = preprocessing.MinMaxScaler()
        data_test[['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot','num_failed_logins',
'logged_in','lnum_compromised','lroot_shell','lsu_attempted','lnum_root','lnum_file_creations','lnum_shells','lnum_access_files','lnum_outbound_cmds',
'is_host_login','is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
'dst_host_rerror_rate','dst_host_srv_rerror_rate']]= min_max_scaler.fit_transform(data_test[['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot','num_failed_logins',
'logged_in','lnum_compromised','lroot_shell','lsu_attempted','lnum_root','lnum_file_creations','lnum_shells','lnum_access_files','lnum_outbound_cmds',
'is_host_login','is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
'dst_host_rerror_rate','dst_host_srv_rerror_rate']])
        df_normal = data[data['label'] == 'normal.']
        df_test1 = data_test[data_test['label'] == 'normal.']
        li_dos=['neptune.','smurf.','pod.','teardrop.','land.','back.']
        li_u2r=['buffer_overflow.','loadmodule.','perl.','rootkit.','spy.']
        li_r2l=['guess_passwd.','ftp_write.','imap.','phf.','multihop.','warezmaster.','warezclient.']
        li_probe=['portsweep.','ipsweep.','nmap.','satan.']
        li_test2=['normal.','neptune.','smurf.','pod.','teardrop.','land.','back.']
        li_test3=['normal.','neptune.','smurf.','pod.','teardrop.','land.','back.','buffer_overflow.','loadmodule.','perl.','rootkit.','spy.']
        li_test4=['normal.','neptune.','smurf.','pod.','teardrop.','land.','back.','buffer_overflow.','loadmodule.','perl.','rootkit.','spy.'
,'guess_passwd.','ftp_write.','imap.','phf.','multihop.','warezmaster.','warezclient.']
        li_test5=['normal.','neptune.','smurf.','pod.','teardrop.','land.','back.','buffer_overflow.','loadmodule.','perl.','rootkit.','spy.'
,'guess_passwd.','ftp_write.','imap.','phf.','multihop.','warezmaster.','warezclient.','portsweep.','ipsweep.','nmap.','satan.']
        df_dos = data[data.label.isin(li_dos)] #dos attacks
        df_u2r = data[data.label.isin(li_u2r)] #u2r attacks
        df_r2l = data[data.label.isin(li_r2l)] #r2l attacks
        df_probe = data[data.label.isin(li_probe)] #probe attacks
        df_test2 = data_test[data_test.label.isin(li_test2)] #test at 2nd task,instances of task1 and task2
        df_test3 = data_test[data_test.label.isin(li_test3)] #test at 3rd task,instances of task1,task2,task3
        df_test4 = data_test[data_test.label.isin(li_test4)] #test at 4th task,instances of task1,task2,task3,task4
        df_test5 = data_test[data_test.label.isin(li_test5)] #test at 5th task,instances of task1,task2,task3,task4,task5
        print(df_normal)
        print(df_dos)
        print(df_u2r)
        print(df_r2l)
        print(df_probe)
        print(data['label'].value_counts())
        print(df_normal['label'].value_counts())
        print(df_dos['label'].value_counts())
        print(df_u2r['label'].value_counts())
        print(df_r2l['label'].value_counts())
        print(df_probe['label'].value_counts())
        labels_normal = df_normal['label'].copy()
        labels_dos = df_dos['label'].copy()
        labels_u2r = df_u2r['label'].copy()
        labels_r2l = df_r2l['label'].copy()
        labels_probe = df_probe['label'].copy()
        labels = data['label'].copy()
        num_features=['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot','num_failed_logins', 'logged_in', 'lnum_compromised', 'lroot_shell', 'lsu_attempted', 'lnum_root', 'lnum_file_creations', 'lnum_shells', 'lnum_access_files', 'lnum_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']
        features_task0 = df_normal[num_features]
        features_task1 = df_dos[num_features]
        features_task2 = df_u2r[num_features]
        features_task3 = df_r2l[num_features]
        features_task4 = df_probe[num_features]
        print(features_task0)
        print(features_task1)
        print(features_task2)
        print(features_task3)
        print(features_task4)
        for task in range(5):
            if task==0:
                print("Task 0:")
                mlp = MLPClassifier(alpha =0.0001,solver='adam',max_iter=500,learning_rate_init=0.001,early_stopping=False,verbose=1)
                t0 = time()
                mlp.fit(features_task0, labels_normal)
                tt = time() - t0
                print ("Classifier trained in {} seconds.".format(round(tt, 3)))
            elif task==1:
                  print("Task 1:")
                  mlp = MLPClassifier(alpha =0.0001,solver='adam',max_iter=500,learning_rate_init=0.001,early_stopping=False,verbose=1)
                  t0 = time()
                  mlp.fit(features_task1, labels_dos)
                  tt = time() - t0
                  print ("Classifier trained in {} seconds.".format(round(tt, 3)))
            elif task==2:
                  print("Task 2:")
                  mlp = MLPClassifier(alpha =0.0001,solver='adam',max_iter=500,learning_rate_init=0.001,early_stopping=False,verbose=1)
                  t0 = time()
                  mlp.fit(features_task2, labels_u2r)
                  tt = time() - t0
                  print ("Classifier trained in {} seconds.".format(round(tt, 3)))
            elif task==3:
                  print("Task 3:")
                  mlp = MLPClassifier(alpha =0.0001,solver='adam',max_iter=500,learning_rate_init=0.001,early_stopping=False,verbose=1)
                  t0 = time()
                  mlp.fit(features_task3, labels_r2l)
                  tt = time() - t0
                  print ("Classifier trained in {} seconds.".format(round(tt, 3)))
            elif task==4:
                  print("Task 4:")
                  mlp = MLPClassifier(alpha =0.0001,solver='adam',max_iter=500,learning_rate_init=0.001,early_stopping=False,verbose=1)
                  t0 = time()
                  mlp.fit(features_task4, labels_probe)
                  tt = time() - t0
                  print ("Classifier trained in {} seconds.".format(round(tt, 3)))
        for task in range(5):
            if task==0:
                print("Testing for Task 0:")
                features_train, features_test, labels_train, labels_test = train_test_split(df_test1[num_features], 
                                                                            df_test1['label'], test_size=0.5, 
                                                                            random_state=None)
                t0 = time()
                pred = mlp.predict(features_test)
                tt = time() - t0
                print ("Predicted in {} seconds".format(round(tt,3)))
                acc = accuracy_score(pred, labels_test)
                print ("Accuracy for Task 0 is {}.".format(round(acc,4)))
                overall_acc+=acc
            elif task==1:
                  print("Testing for Task 1:")
                  features_train, features_test, labels_train, labels_test = train_test_split(df_test2[num_features], 
                                                                            df_test2['label'], test_size=0.5, 
                                                                            random_state=None)
                  t0 = time()
                  pred = mlp.predict(features_test)
                  tt = time() - t0
                  print ("Predicted in {} seconds".format(round(tt,3)))
                  acc = accuracy_score(pred, labels_test)
                  print ("Accuracy for Task 1 is {}.".format(round(acc,4)))
                  overall_acc+=acc
            elif task==2:
                  print("Testing for Task 2:")
                  features_train, features_test, labels_train, labels_test = train_test_split(df_test3[num_features], 
                                                                            df_test3['label'], test_size=0.5, 
                                                                            random_state=None)
                  t0 = time()
                  pred = mlp.predict(features_test)
                  tt = time() - t0
                  print ("Predicted in {} seconds".format(round(tt,3)))
                  acc = accuracy_score(pred, labels_test)
                  print ("Accuracy for Task 2 is {}.".format(round(acc,4)))
                  overall_acc+=acc
            elif task==3:
                  print("Testing for Task 3:")
                  features_train, features_test, labels_train, labels_test = train_test_split(df_test4[num_features], 
                                                                            df_test4['label'], test_size=0.5, 
                                                                            random_state=None)
                  t0 = time()
                  pred = mlp.predict(features_test)
                  tt = time() - t0
                  print ("Predicted in {} seconds".format(round(tt,3)))
                  acc = accuracy_score(pred, labels_test)
                  print ("Accuracy for Task 3 is {}.".format(round(acc,4)))
                  overall_acc+=acc
            elif task==4:
                  print("Testing for Task 4:")
                  features_train, features_test, labels_train, labels_test = train_test_split(df_test5[num_features], 
                                                                            df_test5['label'], test_size=0.5, 
                                                                            random_state=None)
                  t0 = time()
                  pred = mlp.predict(features_test)
                  tt = time() - t0
                  print ("Predicted in {} seconds".format(round(tt,3)))
                  acc = accuracy_score(pred, labels_test)
                  print ("Accuracy for Task 4 is {}.".format(round(acc,4)))
                  overall_acc+=acc
        print("Cummulative Accuracy is {}.".format(round(overall_acc/5,4)))

def get_dataset_name(self):
        return "KDDcup99"
k=kddcup99()

