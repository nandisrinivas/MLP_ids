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
        print(data.tail())
        print(list(data))
        print(data['label'].value_counts())
        labels = data['label'].copy()
        num_features=['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot','num_failed_logins', 'logged_in', 'lnum_compromised', 'lroot_shell', 'lsu_attempted', 'lnum_root', 'lnum_file_creations', 'lnum_shells', 'lnum_access_files', 'lnum_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']
        features = data[num_features]
        print(features)
        print(features.describe())
        mlp = MLPClassifier(alpha =0.0001,solver='adam',max_iter=200,learning_rate_init=0.001,early_stopping=False,verbose=1)
        t0 = time()
        mlp.fit(features, labels)
        tt = time() - t0
        print ("Classifier trained in {} seconds.".format(round(tt, 3)))
        kdd_data_corrected_test = pd.read_csv("/home/srinivas/Desktop/kddcup_corrected.csv", delimiter=",", converters={1: self.converter, 2: self.converter, 3: self.converter}, header=None, names = col_names)
        print(kdd_data_corrected_test.tail())
        min_max_scaler = preprocessing.MinMaxScaler()
        kdd_data_corrected_test[['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot','num_failed_logins',
'logged_in','lnum_compromised','lroot_shell','lsu_attempted','lnum_root','lnum_file_creations','lnum_shells','lnum_access_files','lnum_outbound_cmds',
'is_host_login','is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
'dst_host_rerror_rate','dst_host_srv_rerror_rate']]= min_max_scaler.fit_transform(kdd_data_corrected_test[['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot','num_failed_logins',
'logged_in','lnum_compromised','lroot_shell','lsu_attempted','lnum_root','lnum_file_creations','lnum_shells','lnum_access_files','lnum_outbound_cmds',
'is_host_login','is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
'dst_host_rerror_rate','dst_host_srv_rerror_rate']])
        print(kdd_data_corrected_test.tail())
        print(kdd_data_corrected_test['label'].value_counts())
        features_train, features_test, labels_train, labels_test = train_test_split(kdd_data_corrected_test[num_features], 
                                                                            kdd_data_corrected_test['label'], test_size=0.5, 
                                                                            random_state=None)
        t0 = time()
        pred = mlp.predict(features_test)
        tt = time() - t0
        print ("Predicted in {} seconds".format(round(tt,3)))
        acc = accuracy_score(pred, labels_test)
        print ("Accuracy is {}.".format(round(acc,4)))


def get_dataset_name(self):
        return "KDDcup99"
k=kddcup99()

