import pyshark
import pandas as pd
import time
import traceback
import signal
from datetime import datetime
import sys
from threading import Thread

###############################################################################
#dataset folder
modelfolder = './models/'

#feature to extract
featurenamefile = modelfolder + 'Feature_name.dat'
with open(featurenamefile) as file:
    feature_name = [line.rstrip() for line in file]
file.close()

n_feature = len(feature_name)
dataset_df = pd.DataFrame(columns=feature_name)

dtime_str = datetime.now().strftime('%d-%m-%Y_%H%M')
csvfile = modelfolder + 'captured_dataset_'+dtime_str+'.csv'

###############################################################################

#packet to dataframe
def packet_to_dataframe(pk,time_delta,time_rela):
    global feature_name
    #empty dataframe
    merge_df = pd.DataFrame(columns=feature_name)

    #packet IP, TCP
    df_template = pd.DataFrame(index=[0],columns=feature_name)
    df_template['frame.time_delta'] = time_delta
    df_template['frame.time_relative'] = time_rela
    df_template['ip.len'] = int(pk.ip.len)
    df_template['ip.protocol'] = int(pk.ip.proto)
    df_template['ip.src'] = str(pk.ip.src)
    df_template['ip.dst'] = str(pk.ip.dst)
    df_template['tcp.srcport'] = int(pk.tcp.srcport)
    df_template['tcp.dstport'] = int(pk.tcp.dstport)
    df_template['tcp.flags'] = pk.tcp.flags

    if "MQTT" not in pk:
        merge_df = pd.concat([merge_df,df_template],ignore_index=True)
        return merge_df

    try:
        mqtt_layers = pk.get_multiple_layers('mqtt')
        for mqtt in mqtt_layers:
            # new row with same IP and TCP feature
            df_row = df_template.copy()

            # MQTT fixed header
            df_row['mqtt.hdrflags'] = mqtt.hdrflags
            df_row['mqtt.msgtype'] = int(mqtt.msgtype)
            df_row['mqtt.len'] = int(mqtt.len)

        	# MQTT variable header
            if mqtt.len:
                if mqtt.msgtype == '1' :
                    df_row['mqtt.proto_len'] = int(mqtt.proto_len)
                    if mqtt.proto_len != '0':
                        df_row['mqtt.protoname'] = 1 if "MQTT" in mqtt.protoname else 0
                    else:
                        df_row['mqtt.protoname'] = 0
                    df_row['mqtt.ver'] = int(mqtt.ver)

                    df_row['mqtt.conflags'] = mqtt.conflags
                    df_row['mqtt.conflag.uname'] = int(mqtt.conflag_uname)
                    if mqtt.conflag_uname == '1':
                        df_row['mqtt.username_len'] = int(mqtt.username_len)
                        df_row['mqtt.username'] = str(mqtt.username)

                    df_row['mqtt.conflag.passwd'] = int(mqtt.conflag_passwd)
                    if mqtt.conflag_passwd == '1':
                        df_row['mqtt.passwd_len'] = int(mqtt.passwd_len)
                        df_row['mqtt.passwd'] = str(mqtt.passwd)

                    df_row['mqtt.conflag.willretain'] = int(mqtt.conflag_retain)
                    df_row['mqtt.conflag.willqos'] = int(mqtt.conflag_qos)

                    df_row['mqtt.conflag.willflag'] = int(mqtt.conflag_willflag)
                    if mqtt.conflag_willflag == '1':
                        df_row['mqtt.willtopic_len'] = int(mqtt.willtopic_len)
                        df_row['mqtt.willtopic'] = str(mqtt.willtopic)
                        df_row['mqtt.willmsg_len'] = int(mqtt.willmsg_len)
                        df_row['mqtt.willmsg']     = str(mqtt.willmsg)

                    df_row['mqtt.conflag.cleansess'] = int(mqtt.conflag_cleansess)
                    df_row['mqtt.conflag.reserved'] = int(mqtt.conflag_reserved)
                    df_row['mqtt.kalive'] = int(mqtt.kalive)

                    df_row['mqtt.clientid_len'] = int(mqtt.clientid_len)
                    if mqtt.clientid_len != '0':
                        df_row['mqtt.clientid'] = str(mqtt.clientid)

                elif mqtt.msgtype == '2' :
                    df_row['mqtt.conack.flags'] = mqtt.conack_flags
                    df_row['mqtt.conack.flags.sp'] = mqtt.conack_flags_sp
                    df_row['mqtt.conack.val'] = int(mqtt.conack_val)

                elif mqtt.msgtype == '3' :
                    df_row['mqtt.dupflag'] = int(mqtt.dupflag)
                    df_row['mqtt.qos'] = int(mqtt.qos)
                    df_row['mqtt.retain'] = int(mqtt.retain)

                    df_row['mqtt.topic_len'] = int(mqtt.topic_len)
                    if mqtt.topic_len != '0':
                        df_row['mqtt.topic'] = str(mqtt.topic)

                    if mqtt.qos != '0' :
                        df_row['mqtt.msgid'] = str(mqtt.msgid)
                    msglen_tmp = int(mqtt.len) - int(mqtt.topic_len)
                    df_row['mqtt.msglen'] = msglen_tmp
                    if msglen_tmp != 0 :
                        df_row['mqtt.msg'] = str(mqtt.msg)

                elif mqtt.msgtype == '4' :
                    df_row['mqtt.msgid'] = int(mqtt.msgid)

                elif mqtt.msgtype == '5' :
                    df_row['mqtt.msgid'] = int(mqtt.msgid)

                elif mqtt.msgtype == '6' :
                    df_row['mqtt.msgid'] = int(mqtt.msgid)

                elif mqtt.msgtype == '7' :
                    df_row['mqtt.msgid'] = int(mqtt.msgid)

                elif mqtt.msgtype == '8' :
                    df_row['mqtt.msgid'] = int(mqtt.msgid)
                    df_row['mqtt.topic_len'] = int(mqtt.topic_len)
                    if mqtt.topic_len != 0:
                        df_row['mqtt.topic'] = str(mqtt.topic)
                    df_row['mqtt.sub.qos'] = mqtt.sub_qos

                elif mqtt.msgtype == '9' :
                    df_row['mqtt.msgid'] = mqtt.msgid
                    df_row['mqtt.suback.retcode'] = mqtt.suback_qos

                elif mqtt.msgtype == '10' :
                    df_row['mqtt.msgid'] = mqtt.msgid
                    df_row['mqtt.topic_len'] = int(mqtt.topic_len)
                    if mqtt.topic_len != 0:
                        df_row['mqtt.topic'] = str(mqtt.topic)
                elif mqtt.msgtype == '11' :
                    df_row['mqtt.msgid'] = int(mqtt.msgid)
        merge_df = pd.concat([merge_df,df_row],ignore_index=True)
    except Exception as e:
        print(mqtt)
        print(mqtt.field_names)
        traceback.print_exc()
    return merge_df

def packet_to_list(pk,time_start,time_previous):
    global feature_name
    global n_feature
    now = time.time()
    pk_lst = [None] * n_feature



#capture TCP
def capture_live_packets(network_interface):
    global dataset_df
    capture = pyshark.LiveCapture(interface=network_interface,display_filter='tcp')
    start_time = time.time()
    lastpk_time = start_time
    for raw_packet in capture.sniff_continuously():
        # if "MQTT" in raw_packet:
        #     print(raw_packet)
        now = time.time()
        pk_relative_time = (now - start_time) % 1000
        pkduration = now - lastpk_time
        lastpk_time = now
        df_packet = packet_to_dataframe(raw_packet,pkduration,pk_relative_time)
        dataset_df = pd.concat([dataset_df,df_packet],ignore_index=True)
        # print(df_packet)

        # res = AImodel_Detect_Abnormal(df_packet,label, model_dict)

def signal_handler(*args):
    print('Dumping data:', csvfile )
    dataset_df.to_csv(csvfile,index=False,columns=feature_name)
    print('Dumped data before exit')
    sys.exit(0)


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

capture_live_packets('ogstun')