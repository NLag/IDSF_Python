import pyshark
import pandas as pd
import time 
import traceback
import signal
from datetime import datetime
import sys, os
from threading import Thread
import threading
from collections import deque
import csv
import joblib

ATTACKER_IP = '10.45.0.3'

###############################################################################
#dataset folder
modelfolder = './detection_result/'

#feature to extract
featurenamefile = 'Feature_use_training.dat'
with open(featurenamefile) as file:
    feature_name = [line.rstrip() for line in file]
file.close()
ft_dict = {key: i for i, key in enumerate(feature_name)}
n_feature = len(feature_name)

# dataset_df = pd.DataFrame(columns=feature_name)
result_deque = deque([])
has_result_event = threading.Event()

dtime_str = datetime.now().strftime('%d-%m-%Y_%H%M')

# AI model
modelfile = 'IDSF_model'
filetype = '.joblib'
modelname = 'DT'
filename = modelfile + '_'+ modelname + filetype
loaded_model = joblib.load(filename)

csvfile = modelfolder +'_'+modelname+'_' +'result'+dtime_str+'.csv'

#stop signal and stop ack
STOP_CAPTURE = False
STOP_OUTPUT = False

pk_count = 0

###############################################################################

def use_AI_model_detect_single_row(lstX):
    global loaded_model
    global feature_name
    Xdf = pd.DataFrame([lstX],columns=feature_name)
    lstY = loaded_model.predict(Xdf)
    return lstY[0]

#packet to list
def packet_to_lists(pk,time_start,time_previous,time_now):
    '''process packet and put to queue'''
    global feature_name
    global n_feature
    global result_deque
    global has_result_event
    res_lst = []
    ft_lst = [0] * n_feature
    ft_lst[ft_dict['frame.time_delta']]=time_now-time_previous
    ft_lst[ft_dict['frame.time_relative']]=time_now-time_start
    #IP
    #['version', 'hdr_len', 'dsfield', 'dsfield_dscp', 'dsfield_ecn', 'len', 'id', 'flags', 
    # 'flags_rb', 'flags_df', 'flags_mf', 'frag_offset', 'ttl', 'proto', 'checksum', 'checksum_status', 
    # 'src', 'addr', 'src_host', 'host', 'dst', 'dst_host']
    #pk.ip.version.int_value
    ft_lst[ft_dict['ip.len']]=pk.ip.len.hex_value
    # ft_lst[ft_dict['ip.protocol']]=pk.ip.proto.hex_value
    ipsrc_str=pk.ip.src.show
    true_r = 1 if ipsrc_str == ATTACKER_IP else 0
    # ft_lst[ft_dict['ip.dst']]=pk.ip.dst.show
    if pk.ip.proto.hex_value != 6:
        return 0
    #TCP
    #['srcport', 'dstport', 'port', 'stream', 'len', 'seq', 'seq_raw', 'nxtseq', 'ack', 'ack_raw',
    #  'hdr_len', 'flags', 'flags_res', 'flags_ns', 'flags_cwr', 'flags_ecn', 'flags_urg', 'flags_ack', 
    #  'flags_push', 'flags_reset', 'flags_syn', 'flags_fin', 'flags_str', 'window_size_value', 'window_size',
    #  'window_size_scalefactor', 'checksum', 'checksum_status', 'urgent_pointer', 'options', 'options_nop', 
    #  'option_kind', 'options_timestamp', 'option_len', 'options_timestamp_tsval', 'options_timestamp_tsecr',
    #  'analysis', 'analysis_acks_frame', 'analysis_ack_rtt', '', 'time_relative', 'time_delta']
    ft_lst[ft_dict['tcp.srcport']]=pk.tcp.srcport.hex_value
    ft_lst[ft_dict['tcp.dstport']]=pk.tcp.dstport.hex_value
    # ft_lst[ft_dict['tcp.seglen']]=int(pk.tcp.len)
    # ft_lst[ft_dict['tcp.seg_raw']]=int(pk.tcp.seq_raw)
    # ft_lst[ft_dict['tcp.ack_raw']]=int(pk.tcp.ack_raw)
    ft_lst[ft_dict['tcp.time_relative']]=float(pk.tcp.time_relative)
    ft_lst[ft_dict['tcp.time_delta']]=float(pk.tcp.time_delta)
    if ("MQTT" not in pk):
        detect_r = use_AI_model_detect_single_row(ft_lst)
        result_deque.append((true_r,detect_r))
        return 0
    
    #MQTT
    # ['hdrflags', 'msgtype', 'len']
    mqtt_layers = pk.get_multiple_layers('mqtt')
    mqtt_count=0
    for mqtt in mqtt_layers:
        new_ft_lst = ft_lst.copy()
        mqtt_count+=1
        new_ft_lst[ft_dict['mqtt.num']]=mqtt_count
        new_ft_lst[ft_dict['mqtt.hdrflags']]=mqtt.hdrflags.hex_value
        new_ft_lst[ft_dict['mqtt.msgtype']]=int(mqtt.msgtype)
        new_ft_lst[ft_dict['mqtt.len']]=int(mqtt.len)
        if len(mqtt.field_names) == 4:
            detect_r = use_AI_model_detect_single_row(new_ft_lst)
            res_lst.append((true_r,detect_r))
            continue
        if new_ft_lst[ft_dict['mqtt.msgtype']] == 1:
            #MQTT CONNECT
            #['hdrflags', 'msgtype', 'hdr_reserved', 'len', 'proto_len', 'protoname', 'ver', 'conflags', 'conflag_uname', 
            # 'conflag_passwd', 'conflag_retain', 'conflag_qos', 'conflag_willflag', 'conflag_cleansess', 'conflag_reserved', 
            # 'kalive', 'clientid_len', 'clientid', 'willtopic_len', 'willtopic', 'willmsg_len', 'willmsg'
            # , 'username_len', 'username', 'passwd_len', 'passwd']
            new_ft_lst[ft_dict['mqtt.proto_len']]=int(mqtt.proto_len)
            new_ft_lst[ft_dict['mqtt.protoname']]=1 if 'MQTT' in str(mqtt.protoname) else 0
            new_ft_lst[ft_dict['mqtt.ver']]=int(mqtt.ver)
            new_ft_lst[ft_dict['mqtt.conflags']]=mqtt.conflags.hex_value
            new_ft_lst[ft_dict['mqtt.conflag.uname']]= int(mqtt.conflag_uname)
            new_ft_lst[ft_dict['mqtt.conflag.passwd']]=int(mqtt.conflag_passwd)
            new_ft_lst[ft_dict['mqtt.conflag.willretain']]=int(mqtt.conflag_retain)
            new_ft_lst[ft_dict['mqtt.conflag.willqos']]=int(mqtt.conflag_qos)
            new_ft_lst[ft_dict['mqtt.conflag.willflag']]=int(mqtt.conflag_willflag)
            new_ft_lst[ft_dict['mqtt.conflag.cleansess']]=int(mqtt.conflag_cleansess)
            new_ft_lst[ft_dict['mqtt.conflag.reserved']]=int(mqtt.conflag_reserved)
            new_ft_lst[ft_dict['mqtt.kalive']]=mqtt.kalive.hex_value
            new_ft_lst[ft_dict['mqtt.clientid_len']]=int(mqtt.clientid_len)
            # if new_ft_lst[ft_dict['mqtt.clientid_len']] > 0:
            #     new_ft_lst[ft_dict['mqtt.clientid']] = str(mqtt.clientid)
            if new_ft_lst[ft_dict['mqtt.conflag.willflag']] == 1:
                new_ft_lst[ft_dict['mqtt.willtopic_len']]=int(mqtt.willtopic_len)
                # if new_ft_lst[ft_dict['mqtt.willtopic_len']]>0:
                #     new_ft_lst[ft_dict['mqtt.willtopic']]=str(mqtt.willtopic)
                new_ft_lst[ft_dict['mqtt.willmsg_len']]=int(mqtt.willmsg_len)
                # if new_ft_lst[ft_dict['mqtt.willmsg_len']]>0:
                #     new_ft_lst[ft_dict['mqtt.willmsg']]=str(mqtt.willmsg)
            if new_ft_lst[ft_dict['mqtt.conflag.uname']] == 1:
                new_ft_lst[ft_dict['mqtt.username_len']]=int(mqtt.username_len)
                # if new_ft_lst[ft_dict['mqtt.username_len']]>0:
                #     new_ft_lst[ft_dict['mqtt.username']]=str(mqtt.username)
            if new_ft_lst[ft_dict['mqtt.conflag.passwd']] == 1:
                new_ft_lst[ft_dict['mqtt.passwd_len']]=int(mqtt.passwd_len)
                # if new_ft_lst[ft_dict['mqtt.passwd_len']]>0:
                #     new_ft_lst[ft_dict['mqtt.passwd']]=str(mqtt.passwd)

        elif new_ft_lst[ft_dict['mqtt.msgtype']] == 2:
            #MQTT CONACK
            # ['hdrflags', 'msgtype', 'hdr_reserved', 'len', 'conack_flags', 'conack_flags_reserved', 
            #  'conack_flags_sp', 'conack_val']
            new_ft_lst[ft_dict['mqtt.conack.flags']] = mqtt.conack_flags.hex_value
            new_ft_lst[ft_dict['mqtt.conact.flags.sp']] = int(mqtt.conack_flags_sp)
            if 'conack_val' in mqtt.field_names:
                new_ft_lst[ft_dict['mqtt.conack.val']] = int(mqtt.conack_val)
            
        elif new_ft_lst[ft_dict['mqtt.msgtype']] == 3:
            #MQTT PUBLISH
            #['hdrflags', 'msgtype', 'dupflag', 'qos', 'retain', 'len', 'topic_len', 'topic', 'msgid', 'msg']
            new_ft_lst[ft_dict['mqtt.dupflag']]= int(mqtt.dupflag)
            new_ft_lst[ft_dict['mqtt.qos']]=int(mqtt.qos)
            new_ft_lst[ft_dict['mqtt.retain']]=int(mqtt.retain)
            new_ft_lst[ft_dict['mqtt.topic_len']]=int(mqtt.topic_len)
            # if new_ft_lst[ft_dict['mqtt.topic_len']] > 0 and \
            #         new_ft_lst[ft_dict['mqtt.topic_len']] < new_ft_lst[ft_dict['mqtt.len']] and \
            #         'topic' in mqtt.field_names:
            #     new_ft_lst[ft_dict['mqtt.topic']]=str(mqtt.topic)
            msgid_len = 0
            if new_ft_lst[ft_dict['mqtt.qos']] != 0 and \
                    'msgid' in mqtt.field_names:
                msgid_len = 2
                # new_ft_lst[ft_dict['mqtt.msgid']]=int(mqtt.msgid)
            msglen = new_ft_lst[ft_dict['mqtt.len']] - 2 - new_ft_lst[ft_dict['mqtt.topic_len']] - msgid_len
            if msglen > 0:
                new_ft_lst[ft_dict['mqtt.msglen']] = msglen
                # if  'msg' in mqtt.field_names:
                #     new_ft_lst[ft_dict['mqtt.msg']] = str(mqtt.msg)
            else:
                new_ft_lst[ft_dict['mqtt.msglen']] = 0
            
        # elif new_ft_lst[ft_dict['mqtt.msgtype']] in [4,5,6,7,11]:
            #MQTT PUBACK, PUBREC, PUBREL, PUBCOMP, UNSUBACK
            #['hdrflags', 'msgtype', 'hdr_reserved', 'len', 'msgid']
            # if 'msgid' in mqtt.field_names :
            #     new_ft_lst[ft_dict['mqtt.msgid']]=int(mqtt.msgid)

        elif new_ft_lst[ft_dict['mqtt.msgtype']] == 8:
            #MQTT SUBSCRIBE
            #['hdrflags', 'msgtype', 'hdr_reserved', 'len', 'msgid', 'topic_len', 'topic', 'sub_qos']
            # if 'msgid' in mqtt.field_names:
            #     new_ft_lst[ft_dict['mqtt.msgid']]=int(mqtt.msgid)
            new_ft_lst[ft_dict['mqtt.topic_len']]=int(mqtt.topic_len)
            # if new_ft_lst[ft_dict['mqtt.topic_len']] > 0 and \
            #         'topic' in mqtt.field_names:
            #     new_ft_lst[ft_dict['mqtt.topic']]=str(mqtt.topic)
            if 'sub_qos' in mqtt.field_names:
                new_ft_lst[ft_dict['mqtt.sub.qos']] = int(mqtt.sub_qos)
            
        elif new_ft_lst[ft_dict['mqtt.msgtype']] == 9:
            #MQTT SUBACK
            #['hdrflags', 'msgtype', 'hdr_reserved', 'len', 'msgid', 'suback_qos']
            # if 'msgid' in mqtt.field_names:
            #     new_ft_lst[ft_dict['mqtt.msgid']]=int(mqtt.msgid)
            new_ft_lst[ft_dict['mqtt.suback.qos']] = int(mqtt.suback_qos)

        elif new_ft_lst[ft_dict['mqtt.msgtype']] == 10:
            print(mqtt.field_names)
            #MQTT UNSUBSCRIBE       
            # ['hdrflags', 'msgtype', 'hdr_reserved', 'len', 'msgid', 'topic_len', 'topic']
            # if 'msgid' in mqtt.field_names:
            #     new_ft_lst[ft_dict['mqtt.msgid']]=int(mqtt.msgid)
            new_ft_lst[ft_dict['mqtt.topic_len']]=int(mqtt.topic_len)
            # if new_ft_lst[ft_dict['mqtt.topic_len']] > 0 and \
            #         'topic' in mqtt.field_names:
            #     new_ft_lst[ft_dict['mqtt.topic']]=str(mqtt.topic)
    
        # elif new_ft_lst[ft_dict['mqtt.msgtype']] in [12,13,14]:
            #MQTT PINGREQ, PINGRESP, DISCONNECT
        # else:
        #     #pk_lstMQTT Reserved

        detect_r = use_AI_model_detect_single_row(new_ft_lst)
        res_lst.append((true_r,detect_r))
    result_deque.extend(res_lst)
    has_result_event.set()

###############################################################################

def signal_handler(*args):
    cur_thrd = threading.current_thread()
    if cur_thrd.daemon == False:
        #if main thread, stop capture
        global STOP_CAPTURE
        STOP_CAPTURE = True

        print('wait pk_thread to finish')
        for thrd in threading.enumerate():
            if thrd.daemon == True and thrd.name=='FeT':
                thrd.join()
        
        global STOP_OUTPUT
        STOP_OUTPUT=True
        global has_result_event
        has_result_event.set()
        print('wait output thread to finish')
        global out_thrd
        out_thrd.join()

        # dump data if exist
        if len(result_deque) > 0:
            global csvfile
            n = len(result_deque)
            rows = [result_deque.popleft() for i in range(n)]
            with open(csvfile,'a') as f:
                writer = csv.writer(f)
                writer.writerows(rows)
            print('dumped last rows:',n)

        global pk_count
        print("total:",pk_count," packet")

# signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

###############################################################################

def write_queue_to_file(filename):
    global result_deque
    global has_result_event
    while STOP_OUTPUT==False:
        has_result_event.wait()
        n = len(result_deque)
        rows = [result_deque.popleft() for i in range(n)]
        has_result_event.clear()
        with open(filename,'a') as f:
            writer = csv.writer(f)
            writer.writerows(rows)

#capture TCP
def capture_live_packets(network_interface):
    '''capture live packet and create thread to process packet'''
    global STOP_CAPTURE
    global pk_count
    capture = pyshark.LiveCapture(interface=network_interface,display_filter='tcp')
    now = time.time()
    start_time = now
    lastpk_time = start_time
    for raw_packet in capture.sniff_continuously():
        lastpk_time = now
        now = time.time()
        if STOP_CAPTURE == False:
            try:
                pk_thrd = Thread(target=packet_to_lists,args=(raw_packet,start_time,lastpk_time,now),daemon=True,name='FeT')
                pk_thrd.start()
            except:
                traceback.print_exc()
                print(raw_packet)
        else:
            break
        pk_count+=1
        if pk_count % 1000 == 0:
            print(pk_count,"packets tested")

print('Start Output thread')
out_thrd = Thread(target=write_queue_to_file,args=(csvfile,),daemon=True,name='Output')
out_thrd.start()

print('Start pyshark sniff and detect')
capture_live_packets('ogstun')
