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

###############################################################################
#dataset folder
modelfolder = './captured_traffic/'

#feature to extract
featurenamefile = 'Feature_name.dat'
with open(featurenamefile) as file:
    feature_name = [line.rstrip() for line in file]
file.close()
ft_dict = {key: i for i, key in enumerate(feature_name)}
n_feature = len(feature_name)

# dataset_df = pd.DataFrame(columns=feature_name)
dataset_deque = deque([])
has_data_event = threading.Event()

dtime_str = datetime.now().strftime('%d-%m-%Y_%H%M')
csvfile = modelfolder + 'captured_dataset_'+dtime_str+'.csv'

#stop signal and stop ack
STOP_CAPTURE = False
STOP_OUTPUT = False

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

#packet to list
def packet_to_lists(pk,time_start,time_previous,time_now):
    '''process packet and put to queue'''
    global feature_name
    global n_feature
    global dataset_deque
    global has_data_event
    pk_lst = []
    ft_lst = [None] * n_feature
    ft_lst[ft_dict['frame.time_delta']]=time_now-time_previous
    ft_lst[ft_dict['frame.time_relative']]=time_now-time_start
    #IP
    #['version', 'hdr_len', 'dsfield', 'dsfield_dscp', 'dsfield_ecn', 'len', 'id', 'flags', 
    # 'flags_rb', 'flags_df', 'flags_mf', 'frag_offset', 'ttl', 'proto', 'checksum', 'checksum_status', 
    # 'src', 'addr', 'src_host', 'host', 'dst', 'dst_host']
    #pk.ip.version.int_value
    ft_lst[ft_dict['ip.len']]=pk.ip.len.hex_value
    ft_lst[ft_dict['ip.protocol']]=pk.ip.proto.hex_value
    ft_lst[ft_dict['ip.src']]=pk.ip.src.show
    ft_lst[ft_dict['ip.dst']]=pk.ip.dst.show
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
        dataset_deque.append(ft_lst)
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
        if new_ft_lst[ft_dict['mqtt.msgtype']] == 1:
            #MQTT CONNECT
            #['hdrflags', 'msgtype', 'hdr_reserved', 'len', 'proto_len', 'protoname', 'ver', 'conflags', 'conflag_uname', 
            # 'conflag_passwd', 'conflag_retain', 'conflag_qos', 'conflag_willflag', 'conflag_cleansess', 'conflag_reserved', 
            # 'kalive', 'clientid_len', 'clientid', 'willtopic_len', 'willtopic', 'willmsg_len', 'willmsg'
            # , 'username_len', 'username', 'passwd_len', 'passwd']
            new_ft_lst[ft_dict['mqtt.proto_len']]=int(mqtt.proto_len)
            new_ft_lst[ft_dict['mqtt.protoname']]=str(mqtt.protoname)
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
            if new_ft_lst[ft_dict['mqtt.clientid_len']] > 0:
                new_ft_lst[ft_dict['mqtt.clientid']] = str(mqtt.clientid)
            if new_ft_lst[ft_dict['mqtt.conflag.willflag']] == 1:
                new_ft_lst[ft_dict['mqtt.willtopic_len']]=int(mqtt.willtopic_len)
                if new_ft_lst[ft_dict['mqtt.willtopic_len']]>0:
                    new_ft_lst[ft_dict['mqtt.willtopic']]=str(mqtt.willtopic)
                new_ft_lst[ft_dict['mqtt.willmsg_len']]=int(mqtt.willmsg_len)
                if new_ft_lst[ft_dict['mqtt.willmsg_len']]>0:
                    new_ft_lst[ft_dict['mqtt.willmsg']]=str(mqtt.willmsg)
            if new_ft_lst[ft_dict['mqtt.conflag.uname']] == 1:
                new_ft_lst[ft_dict['mqtt.username_len']]=int(mqtt.username_len)
                if new_ft_lst[ft_dict['mqtt.username_len']]>0:
                    new_ft_lst[ft_dict['mqtt.username']]=str(mqtt.username)
            if new_ft_lst[ft_dict['mqtt.conflag.passwd']] == 1:
                new_ft_lst[ft_dict['mqtt.passwd_len']]=int(mqtt.passwd_len)
                if new_ft_lst[ft_dict['mqtt.passwd_len']]>0:
                    new_ft_lst[ft_dict['mqtt.passwd']]=str(mqtt.passwd)

        elif new_ft_lst[ft_dict['mqtt.msgtype']] == 2:
            #MQTT CONACK
            # ['hdrflags', 'msgtype', 'hdr_reserved', 'len', 'conack_flags', 'conack_flags_reserved', 
            #  'conack_flags_sp', 'conack_val']
            new_ft_lst[ft_dict['mqtt.conack.flags']] = mqtt.conack_flags.hex_value
            new_ft_lst[ft_dict['mqtt.conact.flags.sp']] = int(mqtt.conack_flags_sp)
            new_ft_lst[ft_dict['mqtt.conack.val']] = int(mqtt.conack_val)
            
        elif new_ft_lst[ft_dict['mqtt.msgtype']] == 3:
            #MQTT PUBLISH
            #['hdrflags', 'msgtype', 'dupflag', 'qos', 'retain', 'len', 'topic_len', 'topic', 'msgid', 'msg']
            new_ft_lst[ft_dict['mqtt.dupflag']]= int(mqtt.dupflag)
            new_ft_lst[ft_dict['mqtt.qos']]=int(mqtt.qos)
            new_ft_lst[ft_dict['mqtt.retain']]=int(mqtt.retain)
            new_ft_lst[ft_dict['mqtt.topic_len']]=int(mqtt.topic_len)
            if new_ft_lst[ft_dict['mqtt.topic_len']] > 0:
                new_ft_lst[ft_dict['mqtt.topic']]=str(mqtt.topic)
            msgid_len = 0
            if new_ft_lst[ft_dict['mqtt.qos']] != 0:
                msgid_len = 2
                new_ft_lst[ft_dict['mqtt.msgid']]=int(mqtt.msgid)
            msglen = new_ft_lst[ft_dict['mqtt.len']] - 2 - new_ft_lst[ft_dict['mqtt.topic_len']] - msgid_len
            if msglen > 0 :
                new_ft_lst[ft_dict['mqtt.msglen']] = msglen
                new_ft_lst[ft_dict['mqtt.msg']] = str(mqtt.msg)
            else:
                new_ft_lst[ft_dict['mqtt.msglen']] = 0
            
        elif new_ft_lst[ft_dict['mqtt.msgtype']] in [4,5,6,7,11]:
            #MQTT PUBACK, PUBREC, PUBREL, PUBCOMP, UNSUBACK
            #['hdrflags', 'msgtype', 'hdr_reserved', 'len', 'msgid']
            new_ft_lst[ft_dict['mqtt.msgid']]=int(mqtt.msgid)

        elif new_ft_lst[ft_dict['mqtt.msgtype']] == 8:
            #MQTT SUBSCRIBE
            #['hdrflags', 'msgtype', 'hdr_reserved', 'len', 'msgid', 'topic_len', 'topic', 'sub_qos']
            new_ft_lst[ft_dict['mqtt.msgid']]=int(mqtt.msgid)
            new_ft_lst[ft_dict['mqtt.topic_len']]=int(mqtt.topic_len)
            if new_ft_lst[ft_dict['mqtt.topic_len']] > 0:
                new_ft_lst[ft_dict['mqtt.topic']]=str(mqtt.topic)
            new_ft_lst[ft_dict['mqtt.sub.qos']] = int(mqtt.sub_qos)
            
        elif new_ft_lst[ft_dict['mqtt.msgtype']] == 9:
            #MQTT SUBACK
            #['hdrflags', 'msgtype', 'hdr_reserved', 'len', 'msgid', 'suback_qos']
            new_ft_lst[ft_dict['mqtt.msgid']]=int(mqtt.msgid)
            new_ft_lst[ft_dict['mqtt.suback.qos']] = int(mqtt.suback_qos)

        elif new_ft_lst[ft_dict['mqtt.msgtype']] == 10:
            print(mqtt.field_names)
            #MQTT UNSUBSCRIBE       
            # ['hdrflags', 'msgtype', 'hdr_reserved', 'len', 'msgid', 'topic_len', 'topic']
            new_ft_lst[ft_dict['mqtt.msgid']]=int(mqtt.msgid)
            new_ft_lst[ft_dict['mqtt.topic_len']]=int(mqtt.topic_len)
            if new_ft_lst[ft_dict['mqtt.topic_len']] > 0:
                new_ft_lst[ft_dict['mqtt.topic']]=str(mqtt.topic)
    
        # elif new_ft_lst[ft_dict['mqtt.msgtype']] in [12,13,14]:
            #MQTT PINGREQ, PINGRESP, DISCONNECT
        # else:
        #     #pk_lstMQTT Reserved
        pk_lst.append(new_ft_lst)
    dataset_deque.extend(pk_lst)
    has_data_event.set()

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
        global has_data_event
        has_data_event.set()
        print('wait output thread to finish')
        global out_thrd
        out_thrd.join()

        # dump data if exist
        if len(dataset_deque) > 0:
            global csvfile
            n = len(dataset_deque)
            rows = [dataset_deque.popleft() for i in range(n)]
            with open(csvfile,'a') as f:
                writer = csv.writer(f)
                writer.writerows(rows)
            print('dumped last rows',n)

# signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

###############################################################################

def write_queue_to_file(filename):
    global dataset_deque
    global has_data_event
    while STOP_OUTPUT==False:
        has_data_event.wait()
        n = len(dataset_deque)
        rows = [dataset_deque.popleft() for i in range(n)]
        has_data_event.clear()
        with open(filename,'a') as f:
            writer = csv.writer(f)
            writer.writerows(rows)

#capture TCP
def capture_live_packets(network_interface):
    '''capture live packet and create thread to process packet'''
    global STOP_CAPTURE
    capture = pyshark.LiveCapture(interface=network_interface,display_filter='tcp')
    now = time.time()
    start_time = now
    lastpk_time = start_time
    for raw_packet in capture.sniff_continuously():
        lastpk_time = now
        now = time.time()
        if STOP_CAPTURE == False:
            pk_thrd = Thread(target=packet_to_lists,args=(raw_packet,start_time,lastpk_time,now),daemon=True,name='FeT')
            pk_thrd.start()
        else:
            break

try:
    out_thrd = Thread(target=write_queue_to_file,args=(csvfile,),daemon=True,name='Output')
    out_thrd.start()

    capture_live_packets('ogstun')
except:
    traceback.print_exc()