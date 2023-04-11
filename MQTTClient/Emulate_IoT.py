from multiprocessing import Process
import paho.mqtt.client as mqtt
import time
import random as rand
import string

TEST_TIME = 3600
NUMBER_OF_SHORT_INTERVAL_CLIENTS = 200
NUMBER_OF_RANDOM_INTERVAL_CLIENTS = 0
MOSQUITTO_IP = '192.168.57.4'
#'10.45.0.3'

CHARACTERS = string.ascii_letters + string.digits

def on_connect(client, userdata, flags, rc):
    print ("Connected with result code "+ str(rc))

def on_message(client, userdata, msg):
    print (msg.topic + ' ' + str(msg.payload))

def get_random_string(length):
    # With combination of lower and upper case
    result_str = ''.join(rand.choice(CHARACTERS) for i in range(length))
    # print random string
    return result_str

def mqttShortIntervalClient(id,delay,r_qos, variation = 2):
    time.sleep(delay)
    #print ('Short client '+ str(id)+' initiated with delay ' + str(delay))
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MOSQUITTO_IP, port=1883, keepalive=TEST_TIME)
    data_size = rand.randint(variation+1,100)
    data = get_random_string(data_size + variation)
    var_size = data_size

    startTime = int(time.time())
    while (int(time.time()) < (startTime + TEST_TIME)):
        client.publish(topic='short/'+id, payload=data[:var_size], qos=r_qos)
        var_size = data_size + rand.randrange(-variation,variation) # change size of payload by variation
        time.sleep(delay)
    client.disconnect()
    #print ('Short client '+ str(id)+' terminated')

def mqttRandomIntervalClient(id,delay):
    #print ('Random client '+ str(id)+' initiated')
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MOSQUITTO_IP, port=1883, keepalive=TEST_TIME)
    data = rand.randbytes(rand.randrange(20,64)) #used to be 100

    startTime = int(time.time())
    while (int(time.time()) < (startTime + TEST_TIME)):
        client.publish(topic='random/test'+str(id), payload=data, qos=0)
        data = rand.randbytes(rand.randrange(20,64)) #used to be 100
        time.sleep(rand.randint(0,delay))
    client.disconnect()
    #print ('Random client '+ str(id)+' terminated')

if __name__ == '__main__':
    print('Main Process initiated')
    shorts = []
    randoms = []
    for i in range(NUMBER_OF_SHORT_INTERVAL_CLIENTS):
        rtopic = get_random_string(rand.randint(1,100))
        shorts.append(Process(target = mqttShortIntervalClient, args = (rtopic, rand.randint(10, 600),rand.randint(0,2))))
        shorts[i].start()
    for i in range(NUMBER_OF_RANDOM_INTERVAL_CLIENTS):
        rtopic = get_random_string(rand.randint(1,100))
        randoms.append(Process(target = mqttRandomIntervalClient, args = (rtopic, rand.randint(10, 600))))
        randoms[i].start()
    print('Main Process terminated')
    #print(shorts)
    #print(randoms)