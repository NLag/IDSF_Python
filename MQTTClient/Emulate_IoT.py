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

randomdelayinterval = [356, 374, 593, 43, 132, 414, 356, 305, 175, 32, 186, 585, 518, 505, 139, 197, 128, 449, 420, 318, 276, 377, 363, 56, 12, 322, 329, 548, 304, 196, 176, 537, 105, 557, 16, 80, 59, 194, 595, 78, 307, 484, 336, 385, 448, 504, 529, 245, 36, 271, 94, 493, 231, 557, 87, 394, 267, 40, 144, 425, 583, 348, 253, 233, 540, 452, 11, 260, 56, 247, 322, 435, 309, 462, 221, 170, 177, 179, 215, 271, 340, 93, 151, 487, 572, 191, 116, 108, 223, 189, 484, 590, 336, 76, 441, 391, 112, 121, 211, 517, 341, 598, 219, 35, 546, 538, 595, 319, 511, 518, 588, 330, 247, 266, 564, 477, 15, 238, 410, 371, 557, 18, 248, 579, 309, 586, 61, 307, 462, 313, 196, 250, 403, 536, 206, 312, 44, 144, 20, 227, 540, 261, 327, 536, 50, 162, 323, 530, 387, 459, 269, 210, 203, 472, 356, 358, 403, 91, 338, 371, 346, 191, 179, 282, 515, 460, 136, 225, 318, 461, 412, 583, 245, 346, 460, 526, 77, 500, 522, 323, 111, 545, 317, 165, 407, 32, 142, 476, 218, 470, 366, 108, 371, 249, 592, 48, 452, 158, 529, 330]

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
        shorts.append(Process(target = mqttShortIntervalClient, args = (rtopic, randomdelayinterval[i],rand.randint(0,2))))
        shorts[i].start()
    for i in range(NUMBER_OF_RANDOM_INTERVAL_CLIENTS):
        rtopic = get_random_string(rand.randint(1,100))
        randoms.append(Process(target = mqttRandomIntervalClient, args = (rtopic, rand.randint(10, 600))))
        randoms[i].start()
    print('Main Process terminated')
    #print(shorts)
    #print(randoms)