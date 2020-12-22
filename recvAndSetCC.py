# -*- coding: utf-8 -*-
# !/usr/bin/env python


import subprocess
import numpy as np
import threading
import time
import datetime
import socket
import pickle
import struct
import copy
import threadpool
from ctypes import *
from apscheduler.schedulers.blocking import BlockingScheduler
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED

lock = threading.Lock()
ipCongMap = {}
predicMap = {}
preCCMap = {}
alf = 0.9
timeInterval = 1
maxPactingRate = 4294967295

ccNameMap = {0: "bbr",
             1: "cubic",
             2: "illinois",
             3: "c2tcp",
             4: "westwood",
             5: "vegas"}

ccFileMap = {0: "/usr/src/python/traindata/bbr.pickle",
             1: "/usr/src/python/traindata/cubic.pickle",
             2: "/usr/src/python/traindata/illinois.pickle",
             3: "/usr/src/python/traindata/c2tcp.pickle",
             4: "/usr/src/python/traindata/westwood.pickle",
             5: "/usr/src/python/traindata/vegas.pickle"
             }
pickleMap = {}


class OnlineServer:
    def __init__(self, bufferSize, ccName):
        self.bufferSize = bufferSize
        self.buffer = []
        self.read = 0
        self.write = 0
        self.ccName = ccName
        self.sigma = 1
        self.threadPool = ThreadPoolExecutor(max_workers=4)
        self.staticCount = 20
        self.trainLawData = {}
        self.flowStaticData = {}
        self.flowStaticData[0] = {}
        self.changeCong = CDLL('./transfer_cc.so')
        for cc in ccFileMap:
            with open(ccFileMap[cc], "rb") as fr:
                p = pickle.load(fr)
                pickleMap[cc] = p

    def runTshark(self):
        cmd = ['/usr/src/python/getSocketInfo.py']
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)

        while True:
            try:
                lawline = proc.stdout.readline()
                line = str(lawline, encoding="utf-8")
                line = line.strip()

                if not line:
                    None
                else:
                    if self.write < self.bufferSize:
                        self.buffer.append(line)
                        self.write += 1
                    else:
                        index = self.write % self.bufferSize
                        self.buffer[index] = line
                        self.write += 1
            except Exception as e:
                print("run shell error" + str(e))

    def getData(self, line):
        data = {}
        param = line.split(";")
        # print ("param: " + str(param))
        data['Destination'] = param[3]
        data['Source'] = param[1]
        data['time'] = int(param[0])
        data['delivered'] = param[18]
        data['rtt'] = int(param[5])
        data['mdevRtt'] = int(param[6])
        data['minRtt'] = int(param[7])
        data['bytes_in_flight'] = int(param[8])
        data['port'] = param[4]
        data['lost'] = int(param[9])
        data['retrans'] = int(param[10])
        data['rcv_buf'] = param[11]
        data['snd_buf'] = int(param[12])
        data['snd_cwnd'] = int(param[13])
        data['status'] = param[14]
        data['pacing_rate'] = param[16]
        data['max_pacing_rate'] = param[17]
        return data

    def calIPPred(self, ipKey, val):
        congVal = ipCongMap.get(ipKey, [0, 0, 0, 0])
        for index in range(len(congVal)):
            congVal[index] *= alf
        congVal[val] += 1
        ipCongMap[ipKey] = congVal
        predic = int(congVal.index(max(congVal)))
        print("ipKey: " + str(ipKey) + " ip predic: " + str(predic))
        print(str(ipCongMap))
        return predic

    def readPacketData(self):

        while True:
            if self.read < self.write:
                line = self.buffer[self.read % self.bufferSize]
                readData = self.getData(line)
                key = readData['port']
                self.read += 1
                try:
                    if key not in self.flowStaticData:
                        self.flowStaticData[key] = self.newFlowStaticData()
                        t = time.time()
                        self.flowStaticData[key]['beginTime'] = int(round(t * 1000))
                    elif readData['status'].__contains__("LAST_ACK"):
                        print("enter last")
                        self.flowStaticData[key]['last'] = True
                        t = time.time()
                        self.flowStaticData[key]['time'] = int(round(t * 1000))
                        self.intervalAction(self.flowStaticData[key]['countIndex'], key)
                        del self.flowStaticData[key]
                        del predicMap[key]
                        del preCCMap[key]

                    if key in self.flowStaticData:
                        self.flowStaticData[key]['delivered'].append(int(readData['delivered']))
                        self.flowStaticData[key]['rcvBuf'].append(int(readData['rcv_buf']))
                        self.flowStaticData[key]['sndBuf'].append(int(readData['snd_buf']))
                        self.flowStaticData[key]['sndCwnd'].append(int(readData['snd_cwnd']))
                        self.flowStaticData[key]['rtt'].append(int(readData['rtt']))
                        self.flowStaticData[key]['Destination'] = readData['Destination']
                        self.flowStaticData[key]['minRTT'] = readData['minRtt']
                        self.flowStaticData[key]['mdevRTT'] = readData['mdevRtt']
                        self.flowStaticData[key]['bytesInFlight'].append(int(readData['bytes_in_flight']))
                        self.flowStaticData[key]['lost'] = readData['lost']
                        self.flowStaticData[key]['retrans'] = readData['retrans']
                        self.flowStaticData[key]['pacing_rate'].append(int(readData['pacing_rate']))
                        self.flowStaticData[key]['max_pacing_rate'] = int(readData['max_pacing_rate'])
                        self.flowStaticData[key]['number'] += 1
                        if self.flowStaticData[key]['number'] > self.staticCount:
                            t = time.time()
                            self.flowStaticData[key]['time'] = int(round(t * 1000))
                            countIndex = self.flowStaticData[key]['countIndex']
                            self.intervalAction(countIndex, key)
                            self.flowStaticData[key] = self.newFlowStaticData()
                            countIndex += 1
                            self.flowStaticData[key]['countIndex'] = countIndex
                except Exception as e:
                    print("error: " + str(e))

    def newFlowStaticData(self):
        flowStaticPerData = {}
        flowStaticPerData['time'] = 0
        flowStaticPerData['delivered'] =[]
        flowStaticPerData['Destination'] = ""
        flowStaticPerData['bytesInFlight'] = []
        flowStaticPerData['rcvBuf'] = []
        flowStaticPerData['sndBuf'] = []
        flowStaticPerData['pacing_rate'] = []
        flowStaticPerData['countIndex'] = 0
        flowStaticPerData['max_pacing_rate'] = 0
        flowStaticPerData['sndCwnd'] = []
        flowStaticPerData['rtt'] = []
        flowStaticPerData["retrans"] = 0
        flowStaticPerData["lost"] = 0
        flowStaticPerData["maxRTT"] = 0
        flowStaticPerData['minRTT'] = 0
        flowStaticPerData['mdevRTT'] = 0
        flowStaticPerData['number'] = 0
        flowStaticPerData['beginTime'] = 0
        return flowStaticPerData

    def runPredic(self,cc,rewards,npData):
        newModel = pickleMap[cc]
        y_pred = newModel.predict(npData).tolist()
        print("predic: " + str(y_pred) + " cc:" + str(cc))
        rewards[cc] = float(y_pred[0])

    def predicCC(self, trainData, key):
        data = trainData
        termTrainData = [int(data['minRTT']), float(data['mdevRTT']), float(data['meanRTT']), float(data['maxRTT']),
                         float(data['throughput']), float(data['lost']), float(data['meanPacingRate'])]

        npData = np.array(termTrainData).reshape(1, 7)
        rewards = {}
        allTask = []
        for cc in pickleMap:
            print("cc::"+str(cc))
            allTask.append(self.threadPool.submit(self.runPredic, cc, rewards,npData))
        wait(allTask, return_when=ALL_COMPLETED)
        result = max(rewards, key=rewards.get)
        print("result:" + str(ccNameMap[result]))


        if not predicMap.__contains__(key):
            ccArray = []
        else:
            ccArray = predicMap[key]

        if not preCCMap.__contains__(key):
            preCC = None
        else:
            preCC = preCCMap[key]

        ccArray.append(result)
        predicMap[key] = ccArray

        if (preCC is not None) and (preCC == result or ccArray[-2] != result):
            return preCC
        preCCMap[key] = result
        ipKey = struct.unpack('!I', socket.inet_aton(data['Destination'].split(":")[-1]))[0]
        ipPredic = self.calIPPred(int(ipKey), int(result))
        beishu = int(ipKey) / 1000
        yushu = int(ipKey) % 1000

        self.changeCong.updateCongHash(int(key), int(beishu), int(yushu), int(result), int(ipPredic))
        return result

    def intervalAction(self, countIndex, key):

        preCountIndex = countIndex - 1
        preTrainKey = key + "_" + str(preCountIndex)
        preTrainData = None
        if preTrainKey in self.trainLawData:
            preTrainData = self.trainLawData[preTrainKey]

        data = self.calTrainData(key, preTrainData)
        print("countIndex: " + str(countIndex) + " rtt: " + str(data['meanRTT']))
        beta = 512
        if countIndex < 9:
            beta = pow(2, countIndex)

        if data['minRTT'] * beta > data['meanRTT']:
            rtt = data['minRTT']
        else:
            rtt = data['meanRTT']


        if preTrainKey in self.trainLawData:
            reward = self.calReward(data, rtt)
            self.trainLawData[preTrainKey]['result'] = reward

        if "last" not in self.flowStaticData[key]:
            trainKey = key + "_" + str(countIndex)
            self.trainLawData[trainKey] = data
            self.trainLawData[trainKey]['rtt'] = rtt
            self.trainLawData[trainKey]['predictCC'] = self.predicCC(data, key)

    def calTrainData(self, key, preData):
        result = {}
        maxDelivered = np.max(self.flowStaticData[key]['delivered'])
        if preData is None:
            transTime = self.flowStaticData[key]['time'] - self.flowStaticData[key]['beginTime']
            delivered = maxDelivered

        else:
            transTime = self.flowStaticData[key]['time'] - preData['time']
            delivered = maxDelivered- preData['delivered']

        if transTime == 0:
            throughput = float(delivered)
        else:
            throughput = float(delivered) / float(transTime)
        result['Destination'] = self.flowStaticData[key]['Destination']

        result['meanPacingRate'] = np.mean(self.flowStaticData[key]['pacing_rate'])
        result['time'] = self.flowStaticData[key]['time']
        result['delivered'] = maxDelivered
        result['meanRTT'] = np.mean(self.flowStaticData[key]['rtt'])
        result["maxRTT"] = self.flowStaticData[key]['maxRTT']
        result['95th'] = np.percentile(self.flowStaticData[key]['rtt'], 95)
        result['minRTT'] = self.flowStaticData[key]['minRTT']
        result['mdevRTT'] = self.flowStaticData[key]['mdevRTT']
        result['retrans'] = self.flowStaticData[key]['retrans']
        result['lost'] = self.flowStaticData[key]['lost']
        result['throughput'] = throughput
        if preData is None or throughput > preData['maxThroughput']:
            result['maxThroughput'] = throughput
        else:
            result['maxThroughput'] = preData['maxThroughput']
        return result

    def bashWriteTrainData(self):
        lock.acquire()
        trainDataCCMap = {}
        delKeys = []
        keys = copy.deepcopy(list(self.trainLawData.keys()))

        for cc in ccNameMap.keys():
            trainDataCCMap[cc] = []

        print("\nbatchwrte: ")
        for key in keys:
            if "result" not in self.trainLawData[key].keys() or self.trainLawData[key]['result'] == '':
                continue
            delKeys.append(key)
            data = self.trainLawData[key]
            termTrainData = [int(data['minRTT']), float(data['mdevRTT']), float(data['meanRTT']),float(data['rtt']),
                             float(data['throughput']),float(data['lost']),float(data['meanPacingRate']),
                             float(data['result'])]

            trainDataCCMap[int(data['predictCC'])].append(termTrainData)
        for cc in trainDataCCMap.keys():
            if (trainDataCCMap[cc].__len__() > 0):
                fileName = "/usr/src/python/traindata/"+ccNameMap[cc]+"_output.txt"
                self.writeData(fileName, trainDataCCMap[cc])
        print("write end " + str(delKeys))
        for key in delKeys:
            print("delKey: " + key)
            del self.trainLawData[key]
        lock.release()

    def writeData(self, path, data):

        with open(path, 'a') as f:
            print("open path")
            try:
                writeData = np.array(data)
                np.savetxt(f, writeData, delimiter=" ")
            except Exception as e:
                print(e.message)

    def calReward(self, trainData, rtt):

        print(" meanRTT: " + str(trainData['meanRTT']) + " minRTT: " + str(
            trainData['minRTT']) + " rtt: " + str(rtt) + " max: " + str(trainData['maxThroughput']))
        reward = ((trainData['throughput']) * trainData['minRTT']) / rtt
        return reward

    def scheduleWriteJob(self):
        scheduler = BlockingScheduler()
        scheduler.add_job(self.bashWriteTrainData, 'interval', seconds=20, id='createData')
        scheduler.start()


class tSharkThread(threading.Thread):
    def __init__(self, object):
        threading.Thread.__init__(self, name='tshark')
        self.object = object

    def run(self):
        self.object.runTshark()


class readThread(threading.Thread):
    def __init__(self, object):
        threading.Thread.__init__(self, name='read')
        self.object = object

    def run(self):
        self.object.readPacketData()


def writeTrainData(path, object):
    object.bashWriteTrainData(path)


online = OnlineServer(200, "bbr")
tshark = tSharkThread(online)
read = readThread(online)
tshark.start()
read.start()
online.scheduleWriteJob()
tshark.join()
read.join()
