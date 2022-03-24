# -*- coding: utf-8 -*-
# !/usr/bin/env python


import subprocess
import numpy as np
import threading
import time
import http.client
import urllib.parse
import datetime
import socket
import pickle
import struct
import copy
import json
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
payload = ''
headers = {
  'Connection': 'keep-alive'
}

ccNameMap = {0: "bbr",
             1: "cubic",
             2: "illinois",
             3: "c2tcp",
             4: "westwood",
             5: "vegas"}


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
        self.changeCong = CDLL('./test.so')


    def runTshark(self):
        ## -l 很重要，表示每个包都会output
        cmd = ['/usr/src/python/mytcpack.py']
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
            # 定义一个空字典
            # print(str(self.read)+"  write: "+str(self.write))
            if self.read < self.write:
                line = self.buffer[self.read % self.bufferSize]
                readData = self.getData(line)
                key = readData['port']
                self.read += 1
                # print ("\n\n" + str(self.read) + "readData: " + str(readData))
                # 组合数据
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
                        if ("max_pacing_rate" not in self.flowStaticData[key] or
                                self.flowStaticData[key]['max_pacing_rate'] == 0):
                            self.flowStaticData[key]['max_pacing_rate'] = int(readData['pacing_rate'])
                        else:
                            self.flowStaticData[key]['max_pacing_rate'] = max(int(readData['pacing_rate']),
                                                                              self.flowStaticData[key][
                                                                                  'max_pacing_rate'])

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

    # 使用远端算法进行预测
    def predicCC(self, trainData, key):
        data = trainData
        termTrainData = [int(data['minRTT']), float(data['mdevRTT']), float(data['meanRTT']), float(data['maxRTT']),
                         float(data['throughput']), float(data['lost']), float(data['meanPacingRate'])]

        t = time.time()
        beginTime = int(round(t * 1000))
        con.request("GET", "/predict?param=%5B"+str(termTrainData[0])+","+str(termTrainData[1])+","
                    +str(termTrainData[2])+","+str(termTrainData[3])+","+str(termTrainData[4])+","+str(termTrainData[5])
                                                                           +","+str(termTrainData[6])+"%5D", payload, headers)
        resu = (con.getresponse()).read()
        pre_result = json.loads(resu)
        result = pre_result['result']
        endTime = int(round(time.time()* 1000))
        print("predict time: " + str(endTime-beginTime))
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
        # print("destination: " + str(data['Destination'].split(":")[-1]))
        ipKey = struct.unpack('!I', socket.inet_aton(data['Destination'].split(":")[-1]))[0]
        ipPredic = self.calIPPred(int(ipKey), int(result))
        # 因为python无法向c传递long和string，于是就将long拆分后进行传输
        beishu = int(ipKey) / 1000
        yushu = int(ipKey) % 1000

        print("update!!!!!!!!!!!!!"+str(ccArray))
        self.changeCong.updateCongHash(int(key), int(beishu), int(yushu), int(result), int(ipPredic))
        return result
    # 每隔一段时间，进行数据流统计，并计算reward值
    def intervalAction(self, countIndex, key):

        # 计算本时间段的统计数据
        preCountIndex = countIndex - 1
        preTrainKey = key + "_" + str(preCountIndex)
        trainKey = key + "_" + str(countIndex)
        preTrainData = None
        if preTrainKey in self.trainLawData:
            preTrainData = self.trainLawData[preTrainKey]
        # 计算本时间段的统计数据
        data = self.calTrainData(key, preTrainData)
        print("countIndex: " + str(countIndex) + " rtt: " + str(data['meanRTT']))
        beta = 512
        if countIndex < 9:
            beta = pow(2, countIndex)

        if data['minRTT'] * beta > data['meanRTT']:
            rtt = data['minRTT']
        else:
            rtt = data['meanRTT']

        # 计算上个时间段的reward数据，并将其放入到上个时间段的统计数据中
        if preTrainKey in self.trainLawData:
            reward = self.calReward(data, rtt)
            self.trainLawData[preTrainKey]['result'] = reward

        if "last" not in self.flowStaticData[key]:
            trainKey = key + "_" + str(countIndex)
            self.trainLawData[trainKey] = data
            self.trainLawData[trainKey]['rtt'] = rtt
            # 将预测的结果存入统计数据
            self.trainLawData[trainKey]['predictCC'] = self.predicCC(data, key)

    def calTrainData(self, key, preData):
        result = {}
        maxDelivered = np.max(self.flowStaticData[key]['delivered'])
        if preData is None:
            transTime = self.flowStaticData[key]['time'] - self.flowStaticData[key]['beginTime']
            delivered = maxDelivered
            # print("time" + str(self.flowStaticData[key]['time']) + " beginTime:" + str(
            # self.flowStaticData[key]['beginTime']))
        else:
            transTime = self.flowStaticData[key]['time'] - preData['time']
            delivered = maxDelivered- preData['delivered']
            # print("time" + str(self.flowStaticData[key]['time']) + " beginTime:" + str(preData['time']))

        if transTime == 0:
            throughput = float(delivered)
        else:
            throughput = float(delivered) / float(transTime)
        # print(" transTime" + str(transTime) + " delivered" + str(delivered) + " through: " + str(throughput))
        # print("cwnd: " + str(sndCwnd))
        result['Destination'] = self.flowStaticData[key]['Destination']

        result['meanPacingRate'] = np.mean(self.flowStaticData[key]['pacing_rate'])
        result['time'] = self.flowStaticData[key]['time']
        result['delivered'] = maxDelivered
        # print("rtt: " + str(self.flowStaticData[key]['rtt']))
        result['meanRTT'] = np.mean(self.flowStaticData[key]['rtt'])
        result["maxRTT"] = self.flowStaticData[key]['maxRTT']
        result['95th'] = np.percentile(self.flowStaticData[key]['rtt'], 95)
        result['minRTT'] = self.flowStaticData[key]['minRTT']
        result['mdevRTT'] = self.flowStaticData[key]['mdevRTT']
        result['retrans'] = self.flowStaticData[key]['retrans']
        result['lost'] = self.flowStaticData[key]['lost']
        result['max_pacing_rate'] = self.flowStaticData[key]['max_pacing_rate']
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

        # 输出到文件中
        for cc in trainDataCCMap.keys():
            if (trainDataCCMap[cc].__len__() > 0):
                fileName = "/usr/src/qiuxinyi/python/traindata/"+ccNameMap[cc]+"_output.txt"
                self.writeData(fileName, trainDataCCMap[cc])
        print("write end " + str(delKeys))
        for key in delKeys:
            print("delKey: " + key)
            del self.trainLawData[key]
        lock.release()

    def writeData(self, path, data):

        # print("\nwrite data: " + str(data))
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
        reward = ((trainData['throughput'] * 1000-trainData['lost']) * trainData['minRTT']) / (rtt*trainData['max_pacing_rate'])
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

con = http.client.HTTPConnection('8.142.64.70:9088')
online = OnlineServer(200, "bbr")
tshark = tSharkThread(online)
read = readThread(online)
tshark.start()
read.start()
online.scheduleWriteJob()
tshark.join()
read.join()
#online.threadPool.shutdown(wait=True)