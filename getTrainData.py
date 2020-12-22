# -*- coding: utf-8 -*-
# !/usr/bin/env python


import subprocess
import numpy as np
import threading
import datetime
import socket
# import ModelTrain
import pickle
import struct
from ctypes import *
from apscheduler.schedulers.blocking import BlockingScheduler

lock = threading.Lock()

ipCongMap = {}
alf = 0.9
timeIndex = 0
timeMax = 1000
timeInterval = 1
maxPactingRate = 4294967295


class OnlineServer:
    def __init__(self, bufferSize, ccName):
        self.bufferSize = bufferSize
        self.buffer = []
        self.read = 0
        self.write = 0
        self.ccName = ccName
        self.sigma = 1
        self.trainLawData = {}
        self.flowStaticData = {}
        # self.changeCong = CDLL('./test.so')

    def runTshark(self):
        ## -l 很重要，表示每个包都会output
        cmd = ['/usr/src/qiuxinyi/python/mytcpack.py']
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)

        while True:
            try:
                lawline = proc.stdout.readline()
                line = str(lawline, encoding="utf-8")
                line = line.strip()

                if not line:
                    None
                else:
                    # print ("\nline: write: \n", line, self.write)
                    if self.write < self.bufferSize:
                        self.buffer.append(line)
                        self.write += 1
                    else:
                        index = self.write % self.bufferSize
                        self.buffer[index] = line
                        self.write += 1
                    # print "\nwrite: " + str(self.write)
            except Exception as e:
                print("run shell error" + str(e))

    def getData(self, line):
        data = {}
        param = line.split(";")
        #:qprint("param: " + str(param))
        data['Destination'] = param[3]
        data['Source'] = param[1]
        data['Time'] = int(param[0])
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
                        flowStatic = {}
                        flowStatic['time'] = []
                        flowStatic['bytesInFlight'] = []
                        flowStatic['rcvBuf'] = []
                        flowStatic['sndBuf'] = []
                        flowStatic['pacing_rate'] = []
                        flowStatic['max_pacing_rate'] = 0
                        flowStatic['sndCwnd'] = []
                        flowStatic['rtt'] = []
                        flowStatic["retrans"] = 0
                        flowStatic["lost"] = 0
                        flowStatic["maxRTT"] = 0
                        flowStatic['minRTT'] = 0
                        flowStatic['mdevRTT'] = 0
                        flowStatic['number'] = 0
                        flowStatic['beginTime'] = readData['Time']
                        self.flowStaticData[key] = flowStatic

                    elif readData['status'].__contains__("LAST_ACK"):
                        print("\nenter last ack")
                        data = self.calTrainData(key)
                        self.trainLawData[key] = data
                        # TODO 判断是否有优化趋势
                        self.trainLawData[key]['result'] = self.calReward(data)
                        print("\ntrain" + str(self.trainLawData[key]))
                        del self.flowStaticData[key]

                    if key in self.flowStaticData:
                        self.flowStaticData[key]['time'].append(int(readData['Time']))
                        self.flowStaticData[key]['rcvBuf'].append(int(readData['rcv_buf']))
                        self.flowStaticData[key]['sndBuf'].append(int(readData['snd_buf']))
                        self.flowStaticData[key]['sndCwnd'].append(int(readData['snd_cwnd']))
                        self.flowStaticData[key]['rtt'].append(int(readData['rtt']))

                        self.flowStaticData[key]['minRTT'] = readData['minRtt']
                        if int(self.flowStaticData[key]['maxRTT']) < int(readData['rtt']):
                            self.flowStaticData[key]['maxRTT'] = readData['rtt']

                        self.flowStaticData[key]['mdevRTT'] = readData['mdevRtt']
                        self.flowStaticData[key]['bytesInFlight'].append(int(readData['bytes_in_flight']))
                        self.flowStaticData[key]['lost'] = readData['lost']
                        self.flowStaticData[key]['retrans'] = readData['retrans']
                        self.flowStaticData[key]['pacing_rate'].append(int(readData['pacing_rate']))
                        if int(readData['pacing_rate']) != maxPactingRate and self.flowStaticData[key][
                            'max_pacing_rate'] < int(readData['pacing_rate']):
                            self.flowStaticData[key]['max_pacing_rate'] = int(readData['pacing_rate'])
                        self.flowStaticData[key]['number'] += 1

                except Exception as e:
                    print("error: " + str(e))

    def calTrainData(self, key):
        result = {}
        byteInFlight = self.flowStaticData[key]['bytesInFlight']
        rcvBuf = self.flowStaticData[key]['rcvBuf']
        sndBuf = self.flowStaticData[key]['sndBuf']
        sndCwnd = self.flowStaticData[key]['sndCwnd']
        result['minByte'] = np.min(byteInFlight)
        result['maxByte'] = np.max(byteInFlight)
        result['stdByte'] = np.std(byteInFlight)
        result['meanPacingRate'] = np.mean(self.flowStaticData[key]['pacing_rate'])
        result['maxPacingRate'] = self.flowStaticData[key]['max_pacing_rate']
        if result['maxPacingRate'] == 0:
            result['maxPacingRate'] = maxPactingRate
        result['minRcvBuf'] = np.min(rcvBuf)
        result['maxRcvBuf'] = np.max(rcvBuf)
        result['stdRcvBuf'] = np.std(rcvBuf)
        result['meanRcvBuf'] = np.mean(rcvBuf)
        result['minSndBuf'] = np.min(sndBuf)
        result['maxSndBuf'] = np.max(sndBuf)
        result['stdSndBuf'] = np.std(sndBuf)
        result['meanSndBuf'] = np.mean(sndBuf)
        result['minSndCwnd'] = np.min(sndCwnd)
        result['maxSndCwnd'] = np.max(sndCwnd)
        result['stdSndCwnd'] = np.std(sndCwnd)
        result['meanSndCwnd'] = np.mean(sndCwnd)
        result['meanRTT'] = np.mean(self.flowStaticData[key]['rtt'])
        result["maxRTT"] = self.flowStaticData[key]['maxRTT']
        result['minRTT'] = self.flowStaticData[key]['minRTT']
        result['mdevRTT'] = self.flowStaticData[key]['mdevRTT']
        result['retrans'] = self.flowStaticData[key]['retrans']
        result['lost'] = self.flowStaticData[key]['lost']
        return result

    def bashWriteTrainData(self):
        lock.acquire()
        print("\nenter: " + str(self.trainLawData))
        trainData = []
        delKeys = []
        for key in self.trainLawData:
            if "result" not in self.trainLawData[key].keys() or self.trainLawData[key]['result'] == '':
                continue
            print("trainData: " + str(self.trainLawData[key]))
            delKeys.append(key)
            data = self.trainLawData[key]
            termTrainData = [data['minByte'], data['maxByte'], data['stdByte'],
                             int(data['maxRTT']),
                             int(data['minRTT']), float(data['mdevRTT']), float(data['meanRTT']),
                             int(data['retrans']),
                             int(data['lost']), int(data['minByte']), int(data['maxByte']),
                             float(data['stdByte']), int(data['minRcvBuf']), int(data['maxRcvBuf'])
                , float(data['stdRcvBuf']), float(data['meanRcvBuf']), int(data['minSndBuf']),
                             int(data['maxSndBuf']), float(data['stdSndBuf']), float(data['meanSndBuf'])
                , int(data['minSndCwnd']), int(data['maxSndCwnd']), float(data['stdSndCwnd']),
                             float(data['meanSndCwnd']), float(data['meanPacingRate']), int(data['maxPacingRate']),
                             float(data['result'])]

            trainData.append(termTrainData)

        print("\nnewtrainData1: " + str(trainData))
        # 输出到文件中
        if (trainData.__len__() > 0):
            now = datetime.datetime.now()
            fileName = (now + datetime.timedelta(hours=-1)).strftime("%H:00:00")
            fileName = "/usr/src/qiuxinyi/python/data_" + self.ccName
            self.writeData(fileName, trainData)
        print("write end " + str(delKeys))
        for key in delKeys:
            print("delKey: " + key)
            del self.trainLawData[key]
        lock.release()

    def calReward(self, trainData):
        reward = ((trainData['meanPacingRate'] - self.sigma * trainData['lost']) / trainData['meanRTT']) / (
                trainData['maxPacingRate'] / trainData['minRTT'])
        return reward

    def writeData(self, path, data):

        print("\nwrite data: " + str(data))
        with open(path, 'a') as f:
            print("open path")
            try:
                writeData = np.array(data)
                np.savetxt(f, writeData, delimiter=" ")
            except Exception as e:
                print(e.message)

    def scheduleWriteJob(self):

        scheduler = BlockingScheduler()
        scheduler.add_job(self.bashWriteTrainData, 'interval', seconds=60, id='createData')
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
