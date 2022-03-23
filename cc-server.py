# -*- coding:utf8 -*-
import tornado.ioloop
import tornado.web
import tornado.httpserver
from tornado.escape import json_encode
import pickle
import time
import datetime
import numpy as np
import threading
import threadpool
from ctypes import *
from apscheduler.schedulers.blocking import BlockingScheduler
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
pickleMap = {}
ccFileMap = {0: "/usr/src/python/traindata/bbr.pickle",
             1: "/usr/src/python/traindata/cubic.pickle",
             2: "/usr/src/python/traindata/illinois.pickle",
             3: "/usr/src/python/traindata/c2tcp.pickle",
             4: "/usr/src/python/traindata/westwood.pickle",
             5: "/usr/src/python/traindata/vegas.pickle"
             }

def set_default_header(self):
    # 后面的*可以换成ip地址，意为允许访问的地址
    self.set_header('Access-Control-Allow-Origin', '*')
    self.set_header('Access-Control-Allow-Headers', 'x-requested-with')
    self.set_header('Access-Control-Allow-Methods', 'POST, GET, PUT, DELETE')

class Predict(tornado.web.RequestHandler):
    threadPool = ThreadPoolExecutor(max_workers=4)

    def get(self):
        set_default_header(self)
        arr = self.get_argument("param")
        if arr:
            print('arr = ', arr, type(arr))
            termTrainData = eval(arr) # 字符转列表
            print('arr = ', arr, type(arr))
            print("address: ",self.request.connection.context.address)
            npData = np.array(termTrainData).reshape(1, 7)
            print("npData" + str(npData))

            rewards = {}
            allTask = []
            t = time.time()
            beginTime = int(round(t * 1000))
            for cc in pickleMap:
                print("cc::"+str(cc))
                #self.runPredic(cc,rewards,npData);
                allTask.append(self.threadPool.submit(self.runPredic, cc, rewards, npData))
            wait(allTask, return_when=ALL_COMPLETED)
            result = max(rewards, key=rewards.get)
        sendData = {
            "result": result
        }
        self.write(json_encode(sendData))
        endTime = int(round(time.time() * 1000))
        print("MR time: " + str(endTime - beginTime))

    def runPredic(self,cc,rewards,npData):
        newModel = pickleMap[cc]
        y_pred = newModel.predict(npData).tolist()
        print("predic: " + str(y_pred) + " cc:" + str(cc))
        rewards[cc] = float(y_pred[0])


def make_app():
    return tornado.web.Application([
        (r"/predict", Predict),
    ])

if __name__ =="__main__":
    app = make_app()
    sockets = tornado.netutil.bind_sockets(9088)
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.add_sockets(sockets)
    print("Server Start Ok.....")
    for cc in ccFileMap:
        with open(ccFileMap[cc], "rb") as fr:
            p = pickle.load(fr)
            pickleMap[cc] = p
    tornado.ioloop.IOLoop.instance().start()

