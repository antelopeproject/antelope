# -*- coding: utf-8 -*-
### load module
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
import numpy as np
import pickle
import datetime

DATAPATH = "/usr/src/python/traindata/data.txt"
MODELPATH = "/usr/src/python/traindata/XXX.pickle"


def loadData(dir):
    data = []
    target = []
    fileName = dir
    try:
        rawData = np.loadtxt(fileName)
        for item in rawData:
            data.append(item[:-1])
            target.append(item[-1])
    except  Exception as e:
        pass

    return np.array(data), np.array(target)


### load datasets
data, target = loadData(DATAPATH)
#
# ### data analysis
print(data.shape)
print(target.shape)

### data split
x_train, x_test, y_train, y_test = train_test_split(data,
                                                    target,
                                                    test_size=0.2,
                                                    random_state=33)
### fit model for train data
model = XGBClassifier(n_estimators=40, max_depth=3, subsample=1, gamma=1, learning_rate=0.15)
model.fit(x_train, y_train)
with open(MODELPATH, "wb") as fw:
    pickle.dump(model, fw)

