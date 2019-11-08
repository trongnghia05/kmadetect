#kmadetect
#By Mai Nghia

from detect.ModelHandle import *
from detect.DataHandle import *
import json

# BATCH_SIZE = 32
# IMG_SIZE = 98
# N_CLASSES = 10
# LR = 0.001
# N_EPOCHS = 5

PATH_SAVE_MODEL = "detect/model/KMA_DtectModel.tflearn"
LabelsNum_file = 'reverse/resources/LabelsNum.json'



def train(path, BATCH_SIZE, IMG_SIZE, N_CLASSES, N_EPOCHS): # ham train
    data = readFileCsv(path)

    rowTrain, RowVal, RowTest = raito(len(data))

    # numsRows = len(data)
    train = data[:rowTrain]  # từ row 0  tới x
    val = data[rowTrain:RowVal]  # từ row x tới y
    test = data[RowVal:]  # từ y tới hết

    # 800,100,129 : số row
    # data: file dạng csv(quy định : cột đầu tiền là nhãn, các cột còn lại trên cùng một hàng là các đặc trưng), phương thức  standardizedData sẽ trả về object data gồm phanà data và label(đã được chuẩn hóa để có thể train)
    trainObj = standardizedData(train, IMG_SIZE, N_CLASSES, len(train))
    valObj = standardizedData(val, IMG_SIZE, N_CLASSES, len(val))
    # testObj = DataHandle.standardizedData(test, IMG_SIZE, N_CLASSES, len(test))

    # train
    model = builtModel(N_CLASSES, IMG_SIZE)

    model = trainModel(model, trainObj.getDataTrain(), trainObj.getDataLabel(), valObj.getDataTrain(),
                              valObj.getDataLabel(), N_EPOCHS, PATH_SAVE_MODEL)


def tranfer(path, BATCH_SIZE, IMG_SIZE, N_CLASSES, N_EPOCHS): # ham tranfer
    data = readFileCsv(path)

    rowTrain, RowVal, RowTest = raito(len(data))

    # numsRows = len(data)
    train = data[:rowTrain]  # từ row 0  tới x
    val = data[rowTrain:RowVal]  # từ row x tới y
    test = data[RowVal:]  # từ y tới hết

    trainObj = standardizedData(train, IMG_SIZE, N_CLASSES, len(train))
    valObj = standardizedData(val, IMG_SIZE, N_CLASSES, len(val))
    # testObj = DataHandle.standardizedData(test, IMG_SIZE, N_CLASSES, len(test))

    # tranfer : load từ model đã có và train tiếp (các tham số của mô hình phải được buil lại qua phương thức builtModel)
    model = builtModel(N_CLASSES, IMG_SIZE)
    model = tranfer(model, trainObj.getDataTrain(), trainObj.getDataLabel(), valObj.getDataTrain(),
                                valObj.getDataLabel(), N_EPOCHS, PATH_SAVE_MODEL)




def detect(path,  BATCH_SIZE, IMG_SIZE, N_CLASSES, N_EPOCHS): # ham du doan

    with open(LabelsNum_file, mode='r+') as f:
        dataNumLabel = json.load(f)

    data = readFileCsv(path)
    testObj = standardizedDataTest(data, IMG_SIZE, N_CLASSES, 1)
    # du doan
    model = builtModel(N_CLASSES, IMG_SIZE)
    print('Family Malware Apk: ')
    numLabelPredict = predict(model, testObj, PATH_SAVE_MODEL)

    x = 2
    if (len(numLabelPredict) > 0):
        numLabelDetect = numLabelPredict[0]
    for label in dataNumLabel:
        if dataNumLabel[label] == numLabelDetect:
            print(label)
            return label
    return 'Null'


def trainModel(model, train_data, train_label, val_data, val_label, N_EPOCHS, pathModel):
    model.fit(train_data, train_label, n_epoch=N_EPOCHS, validation_set=(val_data, val_label), show_metric=True)
    model.save(pathModel)

    return model
