from flask import Flask, request
from flask_restful import Resource, Api, reqparse, abort
import json
import requests
import random
import hashlib
import zmq
import sys
from threading import Thread
import time
import random
import string
import sys
import ecdsa
import hashlib
import binascii
from proposer_II import Proposer
from validator_II import Validator
#from validatornewest import Validator
from threading import Thread
import itertools
import filecmp


n = input("Enter the number of peers: ")
k = input("Enter the threshold for tolerable malicious peers: ")
m = input("Enter the number of malicious peers: ")
l = input("Enter the number of transcations per block: ")
r = input("Enter the number of rounds: ")

portNum = 6000
portList = []
portList.append(portNum)

prop = Proposer(portNum, n, k, m, l, r)
validatorList = []
contactThreadsList = []
receiveThreadList = []

for i in range (1, int(n)):
    validatorList.append(Validator(portNum + i, k, m, n))
    portList.append(portNum+i)

print("length of validatorlist", len(validatorList))


proposerThread = Thread(target = prop.contactValidators)
proposerThread.start()

for val in validatorList:
    conThread = Thread(target=val.contactProposer)
    contactThreadsList.append(conThread)
    conThread.start()

    recThread = Thread(target=val.receiveFromValidators)
    receiveThreadList.append(recThread)
    recThread.start()

while (proposerThread.isAlive()):
    x=0 # stall

print ("proposer has returned!")

filesList = []

for i in portList:
   filesList.append('chain_%d_II.txt' % i)

unmatched = False

'''
for x in range(len(filesList)):
    for y in range (len(filesList)):
        if x == y:
            continue
        if not filecmp.cmp(filesList[x], filesList[y]):
            unmatched = True
            print('file ', filesList[x], ' and file ', filesList[y], 'do not match')

if not unmatched:
    print('all files are identical!')
'''

for x in range(len(filesList)):
    signatureCounter = 0
    with open(filesList[x], "r") as ifile:
        for line in ifile:
            if line.startswith("Signatures:"):
                continue
            signatureCounter = signatureCounter + 1
            if (signatureCounter == 2 * k):
                print('There are 2k + 1 signatures for this block')

# for i in range(len(contactThreadsList)):
#     print(type(proposerThread))
#     print(type(contactThreadsList[i]))
#     contactThreadsList[i].kill()
#     contactThreadsList[i].join()
#     receiveThreadList[i].kill()
#     receiveThreadList[i].join()
#     print("validator thread ", i, " has joined!")

# prop = Proposer(6000, n, k, l, r)
# validatorList = []
# val_1 = Validator(6001, k)
# val_2 = Validator(6002, k)
# val_3 = Validator(6003, k )
# val_4 = Validator(6004, k)
# validatorList.append(val_1)
# validatorList.append(val_2)
# validatorList.append(val_3)
# validatorList.append(val_4)
#
#
# Thread(target = prop.contactValidators).start()
# Thread(target = val_1.contactProposer).start()
# Thread(target = val_1.sendToValidatorS).start()
# Thread(target = val_1.receiveFromValidators).start()
# Thread(target = val_2.contactProposer).start()
# Thread(target = val_2.sendToValidatorS).start()
# Thread(target = val_2.receiveFromValidators).start()
# Thread(target = val_3.contactProposer).start()
# Thread(target = val_3.sendToValidatorS).start()
# Thread(target = val_3.receiveFromValidators).start()
# Thread(target = val_4.contactProposer).start()
# Thread(target = val_4.sendToValidatorS).start()
# Thread(target = val_4.receiveFromValidators).start()
# #
# # Thread(target = prop.contactValidators).start()
# # Thread(target = val_1.contactProposer).start()
# # Thread(target = val_1.sendToValidatorS).start()
# # Thread(target = val_1.receiveFromValidators).start()
# # Thread(target = val_2.contactProposer).start()
# # Thread(target = val_2.sendToValidatorS).start()
# # Thread(target = val_2.receiveFromValidators).start()
# # Thread(target = val_3.contactProposer).start()
# # Thread(target = val_3.sendToValidatorS).start()
# # Thread(target = val_3.receiveFromValidators).start()
# # Thread(target = val_4.contactProposer).start()
# # Thread(target = val_4.sendToValidatorS).start()
# # Thread(target = val_4.receiveFromValidators).start()
#


