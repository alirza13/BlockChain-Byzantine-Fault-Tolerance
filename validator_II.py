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
import os



class Validator:
    API_URL = 'http://127.0.0.1:5000/peers'

    def __init__(self, portNo, k, m, n):

        self.isMalicious = False
        self.myPORT = int(portNo)
        if os.path.exists('chain_%d.txt' % self.myPORT):
            os.remove('chain_%d.txt' % self.myPORT)
        else:
            print("The file does not exist")
        self.k = int(k)
        self.sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)
        self.pk = self.sk.get_verifying_key()
        self.m = int(m)  # no. of malicious peers
        self.n = int(n)
        self.honestPeers = self.n - self.m #  total no. of peers - no. of malicious peers
        self.firstGroup = self.honestPeers // 2
        self.receivedBlocksMap = {}
        pkSTR = binascii.hexlify(self.pk.to_string()).decode('utf-8')
        self.alreadySentToValidators = False
        self.sendToValidatorsReady = False
        self.receiveFromValidatorsReady = False
        self. messageToSecondGroup = ''
        self.messageToFirstGroup = ''
        self.assignedValueForReceivedBlock = False
        endpoint = '{}'.format(self.API_URL)
        requests.put((endpoint), json={'PORT': self.myPORT, 'PUBKEY': pkSTR})  # if buggy, check this

    def peerType(self, portNo):
        malicious = False
        endpoint = '{}'.format(self.API_URL)
        response = requests.get((endpoint))
        content = response.json()
        listOfPeers = content['Peers']

        validatorsPortList = []
        for i in listOfPeers:  # excluding self.PORT from list of ports
            if i['PORT'] != self.myPORT:
                validatorsPortList.append(i['PORT'])

        if (validatorsPortList[0] + self.m > portNo):
            malicious = True
            return malicious
        elif (validatorsPortList[0] + self.m  <= portNo):
            return  malicious

    def sendToValidatorS(self):
        endpoint = '{}'.format(self.API_URL)
        response = requests.get((endpoint))
        content = response.json()
        listOfPeers = content['Peers']

        validatorsPortList = []
        for i in listOfPeers:  # excluding self.PORT from list of ports
            if i['PORT'] != self.myPORT:
                validatorsPortList.append(i['PORT'])

        self.sentToOthers = False
        self.numMsgsSent = 0

        receivedMsgs = 0

        while (receivedMsgs < 2*self.k):
            if self.sendToValidatorsReady:
                context = zmq.Context()
                if not self.sentToOthers:
                    self.sentToOthers = True
                    for peer in validatorsPortList:  # send REQ(msg) to all validators
                        if peer == validatorsPortList[0]:
                            continue
                        php = 'tcp://127.0.0.1:' + str(peer + len(listOfPeers))  # how and where to connect
                        forwardingSocket = context.socket(zmq.REQ)  # create socket

                        forwardingSocket.connect(php)  # block until connected

                        if self.peerType(self.myPORT):
                            if (validatorsPortList[0] + self.m > peer):
                                forwardingSocket.send_json(self.maliciousMessage)  # send message
                                print('sending to peer: ', peer, 'message: ', self.maliciousMessage)
                            elif (validatorsPortList[0] + self.m <= peer and peer < validatorsPortList[0] + self.m + self.firstGroup):
                                forwardingSocket.send_json(self.messageToFirstGroup)  # send message
                                print('sending to peer: ', peer, 'message: ', self.messageToFirstGroup)
                            elif (peer >= validatorsPortList[0] + self.m + self.firstGroup ):
                                forwardingSocket.send_json(self.messageToSecondGroup)  # send message
                                print('sending to peer: ', peer, 'message: ', self.messageToSecondGroup)
                        else:
                            forwardingSocket.send_json(self.messageToFirstGroup)  # send message
                            print('sending to peer: ', peer, 'message: ', self.messageToFirstGroup)

                        self.alreadySentToValidators = True
                        self.numMsgsSent = self.numMsgsSent + 1

                        response = forwardingSocket.recv_json()  # receive validation

                        peerPubK = ''
                        for i in listOfPeers:  # finding the public key of the sender thru its port num.
                            if i['PORT'] == response['PORT']:
                                peerPubK = i['PUBKEY']

                        peerSignature = response['SIGNATURE']
                        peerSignature = bytes.fromhex(peerSignature)
                        block = response['BLOCK']
                        if 'BLOCK2' in response:

                            peerSignature2 = response['SIGNATURE2']
                            peerSignature2 = bytes.fromhex(peerSignature2)
                            block2 = response['BLOCK2']

                        encodedPK = peerPubK.encode('utf-8')  # convert string PK to Bytes
                        ecdsaPK = ecdsa.VerifyingKey.from_string(binascii.unhexlify(encodedPK), curve=ecdsa.NIST256p,
                                                                             hashfunc=hashlib.sha256)  # convert to ecdsa object

                        try:  # verifying the receieved block
                            print(ecdsaPK.verify(peerSignature, block.encode('utf-8')))
                            print('Block verified!')
                            if ( 'BLOCK2' in response):
                                print("inside the validation of recfromVals port of sender: ", response['PORT'])
                                print("inside the validation of recfromVals: " , self.myPORT)
                                print(ecdsaPK.verify(peerSignature2, block2.encode('utf-8'))," verified in ", self.myPORT, "block 2")

                            receivedMsgs = receivedMsgs + 1
                            print('Validator ', self.myPORT, ' received this many responses  ', receivedMsgs,
                                              ' from validator ', response['PORT'])
                        except ecdsa.BadSignatureError:
                            print(ecdsa.BadSignatureError)
                            print('Block not verified in sendToValidators!')
        # self.f = open('chain_%d.txt' % self.myPORT, 'a+')  # CREATE FILE
        # print("VALIDATOR BLOCK TYPE: ", type(self.messageToBeSent['BLOCK']))
        # self.f.write(self.messageToBeSent['BLOCK'])
        # self.f.close()

    def receiveFromValidators (self):
        endpoint = '{}'.format(self.API_URL)
        response = requests.get((endpoint))
        content = response.json()
        listOfPeers = content['Peers']

        acceptedMessage = ''

        receivedMsgs = 0  # counter

        firstBlockAdded = False
        signatureList = []
        roundFinished = False

        while True:
                context = zmq.Context()
                php = 'tcp://127.0.0.1:' + str(self.myPORT+ len(listOfPeers))  # how and where to connect
                receivingSocket = context.socket(zmq.REP)  # create socket
                receivingSocket.bind(php)  # block until connected
                message = receivingSocket.recv_json()

                if (message['BLOCK'] in self.receivedBlocksMap):
                    self.receivedBlocksMap[message['BLOCK']] = self.receivedBlocksMap[message['BLOCK']] + 1
                else:
                    self.receivedBlocksMap[message['BLOCK']] = 1

                signatureList.append(message['SIGNATURE'])
                print ('validator', self.myPORT, ' received message from validator ', message)

                peerPubK = ''

                for i in listOfPeers:  # finding the public key of the sender thru its port num.
                    if i['PORT'] == message['PORT']:
                        peerPubK = i['PUBKEY']

                peerSignature = message['SIGNATURE']
                peerSignature = bytes.fromhex(peerSignature)
                block = message['BLOCK']
                if 'BLOCK2' in message:
                    peerSignature2 = message['SIGNATURE2']
                    peerSignature2 = bytes.fromhex(peerSignature2)
                    block2 = message['BLOCK2']

                encodedPK = peerPubK.encode('utf-8')  # convert string PK to Bytes
                ecdsaPK = ecdsa.VerifyingKey.from_string(binascii.unhexlify(encodedPK), curve=ecdsa.NIST256p,
                                                         hashfunc=hashlib.sha256)  # convert to ecdsa object

                try:  # verifying the receieved block
                    print(ecdsaPK.verify(peerSignature, block.encode('utf-8')))
                    if 'BLOCK2' in message:
                        print(ecdsaPK.verify(peerSignature2, block2.encode('utf-8')))
                    print('Block verified!')
                    receivedMsgs = receivedMsgs + 1
                except ecdsa.BadSignatureError:
                    print(ecdsa.BadSignatureError)
                    print('Block not verified!')

                mySignature = self.sk.sign(block.encode('utf-8'))  # signing the verified received block
                messageToBeSent = {'BLOCK': block,
                                        'SIGNATURE': mySignature.hex(),
                                        'PORT': self.myPORT}


                for blockKey, noOfBlocks in self.receivedBlocksMap.items():
                    if (noOfBlocks >= 2* self.k):   # received 2K identical blocks
                        acceptedMessage = str(blockKey)

                        self.f = open('chain_%d_II.txt' % self.myPORT, 'a+')  # CREATE FILE
                        self.f.write(acceptedMessage)
                        self.f.write('\n')
                        self.f.write('Signatures: ')
                        self.f.write('\n')
                        for sign in signatureList:
                            self.f.write(str(sign))
                            self.f.write('\n')
                        self.f.close()
                        self.receivedBlocksMap = {}
                        signatureList = []

                    elif (3 * self.k <= receivedMsgs):  # didn't receive any 2K identical blocks
                        receivedMsgs = 0

                        self.f = open('chain_%d_II.txt' % self.myPORT, 'a+')  # CREATE FILE
                        self.f.write(message['BLOCK'])
                        self.f.write('\n')
                        self.f.write('Signatures: ')
                        self.f.write('\n')
                        for sign in signatureList:
                            self.f.write(str(sign))
                            self.f.write('\n')
                        self.f.close()
                        signatureList = []

                if ('BLOCK2' in message ):
                    mySignature2 = self.sk.sign(block2.encode('utf-8'))  # signing the verified received block
                    block2 = message['BLOCK2']
                    maliciousMessage = {'BLOCK2': block2,
                                        'SIGNATURE2': mySignature2.hex(),
                                        'PORT': self.myPORT,
                                        'BLOCK': block,
                                        'SIGNATURE': mySignature.hex()
                                        }
                    receivingSocket.send_json(maliciousMessage)
                else:
                    receivingSocket.send_json(messageToBeSent)



                print("PORT: ", self.myPORT, " BLOCKS MAP YAY: ", self.receivedBlocksMap)


    def contactProposer(self):

        endpoint = '{}'.format(self.API_URL)
        response = requests.get((endpoint))
        content = response.json()
        listOfPeers = content['Peers']

        validatorsPortList = []
        for i in listOfPeers:  # excluding self.PORT from list of ports
            if i['PORT'] != self.myPORT:
                validatorsPortList.append(i['PORT'])


        while True:
            context = zmq.Context()
            validatorSocket = context.socket(zmq.REP)

            php = 'tcp://127.0.0.1:' + str(self.myPORT)  # how and where to connect
            validatorSocket.bind(php)  # bind socket to address

            message = validatorSocket.recv_json()  # wait for incoming BLOCK & SIGNATURE

            peerPubK = ''
            print('validator: ', self.myPORT, 'received a message: ', message)
            for i in listOfPeers:  # finding the public key of the sender thru its port num.
                if i['PORT'] == message['PORT']:
                    peerPubK = i['PUBKEY']

            peerSignature = message['SIGNATURE']
            peerSignature = bytes.fromhex(peerSignature)
            block = message['BLOCK']
            if 'BLOCK2' in message:
                peerSignature2 = message['SIGNATURE2']
                peerSignature2 = bytes.fromhex(peerSignature2)
                block2 = message['BLOCK2']
                self.isMalicious = True

            encodedPK = peerPubK.encode('utf-8')  # convert string PK to Bytes
            ecdsaPK = ecdsa.VerifyingKey.from_string(binascii.unhexlify(encodedPK), curve=ecdsa.NIST256p,
                                                     hashfunc=hashlib.sha256)  # convert to ecdsa object

            try:  # verifying the receieved block
                print(ecdsaPK.verify(peerSignature, block.encode('utf-8')))
                print('Block verified!')
                if (self.isMalicious):
                    print(ecdsaPK.verify(peerSignature2, block2.encode('utf-8')))
            except ecdsa.BadSignatureError:
                print(ecdsa.BadSignatureError)
                print('Block not verified in ContactProposer!')

            mySignature = self.sk.sign(block.encode('utf-8'))  # signing the verified received block

            if(self.isMalicious):
                mySignature2 = self.sk.sign(block2.encode('utf-8'))  # signing the verified received block

                self.messageToSecondGroup = {'BLOCK': block2,
                                            'SIGNATURE': mySignature2.hex(),
                                            'PORT': self.myPORT}

                self.maliciousMessage = {'BLOCK2': block2,
                                         'SIGNATURE2': mySignature2.hex(),
                                         'PORT': self.myPORT,
                                         'BLOCK': block,
                                         'SIGNATURE': mySignature.hex()
                                         }

            self.messageToFirstGroup = {'BLOCK': block,
                                        'SIGNATURE': mySignature.hex(),
                                        'PORT': self.myPORT}


            if (not message['BLOCK'] in self.receivedBlocksMap):
                self.receivedBlocksMap[self.messageToFirstGroup['BLOCK']] = 1
                self.assignedValueForReceivedBlock = True
            else:
                self.receivedBlocksMap[message['BLOCK']] = self.receivedBlocksMap[message['BLOCK']] + 1

            self.sendToValidatorsReady = True
            self.receiveFromValidatorsReady = True
            self.sendToValidatorS()

            if (self.isMalicious):
                validatorSocket.send_json(self.maliciousMessage)
            else:
                validatorSocket.send_json(self.messageToFirstGroup)


