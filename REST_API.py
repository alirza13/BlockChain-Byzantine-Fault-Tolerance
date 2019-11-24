from flask import Flask, request
from flask_restful import Resource, Api, reqparse, abort
import json
import requests
import random

app = Flask(__name__)
api = Api(app)

peerList = []

class PeerAPI(Resource):
    def put(self):
        global peerList
        data = (request.get_json())
        # myPORT = data['PORT']
        # myPUBKEY = data['PUBKEY']

        peerList.append(data)
        print(data)
        # activeNodes = sorted(activeNodes, key=lambda i: i['ID'])
        # return {'Nodes': activeNodes}

    def get(self):
        global peerList
        # activeNodes = sorted(activeNodes, key=lambda i: i['ID'])
        return {'Peers': peerList}

api.add_resource(PeerAPI, '/peers')
app.run(debug=True, host='127.0.0.1')

