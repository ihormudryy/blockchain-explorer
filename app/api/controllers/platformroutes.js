/* eslint-disable func-names */
/**
 *    SPDX-License-Identifier: Apache-2.0
 */

const requtil = require('./requestutils');
const helper = require('../../common/helper');

const platformroutes = platform => {
  const proxy = platform.getProxy();
  console.log('platformroutes', platform.networks, platform.defaultNetwork);
  const statusMetrics = platform.getPersistence().getMetricService();
  const logger = helper.getLogger('PlatformRoutes');

  /** *
    Block by number
    GET /api/block/getinfo -> /api/block
    curl -i 'http://<host>:<port>/api/block/<channel>/<number>'
    *
    */
  const blockByNumber = (req, res) => {
    const number = parseInt(req.params.number);
    const channel_genesis_hash = req.params.channel_genesis_hash;
    if (!isNaN(number) && channel_genesis_hash) {
      proxy.getBlockByNumber(channel_genesis_hash, number).then(block => {
        res.send({
          status: 200,
          number: block.header.number.toString(),
          previous_hash: block.header.previous_hash,
          data_hash: block.header.data_hash,
          transactions: block.data.data
        });
      });
    } else {
      return requtil.invalidRequest(req, res);
    }
  };

  /**
    Return list of channels
    GET /channellist -> /api/channels
    curl -i http://<host>:<port>/api/channels
    Response:
    {
    'channels': [
        {
        'channel_id': 'mychannel'
        }
    ]
    }
    */
  const channelList = (req, res) => {
    proxy.getChannels().then(channels => {
      const response = {
        status: 200
      };
      response.channels = channels;
      res.send(response);
    });
  };

  /**
    Return current channel
    GET /api/curChannel
    curl -i 'http://<host>:<port>/api/curChannel'
    */
  const currentChannel = (req, res) => {
    proxy.getCurrentChannel().then(data => {
      res.send(data);
    });
  };

  /**
    Return change channel
    POST /api/changeChannel
    curl -i 'http://<host>:<port>/api/curChannel'
    */
  const getChannelChange = (req, res) => {
    const channel_genesis_hash = req.params.channel_genesis_hash;
    proxy.changeChannel(channel_genesis_hash).then(data => {
      res.send({
        currentChannel: data
      });
    });
  };

  /**
     Read 'blockchain-explorer/app/config/CREATE-CHANNEL.md' on 'how to create a channel'

    The values of the profile and genesisBlock are taken fron the configtx.yaml file that
    is used by the configtxgen tool
    Example values from the defualt first network:
    profile = 'TwoOrgsChannel';
    genesisBlock = 'TwoOrgsOrdererGenesis';
    */

  /**
    Create new channel
    POST /api/channel
    Content-Type : application/x-www-form-urlencoded
    {channelName:'newchannel02'
    genesisBlock:'TwoOrgsOrdererGenesis'
    orgName:'Org1'
    profile:'TwoOrgsChannel'}
    {fieldname: 'channelArtifacts', fieldname: 'channelArtifacts'}
    <input type='file' name='channelArtifacts' multiple />
    Response: {  success: true, message: 'Successfully created channel '   }
    */
  const createChannel = async (req, res) => {
    try {
      const { randomNumber, autojoin } = req.body;
      await proxy.createChannel(randomNumber, autojoin);
      return res.sendStatus(200);
    } catch (err) {
      console.error(err);
      const channelError = {
        success: false,
        message: 'Invalid request, payload'
      };
      return res.send(channelError);
    }
  };

  /** *
    An API to join channel
    POST /api/joinChannel

    curl -X POST -H 'Content-Type: application/json' -d '{ 'orgName':'Org1','channelName':'newchannel'}' http://localhost:8080/api/joinChannel

    Response: {  success: true, message: 'Successfully joined peer to the channel '   }
    */
  const joinChannel = (req, res) => {
    const channelName = req.body.channelName;
    const peers = req.body.peers;
    const orgName = req.body.orgName;
    if (channelName && peers && orgName) {
      proxy
        .joinChannel(channelName, peers, orgName)
        .then(resp => res.send(resp));
    } else {
      return requtil.invalidRequest(req, res);
    }
  };

  /**
    Chaincode list
    GET /chaincodelist -> /api/chaincode
    curl -i 'http://<host>:<port>/api/chaincode/<channel>'
    Response:
    [
      {
        'channelName': 'mychannel',
        'chaincodename': 'mycc',
        'path': 'github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02',
        'version': '1.0',
        'txCount': 0
      }
    ]
    */
  const chaincodeList = (req, res) => {
    const channelName = req.params.channel;
    if (channelName) {
      statusMetrics.getTxPerChaincode(channelName, async data => {
        for (const chaincode of data) {
          const temp = await proxy.loadChaincodeSrc(chaincode.path);
          chaincode.source = temp;
        }
        res.send({
          status: 200,
          chaincode: data
        });
      });
    } else {
      return requtil.invalidRequest(req, res);
    }
  };

  /** *Peer Status List
    GET /peerlist -> /api/peersStatus
    curl -i 'http://<host>:<port>/api/peersStatus/<channel>'
    Response:
    [
      {
        'requests': 'grpcs://127.0.0.1:7051',
        'server_hostname': 'peer0.org1.example.com'
      }
    ]
    */
  const peerList = (req, res) => {
    const channelName = req.params.channel;
    if (channelName) {
      proxy.getPeersStatus(channelName).then(data => {
        res.send({ status: 200, peers: data });
      });
    } else {
      return requtil.invalidRequest(req, res);
    }
  };

  /**
   Chaincode install
   POST /api/chaincode
   Request:
   {
      "peers": "peer0.org1.example.com",
      "chaincodename: "TEST",
      "version": "0.0.1",
      "type": "Go"
    }
   */
  const installChaincode = async (req, res) => {
    const { peer, name, version, type } = req.body;
    const { zip } = req.files;

    logger.info(
      'Install chaincode api params: %s, %s, %s, %s, %s, %s',
      peer,
      name,
      zip,
      version,
      type
    );
    try {
      if (peer && name && zip && version) {
        console.log('installChaincode');
        const message = await proxy.installChaincode(
          peer,
          name,
          zip,
          version,
          type
        );
        res.send(message);
      } else {
        return requtil.invalidRequest(req, res);
      }
    } catch (err) {
      console.log(err);
      return requtil.invalidRequest(req, res);
    }
  };

  // Chaincode INSTANTIATE
  const instantiateChaincode = async (req, res) => {
    const {
      channel,
      name,
      version,
      type: txtype,
      policy,
      params: args
    } = req.body;

    let peers = req.body.peer;

    if (!Array.isArray(peers)) {
      peers = [peers];
    }

    logger.info(
      'Instantiate chaincode api params: %s, %s, %s, %s, %s, %s, %s',
      peers,
      name,
      channel,
      version,
      txtype,
      policy,
      args
    );

    if (peers && channel && name && version) {
      let message = await proxy.instantiateChaincode(
        {
          peers,
          name,
          version,
          channel,
          policy,
          args
        },
        txtype
      );
      res.send(message);
    } else {
      return requtil.invalidRequest(req, res);
    }
  };

  /** *
   Get docker artifact for new org
   GET /api/orgs/docker
   curl -i 'http://<host>:<port>/api/orgs/docker'
   */
  const getDockerAtrifacts = (req, res) => {
    const { newOrg, numPeers, randomNumber, startPeer = 1 } = req.query;
    let { services = ['peers', 'ica', 'rca'] } = req.query;
    if (!Array.isArray(services)) {
      services = [services];
    }
    const archive = proxy.generateDockerArtifacts(
      {
        newOrg,
        numPeers: Number(numPeers),
        startPeer: Number(startPeer),
        services
      },
      randomNumber
    );
    res.attachment('docker-artifacts.zip');
    res.send(archive.toBuffer());
  };

  /** *
   Switch to different org
   POST /api/orgs/switch
   curl -i 'http://<host>:<port>/api/orgs/switch'
   */
  const switchOrg = async (req, res) => {
    try {
      const { org, peers = 1 } = req.body;
      await proxy.switchOrg(org, Number(peers));
      res.sendStatus(200);
    } catch (err) {
      console.error(err);
      return requtil.invalidRequest(req, res);
    }
  };

  /** *
   Add new org to channel
   POST /api/orgs/addToChannel
   curl -i 'http://<host>:<port>/api/orgs/addToChannel'
   */
  const addOrgToChannel = async (req, res) => {
    try {
      const { org, numPeers, randomNumber } = req.body;
      await proxy.addOrgToChannel(org, numPeers, randomNumber);
      res.sendStatus(200);
    } catch (err) {
      console.log(err);
      return requtil.invalidRequest(req, res);
    }
  };

  /** *
   Add new org to consortium
   POST /api/orgs/addToConsortium
   curl -i 'http://<host>:<port>/api/orgs/addToConsortium'
   */
  const addToConsortium = async (req, res) => {
    try {
      const { org, peers } = req.body;
      await proxy.addOrgToConsortium(org, peers);
      res.sendStatus(200);
    } catch (err) {
      console.log(err);
      return requtil.invalidRequest(req, res);
    }
  };

  return {
    blockByNumber,
    channelList,
    currentChannel,
    getChannelChange,
    createChannel,
    joinChannel,
    peerList,
    chaincodeList,
    installChaincode,
    instantiateChaincode,
    getDockerAtrifacts,
    switchOrg,
    addOrgToChannel,
    addToConsortium
  };
};

module.exports = platformroutes;
