const path = require('path');
const fs = require('fs-extra');
const sha = require('js-sha256');
const asn = require('asn1.js');
const utils = require('fabric-client/lib/utils');
const FabricClient = require('./../FabricClient.js');
const helper = require('../../../common/helper');

const logger = helper.getLogger('FabricUtils');
const ExplorerError = require('../../../common/ExplorerError');

const explorer_error = require('../../../common/ExplorerMessage').explorer
  .error;

/**
 *
 * @param config
 * @param client_name
 * @param persistence
 * @returns {Promise<FabricClient>}
 */
async function createFabricClient(config, client_name, persistence) {
  logger.debug('Validating client [%s] configuration', client_name);
  // const validation = validateClientConfig(client_config);
  //todo implement validation Config according to new schema
  const isValid = validateConfig(config);

  if (!isValid) {
    throw new ExplorerError(explorer_error.ERROR_2014);
  }

  const client = new FabricClient(config, client_name);
  logger.debug(
    '************ Initializing fabric client for [%s]************',
    client_name
  );
  await client.initialize(config, persistence);
  return client;
}

async function createDetachClient(client_configs, client_name, persistence) {
  // clone global.hfc.config configuration
  const client_config = cloneConfig(client_configs, client_name);

  const client = new FabricClient(client_name);
  await client.initializeDetachClient(client_config, persistence);
  return client;
}

function cloneConfig(client_configs, client_name) {
  const global_hfc_config = JSON.parse(JSON.stringify(global.hfc.config));

  let client_config = global_hfc_config;
  client_config.client = client_configs.clients[client_name];
  client_config.version = client_configs.version;
  client_config.channels = client_configs.channels;
  client_config.organizations = client_configs.organizations;
  client_config.peers = client_configs.peers;
  client_config.orderers = client_configs.orderers;

  // modify url with respect to TLS enable
  client_config = processTLS_URL(client_config);
  return client_config;
}

function processTLS_URL(client_config) {
  for (const peer_name in client_config.peers) {
    const url = client_config.peers[peer_name].url;
    client_config.peers[peer_name].url = client_config.client.tlsEnable
      ? `grpcs${url.substring(url.indexOf('://'))}`
      : `grpc${url.substring(url.indexOf('://'))}`;
    if (client_config.peers[peer_name].eventUrl) {
      const eventUrl = client_config.peers[peer_name].eventUrl;
      client_config.peers[peer_name].eventUrl = client_config.client.tlsEnable
        ? `grpcs${eventUrl.substring(eventUrl.indexOf('://'))}`
        : `grpc${eventUrl.substring(eventUrl.indexOf('://'))}`;
    }
  }
  for (const ord_name in client_config.orderers) {
    const url = client_config.orderers[ord_name].url;
    client_config.orderers[ord_name].url = client_config.client.tlsEnable
      ? `grpcs${url.substring(url.indexOf('://'))}`
      : `grpc${url.substring(url.indexOf('://'))}`;
  }
  return client_config;
}

function validateConfig() {
  return true;
}

async function setAdminEnrolmentPath(network_configs) {
  for (const network_name in network_configs) {
    network_configs[network_name] = setOrgEnrolmentPath(
      network_configs[network_name]
    );
  }
  return network_configs;
}

function setOrgEnrolmentPath(network_config) {
  if (network_config && network_config.organizations) {
    for (const organization_name in network_config.organizations) {
      // checking files path is defined as full path or directory
      // if directory, then it will consider the first file
      const organization = network_config.organizations[organization_name];
      if (!organization.fullpath) {
        // setting admin private key as first file from keystore dir
        logger.debug(
          'Organization [%s] enrolment files path defined as directory',
          organization_name
        );
        if (organization.adminPrivateKey) {
          const privateKeyPath = organization.adminPrivateKey.path;
          var files = fs.readdirSync(privateKeyPath);
          if (files && files.length > 0) {
            organization.adminPrivateKey.path = path.join(
              privateKeyPath,
              files[0]
            );
          }
        }
        // setting admin private key as first file from signcerts dir
        if (organization.signedCert) {
          const signedCertPath = organization.signedCert.path;
          var files = fs.readdirSync(signedCertPath);
          if (files && files.length > 0) {
            organization.signedCert.path = path.join(signedCertPath, files[0]);
          }
        }
      } else {
        logger.debug(
          'Organization [%s] enrolment files path defined as full path',
          organization_name
        );
      }
    }
  }
  return network_config;
}

async function generateBlockHash(block_header) {
  const result = await generateBlockHash(block_header);
  return result;
}

async function getBlockTimeStamp(dateStr) {
  try {
    return new Date(dateStr);
  } catch (err) {
    logger.error(err);
  }
  return new Date(dateStr);
}

async function generateDir() {
  const tempDir = `/tmp/${new Date().getTime()}`;
  try {
    fs.mkdirSync(tempDir);
  } catch (err) {
    logger.error(err);
  }
  return tempDir;
}

async function generateBlockHash(header) {
  const headerAsn = asn.define('headerAsn', function() {
    this.seq().obj(
      this.key('Number').int(),
      this.key('PreviousHash').octstr(),
      this.key('DataHash').octstr()
    );
  });
  const output = headerAsn.encode(
    {
      Number: parseInt(header.number),
      PreviousHash: Buffer.from(header.previous_hash, 'hex'),
      DataHash: Buffer.from(header.data_hash, 'hex')
    },
    'der'
  );
  return sha.sha256(output);
}

function getPEMfromConfig(config) {
  let result = null;
  if (config) {
    if (config.path) {
      // cert value is in a file
      result = readFileSync(config.path);
      result = utils.normalizeX509(result);
    }
  }

  return result;
}

function readFileSync(config_path) {
  try {
    const config_loc = path.resolve(config_path);
    const data = fs.readFileSync(config_loc);
    return Buffer.from(data).toString();
  } catch (err) {
    logger.error(`NetworkConfig101 - problem reading the PEM file :: ${err}`);
    throw err;
  }
}

exports.setAdminEnrolmentPath = setAdminEnrolmentPath;
exports.setOrgEnrolmentPath = setOrgEnrolmentPath;
exports.generateBlockHash = generateBlockHash;
exports.createFabricClient = createFabricClient;
exports.getBlockTimeStamp = getBlockTimeStamp;
exports.generateDir = generateDir;
exports.generateBlockHash = generateBlockHash;
exports.getPEMfromConfig = getPEMfromConfig;
exports.createDetachClient = createDetachClient;
