/*
    SPDX-License-Identifier: Apache-2.0
*/

const { expect } = require('chai');

const utils = require('../../platform/fabric/utils/FabricUtils');

describe('generate ccp entry', () => {
  it('call without arguments returns correct set of properties', () => {
    const expectedProps = [
      'clients',
      'channels',
      'orderers',
      'organizations',
      'peers'
    ];
    const config = utils.generateConfig();

    expect(config).to.not.equal(null);
    expect(config).to.be.an('object');
    expectedProps.forEach(prop =>
      expect(config).to.have.nested.property(prop));
  });
  it('call with correct arguments, returns valid data', () => {
    const expectedProps = [
      'clients.org1',
      'channels.channel1',
      'orderers',
      'organizations.orderer1',
      'organizations.org1'
    ];
    const peers = ['peer1.org1.com', 'peer2.org1.com'];
    const config = utils.generateConfig(
      'org1',
      'channel1',
      'orderer1',
      2
    );
    expect(config).to.be.an('object');
    expectedProps.forEach(prop =>
      expect(config).to.have.nested.property(prop));

    expect(Object.keys(config.clients)).to.have.lengthOf(1);
    expect(Object.keys(config.channels)).to.have.lengthOf(1);
    expect(Object.keys(config.organizations)).to.have.lengthOf(2);
    expect(Object.keys(config.peers)).to.have.lengthOf(2);

    peers.forEach(prop =>
      expect(config.peers).to.have.property(prop));
  });
  it('call with incorrect peers arg, returns peers prop with one entry', () => {
    const config = utils.generateConfig(
      'org1',
      'channel1',
      'orderer1',
      'peer'
    );
    expect(Object.keys(config.peers)).to.have.lengthOf(1);
  });
});
