const assert = require('assert');

const config = require('../platform/fabric/config.json');

describe.skip('config.json should contain properties', () => {
  it('should contain configtxgenToolPath property', () => {
    const configtxgenToolPath = config.configtxgenToolPath;
    assert.notEqual(null, configtxgenToolPath);
  });
});
