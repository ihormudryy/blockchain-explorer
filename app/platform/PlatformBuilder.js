/*
*SPDX-License-Identifier: Apache-2.0
*/

const explorer_const = require('../common/ExplorerConst').explorer.const;
const explorer_error = require('../common/ExplorerMessage').explorer.error;
const ExplorerError = require('../common/ExplorerError');

class PlatformBuilder {
  /**
   *
   * @param pltfrm
   * @param persistence
   * @param broadcaster
   * @returns {Platform}
   */
  static build(pltfrm, persistence, broadcaster) {
    if (pltfrm === explorer_const.PLATFORM_FABRIC) {
      const Platform = require('./fabric/Platform');
      return new Platform(persistence, broadcaster);
    }
    throw new ExplorerError(explorer_error.ERROR_1004, pltfrm);
  }
}

module.exports = PlatformBuilder;
