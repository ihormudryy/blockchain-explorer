/**
 *    SPDX-License-Identifier: Apache-2.0
 */
const express = require('express');
const fileUpload = require('express-fileupload');
const bodyParser = require('body-parser');
const compression = require('compression');
const SwaggerExpress = require('swagger-express-mw');
const SwaggerUi = require('swagger-tools/middleware/swagger-ui');

const PlatformBuilder = require('./platform/PlatformBuilder');
const explorerconfig = require('./explorerconfig.json');
const PersistenceFactory = require('./persistence/PersistenceFactory');
const ExplorerError = require('./common/ExplorerError');

const dbroutes = require('./rest/dbroutes');
const platformroutes = require('./rest/platformroutes');

const explorer_const = require('./common/ExplorerConst').explorer.const;
const explorer_error = require('./common/ExplorerMessage').explorer.error;

class Explorer {
  constructor() {
    this.app = express();
    this.app.use(bodyParser.json());
    this.app.use(bodyParser.urlencoded({ extended: true }));
    this.app.use(fileUpload());
    this.app.use(compression());
    this.persistence;
    this.platform = {};
  }

  getApp() {
    return this.app;
  }

  async initAPI(platform) {
    return new Promise((resolve, reject) => {
      console.log('init', platform.networks);
      debugger;
      const config = {
        appRoot: __dirname,
        swaggerFile: 'app/api/swagger/swagger.json',
        dependencies: platform,
        controllersDirs: ['rest']
      };

      SwaggerExpress.create(config, (err, swaggerExpress) => {
        if (err) {
          throw err;
        }

        // install middleware
        this.app.use(SwaggerUi(swaggerExpress.runner.swagger));

        swaggerExpress.register(this.app);

        this.app.use((err, req, res, next) => {
          if (typeof err !== 'object') {
            err = {
              message: String(err) // Coerce to string
            };
          } else {
            Object.defineProperty(err, 'message', { enumerable: true });
          }

          res.setHeader('Content-Type', 'application/json');
          console.log('error', err);
          res.end(JSON.stringify(err));
        });
        resolve();
      });
    });
  }

  async initialize(broadcaster) {
    if (!explorerconfig[explorer_const.PERSISTENCE]) {
      throw new ExplorerError(explorer_error.ERROR_1001);
    }
    if (!explorerconfig[explorerconfig[explorer_const.PERSISTENCE]]) {
      throw new ExplorerError(
        explorer_error.ERROR_1002,
        explorerconfig[explorer_const.PERSISTENCE]
      );
    }
    this.persistence = await PersistenceFactory.create(
      explorerconfig[explorer_const.PERSISTENCE],
      explorerconfig[explorerconfig[explorer_const.PERSISTENCE]]
    );

    const platform = await PlatformBuilder.build(
      explorerconfig[explorer_const.PLATFORM],
      this.persistence,
      broadcaster
    );
    console.log('PlatformBuilder build');
    platform.setPersistenceService();
    // // initializing the platfrom
    await platform.initialize();
    //TODO: after platform has initialized use platform abject as dependency in swagger config
    await this.initAPI(platform);
    // initializing the rest app services
    // await dbroutes(this.app, platform);
    // await platformroutes(this.app, platform);

    // initializing sync listener
    platform.initializeListener(explorerconfig.sync);

    this.platform = platform;
  }

  close() {
    if (this.persistence) {
      this.persistence.closeconnection();
    }
    if (this.platform) {
      this.platform.destroy();
    }
  }
}

module.exports = Explorer;
