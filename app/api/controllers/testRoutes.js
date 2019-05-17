const platformroutes = function(platform) {
  const proxy = platform.getProxy();

  const ping = (req, res) => {
    res.send(proxy.getClientStatus());
  };

  return { ping };
};

module.exports = platformroutes;
