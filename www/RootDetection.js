var exec = require('cordova/exec');
var detect = function (success, error) {
  // console.warn('root detection!', success, error);
  exec(success, error, 'RootDetection', 'detect', []);
};

module.exports = {
  detect
};

