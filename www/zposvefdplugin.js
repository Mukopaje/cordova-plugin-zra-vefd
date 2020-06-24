var exec = require('cordova/exec');

module.exports = {

    efdInit: function (resolve, reject) {
        exec(resolve, reject, "zposvefdplugin", "efdInit", []);
    },
     initVEFD: function (reg, bus, key, busid, resolve, reject) {
         exec(resolve, reject, "zposvefdplugin", "initVEFD", [reg, bus, key, busid]);
     }
    // printKoubeiBill: function (resolve, reject) {
    //     exec(resolve, reject, "zposvefdplugin", "printKoubeiBill", []);
    // },

    // hasPrinter: function (resolve, reject) {
    //     exec(resolve, reject, "zposvefdplugin", "hasPrinter", []);
    // },
};
