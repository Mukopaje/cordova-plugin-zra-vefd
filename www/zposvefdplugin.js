var exec = require('cordova/exec');

module.exports = {

    efdInit: function (resolve, reject) {
        exec(resolve, reject, "zposvefdplugin", "efdInit", []);
    }
    // printerRunPaper: function (msg, resolve, reject) {
    //     exec(resolve, reject, "zposvefdplugin", "printerRunPaper", [msg]);
    // },
    // printKoubeiBill: function (resolve, reject) {
    //     exec(resolve, reject, "zposvefdplugin", "printKoubeiBill", []);
    // },

    // hasPrinter: function (resolve, reject) {
    //     exec(resolve, reject, "zposvefdplugin", "hasPrinter", []);
    // },
};
