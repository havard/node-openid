/* Re-implemented Base64 conversion functions
 * 
 * they are simply forwarding to the nodejs built-in Buffer functions
 */
exports.base64 = {
  decode: function (s) {
    return new Buffer(s, 'base64').toString('binary'); //for node < 4.5.0
    // return Buffer.from(s, 'base64').toString('binary'); //for node >= 4.5.0
  },
  encode: function (s) {
    return new Buffer(s, 'binary').toString('base64'); //for node < 4.5.0
    // return Buffer.from(s, 'binary').toString('base64'); //for node >= 4.5.0
  }
};
