// this is meant to be copied and used in your project to authenticate to the NCR Business Services Platform
//
// Disclaimer: This is not proper javascript format, but it has been reduced for ease of integration for those not
//				familiar with the BSP or javascript
//
// createHMAC
//
// Arguments:
// sharedKey - user's shared key
// secretKey - user's secret key
// date - date value in ISO-8601 format
// httpMethod - GET, POST, PUT, PATCH, etc.
// requestURL - full url of the request
// contentType - content-type header from request (optional, unless required by API documentation)
// contentMD5 - contentMD5 header from request (optional, unless required by API documentation)
// nepApplicationKey - nepApplicationKey header from request (optional, unless required by API documentation)
// nepCorrelationID - nepCorrelationID header from request (optional, unless required by API documentation)
// nepOrganization - nepOrganization header from request (optional, unless required by API documentation)
// nepServiceVersion - nepServiceVersion header from request (optional, unless required by API documentation)
//
// returns the header for the Authorization header on a BSP API request
function createHMAC(
  sharedKey,
  secretKey,
  date,
  httpMethod,
  requestURL,
  contentType,
  contentMD5,
  nepApplicationKey,
  nepCorrelationID,
  nepOrganization,
  nepServiceVersion) {

  const sdk = require('postman-collection');
  const cryptojs = require('crypto-js');

  const url = new sdk.Url(requestURL);
  const uri = encodeURI(url.getPathWithQuery());

  const d = new Date();
  d.setMilliseconds(0);
  const time = d.toISOString();

  const oneTimeSecret = secretKey + time;
  let toSign = httpMethod + "\n" + uri;
  if (contentType) {
    toSign += "\n" + contentType.trim();
  }
  if (contentMD5) {
    toSign += "\n" + contentMD5.trim();
  }
  if (nepApplicationKey) {
    toSign += "\n" + nepApplicationKey.trim();
  }
  if (nepCorrelationID) {
    toSign += "\n" + nepCorrelationID.trim();
  }
  if (nepOrganization) {
    toSign += "\n" + nepOrganization.trim();
  }
  if (nepServiceVersion) {
    toSign += "\n" + nepServiceVersion.trim();
  }

  const key = cryptojs.HmacSHA512(toSign, oneTimeSecret);
  const accessKey = sharedKey + ":" + cryptojs.enc.Base64.stringify(key);
  return "AccessKey " + accessKey;
}
