using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace BSPExamples
{
    public class CSharpHmacSnippet
    {
        /// <summary>
        /// This is meant to be copied and used in your project to authenticate to the NCR Business Services Platform
        /// </summary>
        /// <param name="sharedKey">user's shared key</param>
        /// <param name="secretKey">user's secret key</param>
        /// <param name="date">date value in ISO-8601 format</param>
        /// <param name="httpMethod">GET, POST, PUT, PATCH, etc.</param>
        /// <param name="requestURL">full url of the request</param>
        /// <param name="contentType">content-type header from request (optional, unless required by API documentation)</param>
        /// <param name="contentMD5">contentMD5 header from request (optional, unless required by API documentation)</param>
        /// <param name="nepApplicationKey">nepApplicationKey header from request (optional, unless required by API documentation)</param>
        /// <param name="nepCorrelationID">nepCorrelationID header from request (optional, unless required by API documentation)</param>
        /// <param name="nepOrganization">nepOrganization header from request (optional, unless required by API documentation)</param>
        /// <param name="nepServiceVersion">nepServiceVersion header from request (optional, unless required by API documentation)</param>
        /// <returns></returns>
        public static string CreateHMAC(
            string sharedKey,
            string secretKey,
            string date,
            string httpMethod,
            string requestURL,
            string contentType = null,
            string contentMD5 = null,
            string nepApplicationKey = null,
            string nepCorrelationID = null,
            string nepOrganization = null,
            string nepServiceVersion = null)
        {
            Uri url = new Uri(requestURL);

            string pathAndQuery = url.PathAndQuery;

            string secretDate = DateTime.ParseExact(date, "R", null).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            string oneTimeSecret = secretKey + secretDate;
            string toSign = httpMethod + "\n" + pathAndQuery;

            if (contentType != null)
            {
                toSign += "\n" + contentType;
            }
            if (contentMD5 != null)
            {
                toSign += "\n" + contentMD5;
            }
            if (nepApplicationKey != null)
            {
                toSign += "\n" + nepApplicationKey;
            }
            if (nepCorrelationID != null)
            {
                toSign += "\n" + nepCorrelationID;
            }
            if (nepOrganization != null)
            {
                toSign += "\n" + nepOrganization;
            }
            if (nepServiceVersion != null)
            {
                toSign += "\n" + nepServiceVersion;
            }

            var data = Encoding.UTF8.GetBytes(toSign);
            var key = Encoding.UTF8.GetBytes(oneTimeSecret);

            byte[] hash = null;

            using (HMACSHA512 shaM = new HMACSHA512(key))
            {
                hash = shaM.ComputeHash(data);
            }

            string accessKey = sharedKey + ":" + System.Convert.ToBase64String(hash);
            return "AccessKey " + accessKey;
        }
    }
}
