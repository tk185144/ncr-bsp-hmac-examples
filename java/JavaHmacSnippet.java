import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class JavaHmacSnippet {

    /**
     * createHMAC
     *
     * this is meant to be copied and used in your project to authenticate to the NCR Business Services Platform
     *
     * Disclaimer: This is not proper java format, but it has been reduced for ease of integration for those not
     * familiar with the BSP or java
     *
     * @param sharedKey user's shared key
     * @param secretKey user's secret key
     * @param date date value in ISO-8601 format
     * @param httpMethod GET, POST, PUT, PATCH, etc.
     * @param requestURL full url of the request
     * @param contentType content-type header from request (optional, unless required by API documentation)
     * @param contentMD5 contentMD5 header from request (optional, unless required by API documentation)
     * @param nepApplicationKey nepApplicationKey header from request (optional, unless required by API documentation)
     * @param nepCorrelationID nepCorrelationID header from request (optional, unless required by API documentation)
     * @param nepOrganization nepOrganization header from request (optional, unless required by API documentation)
     * @param nepServiceVersion nepServiceVersion header from request (optional, unless required by API documentation)
     *
     * @returns {string} the value for the Authorization header on a BSP API request
     */
    public static String createHMAC(
            String sharedKey,
            String secretKey,
            String date,
            String httpMethod,
            String requestURL,
            String contentType,
            String contentMD5,
            String nepApplicationKey,
            String nepCorrelationID,
            String nepOrganization,
            String nepServiceVersion) throws MalformedURLException, InvalidKeyException, NoSuchAlgorithmException {

        URL url = new URL(requestURL);
        String uri = "";
        if (url.getPath() != null) {
            uri += url.getPath();
        }
        if (url.getQuery() != null) {
            uri += url.getQuery();
        }

        ZonedDateTime now = ZonedDateTime.from(DateTimeFormatter.RFC_1123_DATE_TIME.parse(date));

        String oneTimeSecret = secretKey + DateTimeFormatter
                .ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
                .format(now);
        String toSign = httpMethod + "\n" + uri;
        if (contentType != null) {
            toSign += "\n" + contentType;
        }
        if (contentMD5 != null) {
            toSign += "\n" + contentMD5;
        }
        if (nepApplicationKey != null) {
            toSign += "\n" + nepApplicationKey;
        }
        if (nepCorrelationID != null) {
            toSign += "\n" + nepCorrelationID;
        }
        if (nepOrganization != null) {
            toSign += "\n" + nepOrganization;
        }
        if (nepServiceVersion != null) {
            toSign += "\n" + nepServiceVersion;
        }

        Mac sha512Hmac = Mac.getInstance("HmacSHA512");
        SecretKeySpec keySpec = new SecretKeySpec(oneTimeSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA512");
        sha512Hmac.init(keySpec);
        byte[] macData = sha512Hmac.doFinal(toSign.getBytes(StandardCharsets.UTF_8));

        String accessKey = sharedKey + ":" + Base64
                .getEncoder()
                .encodeToString(macData);
        return "AccessKey " + accessKey;
    }
}
