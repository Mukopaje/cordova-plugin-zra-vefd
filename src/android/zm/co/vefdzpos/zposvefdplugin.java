package zm.co.vefdzpos;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;
import android.org.apache.commons.codec.binary.Base64;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import android.widget.Toast;
// import android.util.Base64;
// import android.lib.sun.misc.base64decoder.Decoder.BASE64Encoder;
// import android.lib.sun.misc.base64decoder.Decoder.BASE64Decoder;
// import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
// import org.apache.commons.codec.binary.Base64;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.security.NoSuchAlgorithmException;
import java.io.UnsupportedEncodingException;
import android.util.Log;

import android.os.Build.VERSION;
import android.os.Build.VERSION_CODES;

import android.zm.co.vefdzpos.RSA;

/**
 * This class echoes a string called from JavaScript.
 */
public class zposvefdplugin extends CordovaPlugin {

    public static final String url = "http://41.72.108.82:8097/iface/index";
    public static final String jiek1bus = "R-R-01";
    public static final String jiek2bus = "R-R-02";
    public static final String jiek3bus = "R-R-03";
    public static final String jiek4bus = "INFO-MODI-R";
    public static final String jiek5bus = "INVOICE-APP-R";
    public static final String jiek6bus = "INVOICE-REPORT-R";
    public static final String jiek7bus = "INVOICE-RETURN-R";
    public static final String jiek8bus = "INVOICE-RETRIEVE-R";
    public static final String jiek9bus = "SYS-TIME-R";
    public static final String jiek10bus = "UPDATE-APP-R";
    public static final String jiek11bus = "UPDATE-IP-R";
    public static final String jiek12bus = "MONITOR-R";
    public static final String jiek13bus = "ALARM-R";
    public static final String jiek14bus = "RECOVER-R";
    public static String privateKeyString = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJW1V0eSVG+DBtGw1DlZr8N3MGdXEQNtCg95i9ppVn2/wN1wdzO/RZfdsxl8gHyy924dpey9hTEzvFVeqRaMy2FZJoGK5dASPmeI4MGqaAm742evjZEJz/JycjA23M8sgJOvfIMR42mMGgDCCkVYVA8jsPi9t9i/+A0yu/dGXVGdAgMBAAECgYEAgWhRW7KnfgTaviOGL1TRU7sRgiKGuFlm2t2MAG4Rr30zb7aps3dg5tdi22L9hc0FiI/kP3HLUi6QW5MJwk5N9jMVwe4bai30QuvbT6UqMTmHXh/ejGeo3+alcctVcp45NSBhenJM6WerdbGGoh59nCw36qwsuOsKnkEgnhJWsRkCQQDP1yYxwFaBqLEzLl/sKMgRD+1Ume6oX+fd1di/T5nxirODJehtTIhy/5rSkjigW4/qBfILAOWFlbqYBBqEY3S3AkEAuGXdo9R3ZgXqGoY3MLj4Bv4Q/DjM7iu+VqiTuoIXamR1PO3i+YNLneKCp1FHSdzPi9varH/QTCVPhgkSa7bgSwJANlTb2y2Yb5SVnfeFg8q1YiBzviXvSXyotEjuvDQm3gmQG7yRIeFb2hQPePRYcTL+UAL13wKA/YbCnHKWK/2DyQJAZCeP9sgUAen8eWOk3mXY8ZNVjmkbhdFklJUDiC3YogTmWK2stnFFxP+ej1pqKggxAnnrj/3sGS+6vcZ3puGxeQJBALw4/QfGP4vap+VJrUT7Gufo4KsiY6LRFbe7bUjcr+FUnkjOX5RiO0x0NezRdjb16zU2DhtPC+X5AngcA0ySOzc=";
    public static final String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmM17jKu10p+BLZ9jYHmQynYJayyhqytnZizRXzeTwCK4Ds7AptjMhye2EVIG+oECAp26PcVNA/0YFvT4X8ifkSOat7wyxmR80de64CYlJHPRSIuRiyfmLu2IgIRNCXW3qbsThLEO59WZKeIdtwGLTX/YHA3etbXBverngxr/i5wIDAQAB";
    // public static final String jiek1mingwen =
    // "{\"license\":\"198127248312\",\"sn\":\"187603000010\",\"sw_version\":\"1.2\",\"model\":\"IP-100\",\"manufacture\":\"Inspur\",\"imei\":\"359833002198832\",\"os\":\"linux2.6\",\"hw_sn\":\"3458392322\"}";
    public static final String init1zpos = "{\"license\":\"684821956905\",\"sn\":\"951711000831\",\"sw_version\":\"2.14\",\"model\":\"IS-100\",\"manufacture\":\"Inspur\",\"imei\":\"865740037141467\",\"os\":\"Linux2.6.36\",\"hw_sn\":\"\",\"id\":null}";
    public static final String jiek2mingwen = "{\"id\":\"010800000010\"}";
    public static final String jiek3mingwen = "{\"id\":\"010800000010\"}";
    public static final String jiek4mingwen = "{\"id\":\"010100000006\"}";
    public static final String jiek5mingwen = "{\"id\":\"010100000019\"}";
    public static final String jiek6mingwen = "{\"declaration-info\":{\"invoice-code\":\"000180110000\",\"invoice-number\":\"00048714\",\"buyer-tpin\":\"\",\"buyer-vat-acc-name\":\"\",\"buyer-name\":\"\",\"buyer-address\":\"\",\"buyer-tel\":\"\",\"tax-amount\":1.51,\"total-amount\":10.98,\"total-discount\":0.0,\"invoice-status\":\"01\",\"invoice-issuer\":\"00026\",\"invoicing-time\":1523965682,\"old-invoice-code\":\"\",\"old-invoice-number\":\"\",\"fiscal-code\":\"8466581023551969t077\",\"memo\":\"064824-20180417-011-00041-00136-9121636352\",\"sale-type\":0,\"currency-type\":\"ZMW\",\"conversion-rate\":1.0,\"local-purchase-order\":\"\",\"voucher-PIN\":null,\"items-info\":[{\"no\":\"1\",\"tax-category-code\":\"A\",\"tax-category-name\":\"Standard Rated\",\"name\":\"Cupcake Plain\",\"barcode\":\"02412290000000\",\"count\":2.0,\"amount\":5.98,\"tax-amount\":0.82,\"discount\":0.0,\"unit-price\":2.99,\"tax-rate\":0.16,\"rrp\":0.0},{\"no\":\"2\",\"tax-category-code\":\"A\",\"tax-category-name\":\"Standard Rated\",\"name\":\"Airtel...5\",\"barcode\":\"05020312000364\",\"count\":1.0,\"amount\":5.0,\"tax-amount\":0.69,\"discount\":0.0,\"unit-price\":5.0,\"tax-rate\":0.16,\"rrp\":0.0}],\"tax-info\":[{\"tax-code\":\"A\",\"tax-name\":\"Standard Rated\",\"tax-rate\":0.16,\"tax-value\":1.51}]},\"id\":\"010100000007\"}";
    public static final String jiek6mingwen1 = "{\"declaration-info\":{\"invoice-code\":\"000180110000\",\"invoice-number\":\"00047101\",\"buyer-tpin\":\"\",\"buyer-vat-acc-name\":\"\",\"buyer-name\":\"\",\"buyer-address\":\"\",\"buyer-tel\":\"\",\"tax-amount\":0.0,\"total-amount\":-93.0,\"total-discount\":0.0,\"invoice-status\":\"02\",\"invoice-issuer\":\"00098\",\"invoicing-time\":1523613629,\"old-invoice-code\":\"\",\"old-invoice-number\":\"\",\"fiscal-code\":\"11545301343534070002\",\"memo\":\"002874-20180413-095-00098-00008-9108177670\",\"sale-type\":0,\"currency-type\":\"ZMW\",\"conversion-rate\":1.0,\"local-purchase-order\":\"\",\"voucher-PIN\":null,\"items-info\":[{\"no\":\"1\",\"tax-category-code\":\"D\",\"tax-category-name\":\"Exempt\",\"name\":\"Money Receive\",\"barcode\":\"06001001790789\",\"count\":1.0,\"amount\":-93.0,\"tax-amount\":0.0,\"discount\":0.0,\"unit-price\":-93.0,\"tax-rate\":0.0,\"rrp\":0.0}],\"tax-info\":[{\"tax-code\":\"D\",\"tax-name\":\"Exempt\",\"tax-rate\":0.0,\"tax-value\":0.0}]},\"id\":\"010100000006\"}";
    public static final String jiek7mingwen = "{\"id\":\"010100000006\",\"turn-items\":[{\"invoice-code\":\"000180110000\",\"invoice-number-begin\":\"00047097\",\"invoice-number-end\":\"00001756\"}]}";
    public static final String jiek8mingwen = "{\"id\":\"010100000006\",\"code\":\"000180110000\",\"number\":\"00047097\"}";
    public static final String jiek9mingwen = "{\"id\":\"010100000006\"}";
    public static final String jiek10mingwen = "{\"id\":\"010100000006\",\"version\":\"1.1\"}";
    public static final String jiek11mingwen = "{\"id\":\"010100000006\"}";
    public static final String jiek12mingwen = "{\"id\":\"010100000006\",\"batch\":\"20180311001\",\"lon\":0,\"lat\":0,\"sw_version\":\"1.5\"}";
    public static final String jiek13mingwen = "{\"id\":\"010100000006\",\"level\":\"02\",\"info\":\"2586336655566655\"}";
    public static final String jiek14mingwen = "{\"id\":\"010100000006\"}";

    private static Base64 base64 = null;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        base64 = new Base64();
        Toast.makeText(webView.getContext(), "Initialization Statrted " + "ZRA ZPOS VEFD", Toast.LENGTH_LONG).show();
        // jiami();

    }

    @Override
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext) throws JSONException {
        if (action.equals("hasPrinter")) {
            // hasPrinter(callbackContext);
            return true;
        } else if (action.equals("initVEFD")) {
            initVEFD(data.getString(0), data.getString(1), data.getString(2), data.getString(3), callbackContext);
            return true;
        }
        return false;
    }

    public void initVEFD(String reg, String bus, String key, String busid, final CallbackContext callbackContext)
            throws JSONException {
        try {
            // Base64 base64 = new Base64();
            // System.out.println("Request Business data " + bus);
            byte[] sjm = new byte[] {};
            String bus_id = busid;
            final String privateKeyString = key;
            PrivateKey pri = getPriKey("RSA");
            System.out.println("RSA Generated Local " + pri);

            if (!bus_id.equals("R-R-01") && !bus_id.equals("R-R-02")) {
                byte[] fhsjm = decryptRSA(base64.decode(key), pri, 2048, 11, "RSA/ECB/PKCS1Padding");
                System.out.println("RSA decrypted random code " + new String(fhsjm));
                sjm = fhsjm;
            } else if (bus_id.equals("R-R-02")) {
                // Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                // cipher.init(Cipher.PRIVATE_KEY, pri);
                // System.out.println("Base64 decoded sectret " + base64.decode(key));
                // byte[] s = base64.decode(key);
                // System.out.println("RSA decrypted secret key " + new String(s, "UTF-8"));
                // String y = new String(s, "UTF-8");
                // sjm = "B71a6528".getBytes();

                // byte[] fhsjm = decryptRSA(base64.decode(key), pri, 2048, 11,
                // "RSA/ECB/PKCS1Padding");
                // System.out.println("RSA解密后随机码 " + new String(fhsjm));
                // sjm = fhsjm;
                sjm = key.getBytes();
                // String l = reg.substring(reg.length() - 8);
                // sjm = l.getBytes();
            } else {
                sjm = key.getBytes();
            }

            byte[] sjmMiwen = encryptRSA(sjm, pri, 3072, 11, "RSA/ECB/PKCS1Padding");
            String sjmBase64 = new String(base64.encode(sjmMiwen));

            // System.out.println("Generated Private key " + pri);
            if (sjmBase64 != null) {
                Pattern p = Pattern.compile("\\s*|\t|\r|\n");
                Matcher m = p.matcher(sjmBase64);
                sjmBase64 = m.replaceAll("");
            }
            // }
            Key k = toKey(sjm);
            // System.out.println("New Key used " + k);
            byte[] encryptData = encryptDES(bus.getBytes(), k);
            String content = new String(base64.encode(encryptData));
            if (content != null) {
                Pattern p = Pattern.compile("\\s*|\t|\r|\n");
                Matcher m = p.matcher(content);
                content = m.replaceAll("");
            }
            String sign = new String(base64.encode(md5(content)));
            System.out.println("The value of the encrypted sign " + sign);
            String params = "";
            if (!bus_id.equals("R-R-01")) {
                params = "{\"message\":{\"body\":{\"data\":{\"device\":\"" + reg
                        + "\",\"serial\":\"688877\",\"sign\":\"" + sign + "\",\"key\":\"" + key + "\",\"bus_id\":\""
                        + bus_id + "\",\"content\":\"" + content + "\"}}}}";
            } else {
                params = "{\"message\":{\"body\":{\"data\":{\"device\":\"" + reg
                        + "\",\"serial\":\"688877\",\"sign\":\"" + sign + "\",\"key\":\"\",\"bus_id\":\"" + bus_id
                        + "\",\"content\":\"" + content + "\"}}}}";

            }

            // String paramsBase64 = RSA.encrypt(sjm, "21956905");
            System.out.println("Data Sent " + params);
            String fh = sendPost(url, params);
            System.out.println("Response message " + fh);
            // JSONObject job = JSONObject.fromObject(fh);
            JSONObject job = new JSONObject(fh);
            JSONObject message = (JSONObject) job.get("message");
            JSONObject body = (JSONObject) message.get("body");
            JSONObject data = (JSONObject) body.get("data");
            String fhkey = (String) data.get("key");
            String fhcontent = (String) data.get("content");
            System.out.println("Return the Key value to be decrypted " + fhkey);
            System.out.println("Returns the value of the content to be decrypted " + fhcontent);
            if (!bus_id.equals("R-R-01")) {
                byte[] fhsjm = decryptRSA(base64.decode(fhkey), pri, 2048, 11, "RSA/ECB/PKCS1Padding");
                System.out.println("RSA decrypted random code " + new String(fhsjm));
                sjm = fhsjm;
            }
            Key k2 = toKey(sjm);
            byte[] decryptDES = decryptDES(base64.decode(fhcontent), k2);
            String fhmingwen = new String(decryptDES);
            System.out.println("Decrypted content data " + fhmingwen);
            callbackContext.success(fhmingwen);
            // callbackContext.success("Response from data " + data);
        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
            callbackContext.error(e.getMessage());
        }

    }

    public static String decryptContent(String key, String content) throws Exception {
        PrivateKey pri = getPriKey("RSA");
        byte[] sjm = decryptRSA(base64.decode(key), pri, 2048, 11, "RSA/ECB/PKCS1Padding");
        System.out.println("RSA decrypted random code：" + new String(sjm));
        // "00000003".getBytes()
        Key k = toKey("30026147".getBytes());
        // Key k = toKey("87865651".getBytes());
        // Key k = sjm;
        byte[] decryptDES = decryptDES(base64.decode(content), k);
        String mingwen = new String(decryptDES);
        System.out.println("Decrypted content data:" + mingwen);
        return new String(mingwen);
    }

    // Decrypt with public key (test environment determines if there is a problem
    // with the request)
    public static void jiemi() throws Exception {
        String key = "Kv27UOkvOUF9tygkzDxKbr89MRtSnhhZoMM/G5kneUp3wJHS7uYJRJgLRbEEo1Sy57IqrffaL63fw6OZ9HrEHRuFd1LveQc4NGLn9LUr+0J8SB6XtIW+9MD/VZBgfsVZMCs/27VR60IanFN2IppNtaA6+i38xzoAXhPdivYNdmHWpW0kKBX40EpUzNU3WVA98f/khil90gxpidvbM49xJpeu3fj4ZVrF0bkqO+oSpz23llrrF2lhP8uljr4TvCCXQCnkBrJSfbfNkn4izNcp3loR8ARYuKx8dZgjJBcptgW8hh/EuAwN/ZMmpfwEvAidjqdXCOQlIBRf0X1XHn0476VRm4o7lyZOmsp23W/IeY7TArpPvVaX5ZzE1+zH0uVQbbtPMMqPLQKZNK6pivhKdVEqdY8Cipfo4w7EpvE4Ez+E/xp9ihqvOcqA+1uTh1NrS/7ftU9laodFbjn8/fLdgCJ4TkPfsvR1+6+ycMWiHJiwtyW0DkwLZIRjV9JSnUV2s+M+fExxC1cF9TNUvZhBAVQ0XiS4pGwiC96NJqkADDRFkHClDI80wJpsyt3yaJ9p0JB+BdBfa9UjGCkj5kRQ11ghYmmeiQEB979gQ+DWyP84l6mXA/SmyNvwSfum5MUGk1i1Dxq/iP33bushMZ4eGhIXIEyo2/aR2zFKjQktdKaF+EvIQLymS+8LiRui0J1e6j4GiO8aCNz0vU2A8yLsmdL9TIaWearNw/D0bohkREn5oKuzqUGtOl4EIf17BnYeCbVbWNUPIILrjMOhfjllb5zCYlxChTBEhGUbyYcIQxT/5YsN8PvCF5kMDyg9YyBUcA5KboVNeuriIw==";
        String content = "e2+Dga1Rhhz587dugo92N023EvR/Z0nKVmC3v4RGELI=";
        PublicKey pub = getPubKey("RSA");
        byte[] sjm = decryptRSAPub(base64.decode(key), pub, 2048, 11, "RSA/ECB/PKCS1Padding");
        Key k2 = toKey(sjm); // Only for interface 1
        byte[] decryptDES = decryptDES(base64.decode(content), k2);
        String fhmingwen = new String(decryptDES);
        System.out.println("Decrypted content data " + fhmingwen);
        // callbackContext.success("Decrypted content data " + fhmingwen);
    }

    /**
     * 
     * @param minwen Passed string-processed plaintext (" --> \")
     * @return
     * @throws Exception
     */
    public static String jiami(String mingwen, byte[] sjm) throws Exception {
        try {
            // Read file generation private key
            PrivateKey pri = getPriKey("RSA");
            System.out.println("Private Key: " + pri);
            // Encrypt the plain text of the random number
            byte[] sjmMiwen = encryptRSA(sjm, pri, 2048, 11, "RSA/ECB/PKCS1Padding");
            // Encode random ciphertext
            String sjmBase64 = new String(base64.encode(sjmMiwen));
            System.out.println(
                    "Output the ciphertext of the random number and then the value of Base64             " + sjmBase64);
            Key k = toKey(sjm);
            byte[] encryptData = encryptDSE(mingwen.getBytes(), k);
            String content = new String(base64.encode(encryptData));
            System.out.println("Encrypted content value              " + content);

            String sign = new String(base64.encode(md5(content)));
            System.out.println("The value of the encrypted sign                  " + sign);
            return sign;

        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
            throw new Exception("JIAMI ERROR: ", e);
        }

    }

    public static byte[] desGenerateKey() throws Exception {

        KeyGenerator generator = KeyGenerator.getInstance("DES");
        generator.init(64);
        Key encryptionKey = generator.generateKey();
        return encryptionKey.getEncoded();
    }

    public static String jiemi(String key, String content) throws Exception {
        PrivateKey pri = getPriKey("RSA");
        byte[] sjm = decryptRSA(base64.decode(key), pri, 2048, 11, "RSA/ECB/PKCS1Padding");
        System.out.println("RSA decrypted random code：" + new String(sjm));
        // "00000003".getBytes()
        Key k = toKey("30026147".getBytes());
        // Key k = toKey("87865651".getBytes());
        byte[] decryptDES = decryptDES(base64.decode(content), k);
        String mingwen = new String(decryptDES);
        System.out.println("Decrypted content data:" + mingwen);
        return new String(mingwen);
    }

    public static byte[] decryptDES(byte[] data, Key key) throws Exception {
        // Instantiation
        Cipher cipher = Cipher.getInstance("DES/ECB/ZeroBytePadding");
        // Initialize with key, set to decrypt mode
        cipher.init(Cipher.DECRYPT_MODE, key);
        // Performing operations
        return cipher.doFinal(data);
    }

    public static PrivateKey getPriKey(String keyAlgorithm) throws Exception {
        PrivateKey privateKey = null;
        try {
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(base64.decode(privateKeyString));
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            privateKey = keyFactory.generatePrivate(priPKCS8);
            System.out.println("Private key gen supposed :" + privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception("Private key error: ", e);
        }
        return privateKey;
    }

    public static PublicKey getPubKey(String keyAlgorithm) {
        PublicKey publicKey = null;
        try {
            publicKey = getPublicKey(keyAlgorithm);
        } catch (Exception e) {
            System.out.println("Error loading public key!");
        }
        return publicKey;
    }

    public static PrivateKey getPrivateKey(String keyAlgorithm) throws Exception {
        try {
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(base64.decode(privateKeyString));
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            PrivateKey privateKey = keyFactory.generatePrivate(priPKCS8);
            return privateKey;
        } catch (Exception e) {
            throw new Exception("READ PRIVATE KEY ERROR:", e);
        }
    }

    public static PublicKey getPublicKey(String keyAlgorithm) throws Exception {
        try {
            X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(base64.decode(publicKey));
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            PublicKey publicKey = keyFactory.generatePublic(pubX509);
            return publicKey;
        } catch (Exception e) {
            throw new Exception("READ PRIVATE KEY ERROR:", e);
        }
    }

    public static byte[] decryptRSA(byte[] encryptedBytes, PrivateKey privateKey, int keyLength, int reserveSize,
            String cipherAlgorithm) throws Exception {
        int keyByteSize = keyLength / 8;
        int decryptBlockSize = keyByteSize - reserveSize;
        int nBlock = encryptedBytes.length / keyByteSize;
        ByteArrayOutputStream outbuf = null;
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            outbuf = new ByteArrayOutputStream(nBlock * decryptBlockSize);
            for (int offset = 0; offset < encryptedBytes.length; offset += keyByteSize) {
                int inputLen = encryptedBytes.length - offset;
                if (inputLen > keyByteSize) {
                    inputLen = keyByteSize;
                }
                byte[] decryptedBlock = cipher.doFinal(encryptedBytes, offset, inputLen);
                outbuf.write(decryptedBlock);
            }
            outbuf.flush();
            return outbuf.toByteArray();
        } catch (Exception e) {
            throw new Exception("DEENCRYPT ERROR 1:", e);
        } finally {
            try {
                if (outbuf != null) {
                    outbuf.close();
                }
            } catch (Exception e) {
                outbuf = null;
                throw new Exception("CLOSE ByteArrayOutputStream ERROR:", e);
            }
        }
    }

    public static byte[] decryptRSAPub(byte[] encryptedBytes, PublicKey publicKey, int keyLength, int reserveSize,
            String cipherAlgorithm) throws Exception {
        int keyByteSize = keyLength / 8;
        int decryptBlockSize = keyByteSize - reserveSize;
        int nBlock = encryptedBytes.length / keyByteSize;
        ByteArrayOutputStream outbuf = null;
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);

            outbuf = new ByteArrayOutputStream(nBlock * decryptBlockSize);
            for (int offset = 0; offset < encryptedBytes.length; offset += keyByteSize) {
                int inputLen = encryptedBytes.length - offset;
                if (inputLen > keyByteSize) {
                    inputLen = keyByteSize;
                }
                byte[] decryptedBlock = cipher.doFinal(encryptedBytes, offset, inputLen);
                outbuf.write(decryptedBlock);
            }
            outbuf.flush();
            return outbuf.toByteArray();
        } catch (Exception e) {
            throw new Exception("DEENCRYPT ERROR 2:", e);
        } finally {
            try {
                if (outbuf != null) {
                    outbuf.close();
                }
            } catch (Exception e) {
                outbuf = null;
                throw new Exception("CLOSE ByteArrayOutputStream ERROR:", e);
            }
        }
    }

    public static byte[] md5(String s) {
        try {
            MessageDigest algorithm = MessageDigest.getInstance("MD5");
            algorithm.reset();
            algorithm.update(s.getBytes("UTF-8"));
            byte[] messageDigest = algorithm.digest();
            return messageDigest;
        } catch (Exception var3) {
            // LOGGER.error("MD5 Error...", var3);
            return null;
        }
    }

    public static byte[] encryptDSE(byte[] data, Key key) throws Exception {
        // Instantiation
        Cipher cipher = Cipher.getInstance("DES/ECB/ZeroBytePadding", "BC");
        // Initialize with key, set to encryption mode
        cipher.init(Cipher.ENCRYPT_MODE, key);
        // Performing operations
        return cipher.doFinal(data);
    }

    public static byte[] decodeBase64(String input) throws Exception {
        Class<?> clazz = Class.forName("android.util.Base64");
        Method mainMethod = clazz.getMethod("decode", String.class);
        mainMethod.setAccessible(true);
        Object retObj = mainMethod.invoke(null, input);
        return (byte[]) retObj;
    }

    private String decodeBase64String(String coded) {
        byte[] valueDecoded = new byte[0];
        try {
            valueDecoded = base64.decode(coded);
        } catch (Exception e) {
            Log.d("Error", e.getMessage());
        }
        return new String(valueDecoded);
    }

    /*
     * Get Cipher according to the android version
     */
    private static Cipher getCipher() {
        try {
            if (VERSION.SDK_INT < VERSION_CODES.M) { // below android m
                return Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL"); // error in android 6:
                                                                                     // InvalidKeyException: Need RSA
                                                                                     // private or public key
            } else { // android m and above
                return Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidKeyStoreBCWorkaround"); // error in android 5:
                                                                                                  // NoSuchProviderException:
                                                                                                  // Provider not
                                                                                                  // available:
                                                                                                  // AndroidKeyStoreBCWorkaround
            }
        } catch (Exception exception) {
            throw new RuntimeException("getCipher: Failed to get an instance of Cipher", exception);
        }
    }

    public static byte[] encryptRSA(byte[] plainBytes, PrivateKey privateKey, int keyLength, int reserveSize,
            String cipherAlgorithm) throws Exception {
        int keyByteSize = keyLength / 8;
        int encryptBlockSize = keyByteSize - reserveSize;
        int nBlock = plainBytes.length / encryptBlockSize;
        if ((plainBytes.length % encryptBlockSize) != 0) {
            nBlock += 1;
        }
        ByteArrayOutputStream outbuf = null;
        try {
            // Cipher cipher = getCipher();
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);

            outbuf = new ByteArrayOutputStream(nBlock * keyByteSize);
            for (int offset = 0; offset < plainBytes.length; offset += encryptBlockSize) {
                int inputLen = plainBytes.length - offset;
                if (inputLen > encryptBlockSize) {
                    inputLen = encryptBlockSize;
                }
                byte[] encryptedBlock = cipher.doFinal(plainBytes, offset, inputLen);
                outbuf.write(encryptedBlock);
            }
            outbuf.flush();
            return outbuf.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception("ENCRYPT ERROR 3:", e);

        } finally {
            try {
                if (outbuf != null) {
                    outbuf.close();
                }
            } catch (Exception e) {
                outbuf = null;
                e.printStackTrace();
                throw new Exception("CLOSE ByteArrayOutputStream ERROR:", e);

            }
        }
    }

    public static byte[] encryptRSAPub(byte[] plainBytes, PublicKey publicKey, int keyLength, int reserveSize,
            String cipherAlgorithm) throws Exception {
        int keyByteSize = keyLength / 8;
        int encryptBlockSize = keyByteSize - reserveSize;
        int nBlock = plainBytes.length / encryptBlockSize;
        if ((plainBytes.length % encryptBlockSize) != 0) {
            nBlock += 1;
        }
        ByteArrayOutputStream outbuf = null;
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            outbuf = new ByteArrayOutputStream(nBlock * keyByteSize);
            for (int offset = 0; offset < plainBytes.length; offset += encryptBlockSize) {
                int inputLen = plainBytes.length - offset;
                if (inputLen > encryptBlockSize) {
                    inputLen = encryptBlockSize;
                }
                byte[] encryptedBlock = cipher.doFinal(plainBytes, offset, inputLen);
                outbuf.write(encryptedBlock);
            }
            outbuf.flush();
            return outbuf.toByteArray();
        } catch (Exception e) {
            throw new Exception("ENCRYPT ERROR 4:", e);
        } finally {
            try {
                if (outbuf != null) {
                    outbuf.close();
                }
            } catch (Exception e) {
                outbuf = null;
                throw new Exception("CLOSE ByteArrayOutputStream ERROR:", e);
            }
        }
    }

    public static Key toKey(byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "DES");
        return secretKey;
    }

    public static String sendPost(String url, String Params) throws IOException {
        OutputStreamWriter out = null;
        BufferedReader reader = null;
        String response = "";
        try {
            URL httpUrl = null; // HTTP URL class Use this class to create a connection
            // Create a URL
            httpUrl = new URL(url);
            // establish connection
            HttpURLConnection conn = (HttpURLConnection) httpUrl.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("connection", "keep-alive");
            conn.setUseCaches(false);// Set not to cache
            conn.setInstanceFollowRedirects(true);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.connect();
            // POST request
            out = new OutputStreamWriter(conn.getOutputStream());
            out.write(Params);
            out.flush();
            // Read response
            reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String lines;
            while ((lines = reader.readLine()) != null) {
                lines = new String(lines.getBytes(), "utf-8");
                response += lines;
            }
            reader.close();
            // Disconnect
            conn.disconnect();
            // log.info(response.toString());
        } catch (Exception e) {
            System.out.println("An exception occurred while sending a POST request! " + e);
            e.printStackTrace();
        }
        // Use the finally block to close the output stream, input stream
        finally {
            try {
                if (out != null) {
                    out.close();
                }
                if (reader != null) {
                    reader.close();
                }
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        return response;
    }

    /*
     * Test converting string to MD5 hash
     */
    public static String md5String(String s) {
        try {
            // Create MD5 Hash
            MessageDigest digest = java.security.MessageDigest.getInstance("MD5");
            digest.update(s.getBytes());
            byte messageDigest[] = digest.digest();

            // Create Hex String
            StringBuffer hexString = new StringBuffer();
            for (int i = 0; i < messageDigest.length; i++)
                hexString.append(Integer.toHexString(0xFF & messageDigest[i]));

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }

    /*
     * DES encode text
     */
    public static byte[] encryptDES(byte[] data, Key key) throws Exception {
        // 实例化
        Cipher cipher = Cipher.getInstance("DES/ECB/ZeroBytePadding", "BC");
        // 使用密钥初始化，设置为加密模式
        cipher.init(Cipher.ENCRYPT_MODE, key);
        // 执行操作
        return cipher.doFinal(data);
    }

    public String encryptDES(String content, String k) {
        String encrypted = "";
        try {
            DESKeySpec keySpec = new DESKeySpec(k.getBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey key = keyFactory.generateSecret(keySpec);
            byte[] cleartext = content.getBytes();

            Cipher cipher = Cipher.getInstance("DES"); // cipher is not thread safe
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encrypted = new String(base64.encode(cipher.doFinal(cleartext)));

        } catch (Exception e) {
            e.printStackTrace();
        }
        return encrypted;
    }
}
