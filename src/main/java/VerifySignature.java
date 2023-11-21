import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.ECElGamalDecryptor;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.engines.ECDSASigner;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.RandomDSAKCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.StringReader;
import java.security.Security;
import java.util.Base64;

public class VerifySignature {

    public static void main(String[] args) {
        // Add Bouncy Castle as a security provider
        Security.addProvider(new BouncyCastleProvider());

        // Sample XML data
        String sampleXmlData = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<values>\n" +
                "   <value transactionId=\"1\" context=\"Transaction.Begin\">\n" +
                "      <signedData format=\"OCMF\" encoding=\"plain\" transactionId=\"29\">OCMF|{\"FV\":\"1.0\",\"GI\":\"KEBA_KCP30\",\"GS\":\"17619300\",\"GV\":\"2.8.5\",\"PG\":\"T32\",\"IS\":false,\"IL\":\"NONE\",\"IF\":[\"RFID_NONE\",\"OCPP_NONE\",\"ISO15118_NONE\",\"PLMN_NONE\"],\"IT\":\"NONE\",\"ID\":\"\",\"RD\":[{\"TM\":\"2019-08-13T10:03:15,000+0000 I\",\"TX\":\"B\",\"EF\":\"\",\"ST\":\"G\",\"RV\":0.2596,\"RI\":\"1-b:1.8.0\",\"RU\":\"kWh\"},{\"TM\":\"2019-08-13T10:03:36,000+0000 R\",\"TX\":\"E\",\"EF\":\"\",\"ST\":\"G\",\"RV\":0.2597,\"RI\":\"1-b:1.8.0\",\"RU\":\"kWh\"}]}|{\"SD\":\"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699\"}</signedData>\n" +
                "        <publicKey encoding=\"hex\">3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE</publicKey>\n" +
                "    </value>\n" +
                "</values>";

        // Parse XML
        Element root = parseXmlString(sampleXmlData);
        Element valueElement = (Element) root.getElementsByTagName("value").item(0);

        // Extract relevant data
        byte[] publicKeyBytes = hexStringToByteArray(valueElement.getElementsByTagName("publicKey").item(0).getTextContent().trim());
        String[] signedData = valueElement.getElementsByTagName("signedData").item(0).getTextContent().trim().split("\\|");
        byte[] dataBytes = signedData[0].getBytes();
        byte[] signatureBytes = hexStringToByteArray(signedData[1]);

        // Verify the signature
        verifyEcdsaSignature(publicKeyBytes, signatureBytes, dataBytes);
    }

    private static Element parseXmlString(String xmlString) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            InputSource inputSource = new InputSource(new StringReader(xmlString));
            return builder.parse(inputSource).getDocumentElement();
        } catch (ParserConfigurationException | SAXException | java.io.IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void verifyEcdsaSignature(byte[] publicKeyBytes, byte[] signatureBytes, byte[] dataBytes) {
        try {
            ECNamedCurveParameterSpec spec = SECNamedCurves.getByName("secp256r1");
            ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(spec);
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.init(keyGenParams);

            AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

            ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
            ECKeyParameters privateKey = (ECKeyParameters) keyPair.getPrivate();

            ECDSASigner signer = new ECDSASigner(new RandomDSAKCalculator());
            signer.init(false, publicKey);

            // Convert Bouncy Castle ECDSA signature to Java signature format
            byte[] javaSignature = new byte[64];
            System.arraycopy(signatureBytes, 1, javaSignature, 0, 32);
            System.arraycopy(signatureBytes, 33, javaSignature, 32, 32);

            // Verify the signature
            if (signer.verifySignature(dataBytes, javaSignature)) {
                System.out.println("Signature is valid.");
            } else {
                System.out.println("Signature is invalid.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }
}
