import lombok.extern.slf4j.Slf4j;
import services.SignatureService;
import utils.AlgorithmType;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class DigitalSignatureApplication {
    private static final SignatureService signatureService = new SignatureService();

    public static void main(String[] args) throws IOException {
        rsaSignature();
        ed25519Signature();
    }

    private static void rsaSignature() throws IOException {
        String request = "RSA payload request";
        log.info("Start signing and verifying {}", request);
        Optional<String> stringOptional = signatureService.getDigitalSignature(
                request,
                cleanPem(Files.readString(Paths.get("src/main/resources/RSA/rsa_private.pem")).trim()),
                AlgorithmType.RSA
        );

        stringOptional.ifPresentOrElse(signature -> {
                    try {
                        signatureService.verifySignature(
                                request,
                                signature,
                                cleanPem(Files.readString(Paths.get("src/main/resources/RSA/rsa_public.pem")).trim()),
                                AlgorithmType.RSA
                        );
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                },
                () -> log.info("Signature not present"));
    }

    private static void ed25519Signature() throws IOException {
        String request = "Ed25519 payload request";
        log.info("Start signing and verifying {}", request);
        Optional<String> stringOptional = signatureService.getDigitalSignature(
                request,
                cleanPem(Files.readString(Paths.get("src/main/resources/Ed25519/ed25519_private.pem")).trim()),
                AlgorithmType.ED25519
        );

        stringOptional.ifPresentOrElse(signature -> {
                    try {
                        signatureService.verifySignature(
                                request,
                                signature,
                                cleanPem(Files.readString(Paths.get("src/main/resources/Ed25519/ed25519_public.pem")).trim()),
                                AlgorithmType.ED25519
                        );
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                },
                () -> log.info("Signature not present"));
    }


    private static String cleanPem(String pem) {
        Pattern pattern = Pattern.compile("-----BEGIN (.*)-----|-----END (.*)-----");
        Matcher matcher = pattern.matcher(pem);
        return matcher.replaceAll("").replaceAll("\\s", "");
    }
}
