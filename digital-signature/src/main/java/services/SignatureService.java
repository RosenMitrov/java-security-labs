package services;

import lombok.extern.slf4j.Slf4j;
import utils.AlgorithmType;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.Optional;

@Slf4j
public class SignatureService {


    public Optional<String> getDigitalSignature(String request,
                                                String privateKey,
                                                AlgorithmType algorithmType) {
        try {

            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);


           KeyFactory keyFactory = KeyFactory.getInstance(algorithmType.getKeyAlgorithm());

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey key = keyFactory.generatePrivate(keySpec);
            Signature signature = Signature.getInstance(algorithmType.getSignatureAlgorithm());
            signature.initSign(key);
            signature.update(request.getBytes(StandardCharsets.UTF_8));

            byte[] signedBytes = signature.sign();
            return Optional.of(Base64.getEncoder().encodeToString(signedBytes));
        } catch (GeneralSecurityException ex) {
            log.error("Cannot generate digital signature {}", ex.getMessage(), ex);
            return Optional.empty();
        }
    }

    public boolean verifySignature(String request,
                                   String digitalSignature,
                                   String publicKeyBase64,
                                   AlgorithmType algorithmType) {
        boolean isValidSignature;
        try {
            PublicKey publicKey = getPublicKey(publicKeyBase64, algorithmType.getKeyAlgorithm());
            byte[] decodedSignature = Base64.getDecoder().decode(digitalSignature);
            Signature signature = Signature.getInstance(algorithmType.getSignatureAlgorithm());
            signature.initVerify(publicKey);
            signature.update(request.getBytes(StandardCharsets.UTF_8));

            isValidSignature = signature.verify(decodedSignature);
            log.info("Signature validation status: {}", isValidSignature);
        } catch (GeneralSecurityException ex) {
            isValidSignature = false;
            log.error("Cannot validate the digital signature: {}", ex.getMessage(), ex);
        }
        return isValidSignature;
    }

    private PublicKey getPublicKey(String publicKeyBase64,
                                   String keyAlgorithm) throws GeneralSecurityException {
        byte[] decodedKey = Base64.getDecoder().decode(publicKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        return keyFactory.generatePublic(keySpec);
    }
}
