package utils;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum AlgorithmType {
    RSA("RSA", "SHA256withRSA"),
    ECDSA("EC", "SHA256withECDSA"),
    ED25519("Ed25519", "Ed25519");

    private final String keyAlgorithm;
    private final String signatureAlgorithm;
}
