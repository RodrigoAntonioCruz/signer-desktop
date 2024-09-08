package com.signer.service;

import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.signer.util.Constants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

@Service
public class PDFSignerService {
    private static final Logger log = LoggerFactory.getLogger(PDFSignerService.class);
    private final KeyStoreService keyStoreService;
    public PDFSignerService(KeyStoreService keyStoreService) {
        this.keyStoreService = keyStoreService;
    }

    public void signPDF(byte[] content, Path signedFilePath, String certificateDetails) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        keyStoreService.initializeKeyStore(certificateDetails);
        PrivateKey privateKey = keyStoreService.getPrivateKey();
        Certificate[] certificateChain = keyStoreService.getCertificateChain();

        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(content);
             PdfReader reader = new PdfReader(inputStream);
             PdfWriter writer = new PdfWriter(new FileOutputStream(signedFilePath.toFile()))) {

            PdfSigner signer = new PdfSigner(reader, writer, new StampingProperties());
            signer.setFieldName(Constants.PADES_SIGNED);

            String providerName = determineProvider();
            IExternalSignature pks = new PrivateKeySignature(privateKey, Constants.SHA_256, providerName);
            IExternalDigest digest = new BouncyCastleDigest();

            signer.signDetached(digest, pks, certificateChain, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
            log.info("Assinatura PAdES realizada com sucesso!");
        }
    }

    private String determineProvider() {
        String osName = System.getProperty(Constants.OS_NAME).toLowerCase();
        return osName.contains(Constants.WIN) ? Constants.PROVIDER_WINDOWS : BouncyCastleProvider.PROVIDER_NAME;
    }
}
