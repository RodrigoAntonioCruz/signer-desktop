package com.signer.service;

import com.signer.util.Constants;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

@Service
public class KeyStoreService {
    private static final Logger log = LoggerFactory.getLogger(KeyStoreService.class);
    private PrivateKey privateKey;
    private X509Certificate certificate;
    private Certificate[] certificateChain;

    public void initializeKeyStore(String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        // Obtém a instância de KeyStore do KeyStoreLoader
        KeyStoreLoader keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
        KeyStore keyStore = keyStoreLoader.getKeyStore();

        // Obtém o certificado usando o alias selecionado
        certificate = (X509Certificate) keyStore.getCertificate(alias);

        // Verifica se o aliases que representa uma entrada de chave privada
        if (keyStore.isKeyEntry(alias)) {
            privateKey = (PrivateKey) keyStore.getKey(alias, null);
            certificateChain = keyStore.getCertificateChain(alias);
        } else {
            log.info("Certificado não contém chave privada.");
        }
    }

    public List<String> getAllCertificateDetails() throws KeyStoreException {
        // Obtém a instância de KeyStore do KeyStoreLoader
        KeyStoreLoader keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
        KeyStore keyStore = keyStoreLoader.getKeyStore();

        List<String> certificateDetailsList = new ArrayList<>();

        // Lista todos os aliases disponíveis na KeyStore
        Enumeration<String> aliases = keyStore.aliases();

        // Itera pelos aliases e extrai detalhes do certificado
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate(alias);

            if (Objects.nonNull(x509Certificate)) {
                // Chama o método extraído para obter detalhes do certificado
                String certificateDetails = getCertificateDetailsForAlias(alias, x509Certificate);
                certificateDetailsList.add(certificateDetails);
            }
        }

        return certificateDetailsList;
    }

    private String getCertificateDetailsForAlias(String alias, X509Certificate certificate) {
        // Obtém o Nome Comum (CN) do certificado
        String subjectDN = certificate.getSubjectX500Principal().getName();
        String cn = subjectDN.replaceAll(Constants.CN_PATTERN, Constants.GROUP_ONE);

        // Obtém o Número de Série do certificado
        String serialNumber = certificate.getSerialNumber().toString();

        // Formata as informações para serem retornadas na lista
        return String.format("alias: %s, cn: %s, numero de serie: %s", alias, cn, serialNumber);
    }


    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public X509Certificate getCertificate() { return certificate; }

    public Certificate[] getCertificateChain() {
        return certificateChain;
    }
}
