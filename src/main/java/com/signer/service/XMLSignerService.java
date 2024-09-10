package com.signer.service;

import com.signer.exception.ExceptionResolver;
import com.signer.util.Constants;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

@Service
public class XMLSignerService {
    private static final Logger log = LoggerFactory.getLogger(XMLSignerService.class);
    private final KeyStoreService keyStoreService;

    public XMLSignerService(KeyStoreService keyStoreService) {
        this.keyStoreService = keyStoreService;
    }

    public void signXML(byte[] content, Path signedFilePath, String certificateDetails) throws MarshalException, InvalidAlgorithmParameterException, UnrecoverableKeyException, TransformerConfigurationException, KeyStoreException, NoSuchAlgorithmException, ParserConfigurationException, IOException, XMLSignatureException, SAXException {
        signXMLDocument(content, signedFilePath, certificateDetails);
    }

    public void signXMLDetached(Path signedFilePath, String certificateDetails) throws UnrecoverableKeyException, CertificateEncodingException, KeyStoreException, NoSuchAlgorithmException, OperatorCreationException, CMSException {
        generatePKCS7Signature(signedFilePath, certificateDetails);
    }

    private void signXMLDocument(byte[] content, Path signedFilePath, String certificateDetails) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, ParserConfigurationException, MarshalException, TransformerConfigurationException, XMLSignatureException, IOException, SAXException, InvalidAlgorithmParameterException {
        initializeKeyStore(certificateDetails);

        XMLSignatureFactory xmlSigFactory = XMLSignatureFactory.getInstance(Constants.DOM);
        SignedInfo signedInfo = createSignedInfo(xmlSigFactory, createReference(xmlSigFactory));
        KeyInfo keyInfo = createKeyInfo(xmlSigFactory, keyStoreService.getCertificate());

        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        disableAccessExternalEntities(dbFactory);

        Document document = dbFactory.newDocumentBuilder().parse(new ByteArrayInputStream(content));
        signAndSaveDocument(document, signedFilePath, xmlSigFactory, signedInfo, keyInfo);
        log.info("Assinatura XML realizada com sucesso!");
    }

    private void generatePKCS7Signature(Path signedFilePath, String certificateDetails) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateEncodingException, OperatorCreationException, CMSException {
        initializeKeyStore(certificateDetails);
        List<Certificate> certList = Collections.singletonList(keyStoreService.getCertificate());

        ContentSigner contentSigner = new JcaContentSignerBuilder(Constants.SHA256_RSA).build(keyStoreService.getPrivateKey());
        CMSSignedDataGenerator generator = createCMSSignedDataGenerator(certList, contentSigner);

        CMSProcessableByteArray cmsData = new CMSProcessableByteArray(new byte[0]);
        CMSSignedData signedData = generator.generate(cmsData, true);
        String fileName = fileNameResolver(signedFilePath);

        try (FileOutputStream outputStream = new FileOutputStream(fileName)) {
            outputStream.write(signedData.getEncoded());
        } catch (IOException e) {
            ExceptionResolver.getRootException(e);
        }

        log.info("ssinatura destacada PKCS #7 realizada com sucesso!");
    }

    private String fileNameResolver(Path signedFilePath) {
        String fileName = signedFilePath.toString();
        if (fileName.endsWith(Constants.DOT_XML)) {
            return fileName.replace(Constants.DOT_XML, Constants.DOT_XML_P7S);
        } else if (!fileName.endsWith(Constants.DOT_P7S)) {
            return fileName.concat(Constants.DOT_P7S);
        }
        return fileName;
    }

    private void initializeKeyStore(String certificateDetails) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        keyStoreService.initializeKeyStore(certificateDetails);
    }

    private Reference createReference(XMLSignatureFactory xmlSigFactory) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return xmlSigFactory.newReference(Constants.EMPTY, xmlSigFactory.newDigestMethod(DigestMethod.SHA256, null),
                Collections.singletonList(xmlSigFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);
    }

    private SignedInfo createSignedInfo(XMLSignatureFactory xmlSigFactory, Reference reference) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return xmlSigFactory.newSignedInfo(xmlSigFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                xmlSigFactory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), Collections.singletonList(reference));
    }

    private KeyInfo createKeyInfo(XMLSignatureFactory xmlSigFactory, X509Certificate certificate) {
        KeyInfoFactory keyInfoFactory = xmlSigFactory.getKeyInfoFactory();
        X509Data x509Data = keyInfoFactory.newX509Data(Collections.singletonList(certificate));
        return keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));
    }

    private void signAndSaveDocument(Document document, Path signedFilePath, XMLSignatureFactory xmlSigFactory, SignedInfo signedInfo, KeyInfo keyInfo) throws MarshalException, XMLSignatureException, TransformerConfigurationException {
        DOMSignContext domSignContext = new DOMSignContext(keyStoreService.getPrivateKey(), document.getDocumentElement());
        XMLSignature signature = xmlSigFactory.newXMLSignature(signedInfo, keyInfo);
        signature.sign(domSignContext);
        saveDocumentToFile(document, signedFilePath);
    }

    private void saveDocumentToFile(Document document, Path signedFilePath) throws TransformerConfigurationException {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        disableAccessExternalEntities(transformerFactory);

        Transformer transformer = transformerFactory.newTransformer();
        try (FileOutputStream outputStream = new FileOutputStream(signedFilePath.toFile())) {
            transformer.transform(new DOMSource(document), new StreamResult(outputStream));
        } catch (IOException | TransformerException e) {
            ExceptionResolver.getRootException(e);
        }
    }

    private CMSSignedDataGenerator createCMSSignedDataGenerator(List<Certificate> certList, ContentSigner contentSigner) throws OperatorCreationException, CertificateEncodingException, CMSException {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().build()).build(contentSigner, (X509Certificate) certList.get(0)));
        generator.addCertificates(new JcaCertStore(certList));
        return generator;
    }

    private void disableAccessExternalEntities(DocumentBuilderFactory dbFactory) throws ParserConfigurationException {
        dbFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbFactory.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);
        dbFactory.setNamespaceAware(true);
    }

    private void disableAccessExternalEntities(TransformerFactory transformerFactory) throws TransformerConfigurationException {
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    }
}