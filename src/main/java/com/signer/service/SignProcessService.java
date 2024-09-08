package com.signer.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.ByteString;
import com.signer.domain.enums.FileType;
import com.signer.domain.proto.FileMessage;
import com.signer.util.Constants;
import org.demoiselle.signer.chain.icp.brasil.provider.impl.ICPBrasilUserHomeProviderCA;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Service
public class SignProcessService {
    private static final Logger log = LoggerFactory.getLogger(SignProcessService.class);
    private final RabbitTemplate template;
    private final PDFSignerService pdfSigner;
    private final XMLSignerService xmlSigner;
    private final KeyStoreService keyStoreService;

    public SignProcessService(RabbitTemplate template,
                              PDFSignerService pdfSigner,
                              XMLSignerService xmlSigner,
                              KeyStoreService keyStoreService) {
        this.template = template;
        this.pdfSigner = pdfSigner;
        this.xmlSigner = xmlSigner;
        this.keyStoreService = keyStoreService;
    }

    @RabbitListener(queues = Constants.QUEUE_TO_SIGN)
    public void receiveMessage(byte[] message) {
        Path signedFilePath = null;
        try {
            FileMessage fileMessage = FileMessage.parseFrom(message);

            String key = getStringAttributeByKey(fileMessage, Constants.KEY);
            String certificate = getStringAttributeByKey(fileMessage, Constants.ALIAS);
            String fileName = getStringAttributeByKey(fileMessage, Constants.NAME);
            byte[] fileContent = getBytesAttributeByKey(fileMessage, Constants.CONTENT);

            log.info("Recebido arquivo para assinatura: {}", fileName);

            FileType fileType = FileType.fromContent(fileContent);
            signedFilePath = determineSignedFilePath(fileName, fileType);

            log.info("Certificado utilizado para a assinatura: {}", certificate);

            if (fileType == FileType.PDF) {
                pdfSigner.signPDF(fileContent, signedFilePath, certificate);
            } else if (fileType == FileType.XML) {
                xmlResolver(key, fileContent, signedFilePath, certificate);
            } else {
                log.warn("Tipo de arquivo desconhecido");
                return;
            }

            try (var inputStream = Files.newInputStream(signedFilePath)) {
                byte[] signedContent = inputStream.readAllBytes();
                FileMessage signedMessage = contentResolver(key, fileName, certificate, fileContent, signedContent);
                sendSignedMessage(template, signedMessage);
            }

            getCertificate();

            log.info("Arquivo assinado com sucesso!");
        } catch (Exception e) {
            log.error("Erro ao processar mensagem", e);
        } finally {
            if (Objects.nonNull(signedFilePath)) {
                try {
                    Files.deleteIfExists(signedFilePath);
                    log.info("Arquivo temporário excluído: {}", signedFilePath);
                } catch (Exception ex) {
                    log.error("Erro ao excluir o arquivo temporário: {}", signedFilePath, ex);
                }
            }
        }
    }

    private void xmlResolver(String key, byte[] content, Path signedFilePath, String certificate) throws Exception {
        if (Constants.DETACHE_SIGNATURE.equals(key)) {
            xmlSigner.signXMLDetached(signedFilePath, certificate);
        } else {
            xmlSigner.signXML(content, signedFilePath, certificate);
        }
    }

    private FileMessage contentResolver(String key, String fileName, String certificate, byte[] fileContent, byte[] signedContent) {
        FileMessage.Builder fileMessageBuilder = FileMessage.newBuilder()
                .putAttributes(Constants.NAME, ByteString.copyFromUtf8(fileName))
                .putAttributes(Constants.ALIAS, ByteString.copyFromUtf8(certificate));

        if (Constants.DETACHE_SIGNATURE.equals(key)) {
            fileMessageBuilder.putAttributes(Constants.CONTENT, ByteString.copyFrom(fileContent));
            fileMessageBuilder.putAttributes(Constants.SIGNATURE_CONTENT, ByteString.copyFrom(signedContent));
        } else {
            fileMessageBuilder.putAttributes(Constants.CONTENT, ByteString.copyFrom(signedContent));
        }

        return fileMessageBuilder.build();
    }

    private void getCertificate() throws KeyStoreException {
        List<String> certificateDetails = keyStoreService.getAllCertificateDetails();
        ObjectMapper objectMapper = new ObjectMapper();

        try {
            String json = objectMapper.writeValueAsString(certificateDetails);
            log.info("Lista de alias de certificados (JSON): {}", json);
        } catch (JsonProcessingException e) {
            log.error("Erro ao converter a lista de certificados para JSON", e);
        }
    }

    private Path determineSignedFilePath(String fileName, FileType fileType) {
        String homeUser = ICPBrasilUserHomeProviderCA.PATH_HOME_USER;
        String signedFileName = fileName.concat(Constants.DOT_SIGNED);
        if (fileType == FileType.PDF) {
            signedFileName += Constants.DOT_PDF;
        } else if (fileType == FileType.XML) {
            signedFileName += Constants.DOT_P7S;
        }
        return Paths.get(homeUser, signedFileName);
    }

    private String getStringAttributeByKey(FileMessage fileMessage, String key) {
        Map<String, ByteString> attributes = fileMessage.getAttributesMap();
        return attributes.containsKey(key) ? Objects.requireNonNull(attributes.get(key).toStringUtf8()) : Constants.EMPTY;
    }

    private byte[] getBytesAttributeByKey(FileMessage fileMessage, String key) {
        Map<String, ByteString> attributes = fileMessage.getAttributesMap();
        return attributes.containsKey(key) ? attributes.get(key).toByteArray() : Constants.EMPTY.getBytes();
    }

    private static void sendSignedMessage(RabbitTemplate template, FileMessage message) {
        template.convertAndSend(Constants.QUEUE_SIGNED, message.toByteArray());
        log.info("Mensagem assinada enviada para a fila.");
    }
}
