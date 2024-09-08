package com.signer.domain.enums;

import com.signer.util.Constants;

public enum FileType {
    PDF(Constants.PDF, Constants.PDF_MAGIC_NUMBER),
    XML(Constants.XML, Constants.XML_MAGIC_NUMBER),
    UNKNOWN(Constants.UNKNOWN, new byte[0]);

    private final String extension;
    private final byte[] magicNumber;

    FileType(String extension, byte[] magicNumber) {
        this.extension = extension;
        this.magicNumber = magicNumber;
    }

    public String getExtension() {
        return extension;
    }

    public byte[] getMagicNumber() {
        return magicNumber;
    }

    public static FileType fromContent(byte[] content) {
        if (content != null) {
            if (matches(content, PDF.magicNumber)) {
                return PDF;
            } else if (matches(content, XML.magicNumber)) {
                return XML;
            }
        }
        return UNKNOWN;
    }

    private static boolean matches(byte[] content, byte[] magicNumber) {
        if (content.length < magicNumber.length) {
            return false;
        }
        for (int i = 0; i < magicNumber.length; i++) {
            if (content[i] != magicNumber[i]) {
                return false;
            }
        }
        return true;
    }
}
