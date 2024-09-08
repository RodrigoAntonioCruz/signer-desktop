package com.signer.util;

public class Constants {
    private Constants() {
    }

    public static final String QUEUE_TO_SIGN = "to-sign-002321";
    public static final String QUEUE_SIGNED = "signed-002321";
    public static final String XML = "xml";
    public static final String PDF = "pdf";
    public static final String UNKNOWN = "unknown";
    public static final String DOT_SIGNED = ".signed";
    public static final String DOT_XML = ".xml";
    public static final String DOT_PDF = ".pdf";
    public static final String DOT_XML_P7S =".xml.p7s";
    public static final String DOT_P7S = ".p7s";
    public static final String PADES_SIGNED = "AssinaturaPAdES";
    public static final String EMPTY = "";
    public static final String DOM = "DOM";
    public static final CharSequence WIN = "win";
    public static final String PROVIDER_WINDOWS = "SunMSCAPI";
    public static final String OS_NAME = "os.name";
    public static final String SHA_256 = "SHA-256";
    public static final String SHA256_RSA = "SHA256withRSA";
    public static final byte[] PDF_MAGIC_NUMBER = {0x25, 0x50, 0x44, 0x46};
    public static final byte[] XML_MAGIC_NUMBER = {0x3C, 0x3F, 0x78, 0x6D, 0x6C};
    public static final String KEY = "key";
    public static final String NAME = "name";
    public static final String ALIAS = "alias";
    public static final String CONTENT = "content";
    public static final String SIGNATURE_CONTENT = "signatureContent";
    public static final String DETACHE_SIGNATURE = "detache";
    public static final String GROUP_ONE = "$1";
    public static final String CN_PATTERN = ".*CN=([^,]+).*";
}
