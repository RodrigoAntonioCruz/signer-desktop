// Generated by the protocol buffer compiler.  DO NOT EDIT!
// NO CHECKED-IN PROTOBUF GENCODE
// source: src/main/resources/proto/FileMessage.proto
// Protobuf Java Version: 4.28.0

package com.signer.domain.proto;

public final class FileMessageOuterClass {
  private FileMessageOuterClass() {}
  static {
    com.google.protobuf.RuntimeVersion.validateProtobufGencodeVersion(
      com.google.protobuf.RuntimeVersion.RuntimeDomain.PUBLIC,
      /* major= */ 4,
      /* minor= */ 28,
      /* patch= */ 0,
      /* suffix= */ "",
      FileMessageOuterClass.class.getName());
  }
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_com_signer_FileMessage_descriptor;
  static final 
    com.google.protobuf.GeneratedMessage.FieldAccessorTable
      internal_static_com_signer_FileMessage_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_com_signer_FileMessage_AttributesEntry_descriptor;
  static final 
    com.google.protobuf.GeneratedMessage.FieldAccessorTable
      internal_static_com_signer_FileMessage_AttributesEntry_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    String[] descriptorData = {
      "\n*src/main/resources/proto/FileMessage.p" +
      "roto\022\ncom.signer\"\211\001\n\013FileMessage\022\n\n\002id\030\001" +
      " \001(\t\022;\n\nattributes\030\002 \003(\0132\'.com.signer.Fi" +
      "leMessage.AttributesEntry\0321\n\017AttributesE" +
      "ntry\022\013\n\003key\030\001 \001(\t\022\r\n\005value\030\002 \001(\014:\0028\001B\033\n\027" +
      "com.signer.domain.protoP\001b\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
    internal_static_com_signer_FileMessage_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_com_signer_FileMessage_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessage.FieldAccessorTable(
        internal_static_com_signer_FileMessage_descriptor,
        new String[] { "Id", "Attributes", });
    internal_static_com_signer_FileMessage_AttributesEntry_descriptor =
      internal_static_com_signer_FileMessage_descriptor.getNestedTypes().get(0);
    internal_static_com_signer_FileMessage_AttributesEntry_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessage.FieldAccessorTable(
        internal_static_com_signer_FileMessage_AttributesEntry_descriptor,
        new String[] { "Key", "Value", });
    descriptor.resolveAllFeaturesImmutable();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
