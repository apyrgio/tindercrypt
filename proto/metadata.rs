// This file is generated by rust-protobuf 3.7.2. Do not edit
// .proto file is parsed by pure
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_results)]
#![allow(unused_mut)]

//! Generated file from `metadata.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_7_2;

// @@protoc_insertion_point(message:metadata.KeyDerivationMetadata)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct KeyDerivationMetadata {
    // message fields
    // @@protoc_insertion_point(field:metadata.KeyDerivationMetadata.algo)
    pub algo: ::protobuf::EnumOrUnknown<KeyDerivationAlgorithm>,
    // @@protoc_insertion_point(field:metadata.KeyDerivationMetadata.hash_fn)
    pub hash_fn: ::protobuf::EnumOrUnknown<HashFunction>,
    // @@protoc_insertion_point(field:metadata.KeyDerivationMetadata.iterations)
    pub iterations: u64,
    // @@protoc_insertion_point(field:metadata.KeyDerivationMetadata.salt)
    pub salt: ::std::vec::Vec<u8>,
    // special fields
    // @@protoc_insertion_point(special_field:metadata.KeyDerivationMetadata.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a KeyDerivationMetadata {
    fn default() -> &'a KeyDerivationMetadata {
        <KeyDerivationMetadata as ::protobuf::Message>::default_instance()
    }
}

impl KeyDerivationMetadata {
    pub fn new() -> KeyDerivationMetadata {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(4);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "algo",
            |m: &KeyDerivationMetadata| { &m.algo },
            |m: &mut KeyDerivationMetadata| { &mut m.algo },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "hash_fn",
            |m: &KeyDerivationMetadata| { &m.hash_fn },
            |m: &mut KeyDerivationMetadata| { &mut m.hash_fn },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "iterations",
            |m: &KeyDerivationMetadata| { &m.iterations },
            |m: &mut KeyDerivationMetadata| { &mut m.iterations },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "salt",
            |m: &KeyDerivationMetadata| { &m.salt },
            |m: &mut KeyDerivationMetadata| { &mut m.salt },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<KeyDerivationMetadata>(
            "KeyDerivationMetadata",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for KeyDerivationMetadata {
    const NAME: &'static str = "KeyDerivationMetadata";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                8 => {
                    self.algo = is.read_enum_or_unknown()?;
                },
                16 => {
                    self.hash_fn = is.read_enum_or_unknown()?;
                },
                24 => {
                    self.iterations = is.read_uint64()?;
                },
                34 => {
                    self.salt = is.read_bytes()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if self.algo != ::protobuf::EnumOrUnknown::new(KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_INVALID) {
            my_size += ::protobuf::rt::int32_size(1, self.algo.value());
        }
        if self.hash_fn != ::protobuf::EnumOrUnknown::new(HashFunction::HASH_FUNCTION_INVALID) {
            my_size += ::protobuf::rt::int32_size(2, self.hash_fn.value());
        }
        if self.iterations != 0 {
            my_size += ::protobuf::rt::uint64_size(3, self.iterations);
        }
        if !self.salt.is_empty() {
            my_size += ::protobuf::rt::bytes_size(4, &self.salt);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if self.algo != ::protobuf::EnumOrUnknown::new(KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_INVALID) {
            os.write_enum(1, ::protobuf::EnumOrUnknown::value(&self.algo))?;
        }
        if self.hash_fn != ::protobuf::EnumOrUnknown::new(HashFunction::HASH_FUNCTION_INVALID) {
            os.write_enum(2, ::protobuf::EnumOrUnknown::value(&self.hash_fn))?;
        }
        if self.iterations != 0 {
            os.write_uint64(3, self.iterations)?;
        }
        if !self.salt.is_empty() {
            os.write_bytes(4, &self.salt)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> KeyDerivationMetadata {
        KeyDerivationMetadata::new()
    }

    fn clear(&mut self) {
        self.algo = ::protobuf::EnumOrUnknown::new(KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_INVALID);
        self.hash_fn = ::protobuf::EnumOrUnknown::new(HashFunction::HASH_FUNCTION_INVALID);
        self.iterations = 0;
        self.salt.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static KeyDerivationMetadata {
        static instance: KeyDerivationMetadata = KeyDerivationMetadata {
            algo: ::protobuf::EnumOrUnknown::from_i32(0),
            hash_fn: ::protobuf::EnumOrUnknown::from_i32(0),
            iterations: 0,
            salt: ::std::vec::Vec::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for KeyDerivationMetadata {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("KeyDerivationMetadata").unwrap()).clone()
    }
}

impl ::std::fmt::Display for KeyDerivationMetadata {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for KeyDerivationMetadata {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:metadata.EncryptionMetadata)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct EncryptionMetadata {
    // message fields
    // @@protoc_insertion_point(field:metadata.EncryptionMetadata.algo)
    pub algo: ::protobuf::EnumOrUnknown<EncryptionAlgorithm>,
    // @@protoc_insertion_point(field:metadata.EncryptionMetadata.nonce)
    pub nonce: ::std::vec::Vec<u8>,
    // special fields
    // @@protoc_insertion_point(special_field:metadata.EncryptionMetadata.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a EncryptionMetadata {
    fn default() -> &'a EncryptionMetadata {
        <EncryptionMetadata as ::protobuf::Message>::default_instance()
    }
}

impl EncryptionMetadata {
    pub fn new() -> EncryptionMetadata {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "algo",
            |m: &EncryptionMetadata| { &m.algo },
            |m: &mut EncryptionMetadata| { &mut m.algo },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "nonce",
            |m: &EncryptionMetadata| { &m.nonce },
            |m: &mut EncryptionMetadata| { &mut m.nonce },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<EncryptionMetadata>(
            "EncryptionMetadata",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for EncryptionMetadata {
    const NAME: &'static str = "EncryptionMetadata";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                8 => {
                    self.algo = is.read_enum_or_unknown()?;
                },
                18 => {
                    self.nonce = is.read_bytes()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if self.algo != ::protobuf::EnumOrUnknown::new(EncryptionAlgorithm::ENCRYPTION_ALGORITHM_INVALID) {
            my_size += ::protobuf::rt::int32_size(1, self.algo.value());
        }
        if !self.nonce.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.nonce);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if self.algo != ::protobuf::EnumOrUnknown::new(EncryptionAlgorithm::ENCRYPTION_ALGORITHM_INVALID) {
            os.write_enum(1, ::protobuf::EnumOrUnknown::value(&self.algo))?;
        }
        if !self.nonce.is_empty() {
            os.write_bytes(2, &self.nonce)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> EncryptionMetadata {
        EncryptionMetadata::new()
    }

    fn clear(&mut self) {
        self.algo = ::protobuf::EnumOrUnknown::new(EncryptionAlgorithm::ENCRYPTION_ALGORITHM_INVALID);
        self.nonce.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static EncryptionMetadata {
        static instance: EncryptionMetadata = EncryptionMetadata {
            algo: ::protobuf::EnumOrUnknown::from_i32(0),
            nonce: ::std::vec::Vec::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for EncryptionMetadata {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("EncryptionMetadata").unwrap()).clone()
    }
}

impl ::std::fmt::Display for EncryptionMetadata {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for EncryptionMetadata {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:metadata.Metadata)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct Metadata {
    // message fields
    // @@protoc_insertion_point(field:metadata.Metadata.key_deriv_meta)
    pub key_deriv_meta: ::protobuf::MessageField<KeyDerivationMetadata>,
    // @@protoc_insertion_point(field:metadata.Metadata.enc_meta)
    pub enc_meta: ::protobuf::MessageField<EncryptionMetadata>,
    // @@protoc_insertion_point(field:metadata.Metadata.ciphertext_size)
    pub ciphertext_size: u64,
    // special fields
    // @@protoc_insertion_point(special_field:metadata.Metadata.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a Metadata {
    fn default() -> &'a Metadata {
        <Metadata as ::protobuf::Message>::default_instance()
    }
}

impl Metadata {
    pub fn new() -> Metadata {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(3);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, KeyDerivationMetadata>(
            "key_deriv_meta",
            |m: &Metadata| { &m.key_deriv_meta },
            |m: &mut Metadata| { &mut m.key_deriv_meta },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, EncryptionMetadata>(
            "enc_meta",
            |m: &Metadata| { &m.enc_meta },
            |m: &mut Metadata| { &mut m.enc_meta },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "ciphertext_size",
            |m: &Metadata| { &m.ciphertext_size },
            |m: &mut Metadata| { &mut m.ciphertext_size },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<Metadata>(
            "Metadata",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for Metadata {
    const NAME: &'static str = "Metadata";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.key_deriv_meta)?;
                },
                18 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.enc_meta)?;
                },
                24 => {
                    self.ciphertext_size = is.read_uint64()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.key_deriv_meta.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        if let Some(v) = self.enc_meta.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        if self.ciphertext_size != 0 {
            my_size += ::protobuf::rt::uint64_size(3, self.ciphertext_size);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.key_deriv_meta.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(1, v, os)?;
        }
        if let Some(v) = self.enc_meta.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(2, v, os)?;
        }
        if self.ciphertext_size != 0 {
            os.write_uint64(3, self.ciphertext_size)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> Metadata {
        Metadata::new()
    }

    fn clear(&mut self) {
        self.key_deriv_meta.clear();
        self.enc_meta.clear();
        self.ciphertext_size = 0;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static Metadata {
        static instance: Metadata = Metadata {
            key_deriv_meta: ::protobuf::MessageField::none(),
            enc_meta: ::protobuf::MessageField::none(),
            ciphertext_size: 0,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for Metadata {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("Metadata").unwrap()).clone()
    }
}

impl ::std::fmt::Display for Metadata {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for Metadata {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
// @@protoc_insertion_point(enum:metadata.HashFunction)
pub enum HashFunction {
    // @@protoc_insertion_point(enum_value:metadata.HashFunction.HASH_FUNCTION_INVALID)
    HASH_FUNCTION_INVALID = 0,
    // @@protoc_insertion_point(enum_value:metadata.HashFunction.HASH_FUNCTION_SHA256)
    HASH_FUNCTION_SHA256 = 1,
    // @@protoc_insertion_point(enum_value:metadata.HashFunction.HASH_FUNCTION_SHA384)
    HASH_FUNCTION_SHA384 = 2,
    // @@protoc_insertion_point(enum_value:metadata.HashFunction.HASH_FUNCTION_SHA512)
    HASH_FUNCTION_SHA512 = 3,
}

impl ::protobuf::Enum for HashFunction {
    const NAME: &'static str = "HashFunction";

    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<HashFunction> {
        match value {
            0 => ::std::option::Option::Some(HashFunction::HASH_FUNCTION_INVALID),
            1 => ::std::option::Option::Some(HashFunction::HASH_FUNCTION_SHA256),
            2 => ::std::option::Option::Some(HashFunction::HASH_FUNCTION_SHA384),
            3 => ::std::option::Option::Some(HashFunction::HASH_FUNCTION_SHA512),
            _ => ::std::option::Option::None
        }
    }

    fn from_str(str: &str) -> ::std::option::Option<HashFunction> {
        match str {
            "HASH_FUNCTION_INVALID" => ::std::option::Option::Some(HashFunction::HASH_FUNCTION_INVALID),
            "HASH_FUNCTION_SHA256" => ::std::option::Option::Some(HashFunction::HASH_FUNCTION_SHA256),
            "HASH_FUNCTION_SHA384" => ::std::option::Option::Some(HashFunction::HASH_FUNCTION_SHA384),
            "HASH_FUNCTION_SHA512" => ::std::option::Option::Some(HashFunction::HASH_FUNCTION_SHA512),
            _ => ::std::option::Option::None
        }
    }

    const VALUES: &'static [HashFunction] = &[
        HashFunction::HASH_FUNCTION_INVALID,
        HashFunction::HASH_FUNCTION_SHA256,
        HashFunction::HASH_FUNCTION_SHA384,
        HashFunction::HASH_FUNCTION_SHA512,
    ];
}

impl ::protobuf::EnumFull for HashFunction {
    fn enum_descriptor() -> ::protobuf::reflect::EnumDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::EnumDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().enum_by_package_relative_name("HashFunction").unwrap()).clone()
    }

    fn descriptor(&self) -> ::protobuf::reflect::EnumValueDescriptor {
        let index = *self as usize;
        Self::enum_descriptor().value_by_index(index)
    }
}

impl ::std::default::Default for HashFunction {
    fn default() -> Self {
        HashFunction::HASH_FUNCTION_INVALID
    }
}

impl HashFunction {
    fn generated_enum_descriptor_data() -> ::protobuf::reflect::GeneratedEnumDescriptorData {
        ::protobuf::reflect::GeneratedEnumDescriptorData::new::<HashFunction>("HashFunction")
    }
}

#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
// @@protoc_insertion_point(enum:metadata.KeyDerivationAlgorithm)
pub enum KeyDerivationAlgorithm {
    // @@protoc_insertion_point(enum_value:metadata.KeyDerivationAlgorithm.KEY_DERIVATION_ALGORITHM_INVALID)
    KEY_DERIVATION_ALGORITHM_INVALID = 0,
    // @@protoc_insertion_point(enum_value:metadata.KeyDerivationAlgorithm.KEY_DERIVATION_ALGORITHM_NONE)
    KEY_DERIVATION_ALGORITHM_NONE = 1,
    // @@protoc_insertion_point(enum_value:metadata.KeyDerivationAlgorithm.KEY_DERIVATION_ALGORITHM_PBKDF2)
    KEY_DERIVATION_ALGORITHM_PBKDF2 = 2,
}

impl ::protobuf::Enum for KeyDerivationAlgorithm {
    const NAME: &'static str = "KeyDerivationAlgorithm";

    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<KeyDerivationAlgorithm> {
        match value {
            0 => ::std::option::Option::Some(KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_INVALID),
            1 => ::std::option::Option::Some(KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_NONE),
            2 => ::std::option::Option::Some(KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_PBKDF2),
            _ => ::std::option::Option::None
        }
    }

    fn from_str(str: &str) -> ::std::option::Option<KeyDerivationAlgorithm> {
        match str {
            "KEY_DERIVATION_ALGORITHM_INVALID" => ::std::option::Option::Some(KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_INVALID),
            "KEY_DERIVATION_ALGORITHM_NONE" => ::std::option::Option::Some(KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_NONE),
            "KEY_DERIVATION_ALGORITHM_PBKDF2" => ::std::option::Option::Some(KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_PBKDF2),
            _ => ::std::option::Option::None
        }
    }

    const VALUES: &'static [KeyDerivationAlgorithm] = &[
        KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_INVALID,
        KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_NONE,
        KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_PBKDF2,
    ];
}

impl ::protobuf::EnumFull for KeyDerivationAlgorithm {
    fn enum_descriptor() -> ::protobuf::reflect::EnumDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::EnumDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().enum_by_package_relative_name("KeyDerivationAlgorithm").unwrap()).clone()
    }

    fn descriptor(&self) -> ::protobuf::reflect::EnumValueDescriptor {
        let index = *self as usize;
        Self::enum_descriptor().value_by_index(index)
    }
}

impl ::std::default::Default for KeyDerivationAlgorithm {
    fn default() -> Self {
        KeyDerivationAlgorithm::KEY_DERIVATION_ALGORITHM_INVALID
    }
}

impl KeyDerivationAlgorithm {
    fn generated_enum_descriptor_data() -> ::protobuf::reflect::GeneratedEnumDescriptorData {
        ::protobuf::reflect::GeneratedEnumDescriptorData::new::<KeyDerivationAlgorithm>("KeyDerivationAlgorithm")
    }
}

#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
// @@protoc_insertion_point(enum:metadata.EncryptionAlgorithm)
pub enum EncryptionAlgorithm {
    // @@protoc_insertion_point(enum_value:metadata.EncryptionAlgorithm.ENCRYPTION_ALGORITHM_INVALID)
    ENCRYPTION_ALGORITHM_INVALID = 0,
    // @@protoc_insertion_point(enum_value:metadata.EncryptionAlgorithm.ENCRYPTION_ALGORITHM_AES256GCM)
    ENCRYPTION_ALGORITHM_AES256GCM = 1,
    // @@protoc_insertion_point(enum_value:metadata.EncryptionAlgorithm.ENCRYPTION_ALGORITHM_CHACHA20_POLY1305)
    ENCRYPTION_ALGORITHM_CHACHA20_POLY1305 = 2,
}

impl ::protobuf::Enum for EncryptionAlgorithm {
    const NAME: &'static str = "EncryptionAlgorithm";

    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<EncryptionAlgorithm> {
        match value {
            0 => ::std::option::Option::Some(EncryptionAlgorithm::ENCRYPTION_ALGORITHM_INVALID),
            1 => ::std::option::Option::Some(EncryptionAlgorithm::ENCRYPTION_ALGORITHM_AES256GCM),
            2 => ::std::option::Option::Some(EncryptionAlgorithm::ENCRYPTION_ALGORITHM_CHACHA20_POLY1305),
            _ => ::std::option::Option::None
        }
    }

    fn from_str(str: &str) -> ::std::option::Option<EncryptionAlgorithm> {
        match str {
            "ENCRYPTION_ALGORITHM_INVALID" => ::std::option::Option::Some(EncryptionAlgorithm::ENCRYPTION_ALGORITHM_INVALID),
            "ENCRYPTION_ALGORITHM_AES256GCM" => ::std::option::Option::Some(EncryptionAlgorithm::ENCRYPTION_ALGORITHM_AES256GCM),
            "ENCRYPTION_ALGORITHM_CHACHA20_POLY1305" => ::std::option::Option::Some(EncryptionAlgorithm::ENCRYPTION_ALGORITHM_CHACHA20_POLY1305),
            _ => ::std::option::Option::None
        }
    }

    const VALUES: &'static [EncryptionAlgorithm] = &[
        EncryptionAlgorithm::ENCRYPTION_ALGORITHM_INVALID,
        EncryptionAlgorithm::ENCRYPTION_ALGORITHM_AES256GCM,
        EncryptionAlgorithm::ENCRYPTION_ALGORITHM_CHACHA20_POLY1305,
    ];
}

impl ::protobuf::EnumFull for EncryptionAlgorithm {
    fn enum_descriptor() -> ::protobuf::reflect::EnumDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::EnumDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().enum_by_package_relative_name("EncryptionAlgorithm").unwrap()).clone()
    }

    fn descriptor(&self) -> ::protobuf::reflect::EnumValueDescriptor {
        let index = *self as usize;
        Self::enum_descriptor().value_by_index(index)
    }
}

impl ::std::default::Default for EncryptionAlgorithm {
    fn default() -> Self {
        EncryptionAlgorithm::ENCRYPTION_ALGORITHM_INVALID
    }
}

impl EncryptionAlgorithm {
    fn generated_enum_descriptor_data() -> ::protobuf::reflect::GeneratedEnumDescriptorData {
        ::protobuf::reflect::GeneratedEnumDescriptorData::new::<EncryptionAlgorithm>("EncryptionAlgorithm")
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x0emetadata.proto\x12\x08metadata\"\xb2\x01\n\x15KeyDerivationMetadat\
    a\x124\n\x04algo\x18\x01\x20\x01(\x0e2\x20.metadata.KeyDerivationAlgorit\
    hmR\x04algo\x12/\n\x07hash_fn\x18\x02\x20\x01(\x0e2\x16.metadata.HashFun\
    ctionR\x06hashFn\x12\x1e\n\niterations\x18\x03\x20\x01(\x04R\niterations\
    \x12\x12\n\x04salt\x18\x04\x20\x01(\x0cR\x04salt\"]\n\x12EncryptionMetad\
    ata\x121\n\x04algo\x18\x01\x20\x01(\x0e2\x1d.metadata.EncryptionAlgorith\
    mR\x04algo\x12\x14\n\x05nonce\x18\x02\x20\x01(\x0cR\x05nonce\"\xb3\x01\n\
    \x08Metadata\x12E\n\x0ekey_deriv_meta\x18\x01\x20\x01(\x0b2\x1f.metadata\
    .KeyDerivationMetadataR\x0ckeyDerivMeta\x127\n\x08enc_meta\x18\x02\x20\
    \x01(\x0b2\x1c.metadata.EncryptionMetadataR\x07encMeta\x12'\n\x0fciphert\
    ext_size\x18\x03\x20\x01(\x04R\x0eciphertextSize*w\n\x0cHashFunction\x12\
    \x19\n\x15HASH_FUNCTION_INVALID\x10\0\x12\x18\n\x14HASH_FUNCTION_SHA256\
    \x10\x01\x12\x18\n\x14HASH_FUNCTION_SHA384\x10\x02\x12\x18\n\x14HASH_FUN\
    CTION_SHA512\x10\x03*\x86\x01\n\x16KeyDerivationAlgorithm\x12$\n\x20KEY_\
    DERIVATION_ALGORITHM_INVALID\x10\0\x12!\n\x1dKEY_DERIVATION_ALGORITHM_NO\
    NE\x10\x01\x12#\n\x1fKEY_DERIVATION_ALGORITHM_PBKDF2\x10\x02*\x87\x01\n\
    \x13EncryptionAlgorithm\x12\x20\n\x1cENCRYPTION_ALGORITHM_INVALID\x10\0\
    \x12\"\n\x1eENCRYPTION_ALGORITHM_AES256GCM\x10\x01\x12*\n&ENCRYPTION_ALG\
    ORITHM_CHACHA20_POLY1305\x10\x02B+\n\x0ccom.metadataB\rMetadataProtoP\
    \x01Z\nmetadatapbb\x06proto3\
";

/// `FileDescriptorProto` object which was a source for this generated file
fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    static file_descriptor_proto_lazy: ::protobuf::rt::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::Lazy::new();
    file_descriptor_proto_lazy.get(|| {
        ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
    })
}

/// `FileDescriptor` object which allows dynamic access to files
pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
    static generated_file_descriptor_lazy: ::protobuf::rt::Lazy<::protobuf::reflect::GeneratedFileDescriptor> = ::protobuf::rt::Lazy::new();
    static file_descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::FileDescriptor> = ::protobuf::rt::Lazy::new();
    file_descriptor.get(|| {
        let generated_file_descriptor = generated_file_descriptor_lazy.get(|| {
            let mut deps = ::std::vec::Vec::with_capacity(0);
            let mut messages = ::std::vec::Vec::with_capacity(3);
            messages.push(KeyDerivationMetadata::generated_message_descriptor_data());
            messages.push(EncryptionMetadata::generated_message_descriptor_data());
            messages.push(Metadata::generated_message_descriptor_data());
            let mut enums = ::std::vec::Vec::with_capacity(3);
            enums.push(HashFunction::generated_enum_descriptor_data());
            enums.push(KeyDerivationAlgorithm::generated_enum_descriptor_data());
            enums.push(EncryptionAlgorithm::generated_enum_descriptor_data());
            ::protobuf::reflect::GeneratedFileDescriptor::new_generated(
                file_descriptor_proto(),
                deps,
                messages,
                enums,
            )
        });
        ::protobuf::reflect::FileDescriptor::new_generated_2(generated_file_descriptor)
    })
}
