use std::fmt::Debug;

use bitflags::bitflags;

#[repr(C)]
pub struct StringDataItem<'a> {
    pub size: u16,
    pub data: &'a [u8],
}

impl Debug for StringDataItem<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Log undecoded data
        write!(
            f,
            "StringDataItem {{ size: {}, data: {:?} }}",
            self.size, self.data
        )
    }
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct proto_id_item {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct field_id_item {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct method_id_item {
    pub class_idx: u16,
    pub proto_idx: u16, // Index into proto_ids (was incorrectly named type_idx)
    pub name_idx: u32,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct class_def_item {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AccessFlags: u32 {
        const PUBLIC               = 0x0001;
        const PRIVATE              = 0x0002;
        const PROTECTED            = 0x0004;
        const STATIC               = 0x0008;
        const FINAL                = 0x0010;
        const SYNCHRONIZED         = 0x0020;
        const VOLATILE             = 0x0040;
        const BRIDGE               = 0x0040;
        const TRANSIENT            = 0x0080;
        const VARARGS              = 0x0080;
        const NATIVE               = 0x0100;
        const INTERFACE            = 0x0200;
        const ABSTRACT             = 0x0400;
        const STRICT               = 0x0800;
        const SYNTHETIC            = 0x1000;
        const ANNOTATION           = 0x2000;
        const ENUM                 = 0x4000;
        const CONSTRUCTOR          = 0x10000;
        const DECLARED_SYNCHRONIZED = 0x20000;
    }
}

impl AccessFlags {
    pub fn is_class_flag(self) -> bool {
        self.intersects(
            Self::PUBLIC
                | Self::FINAL
                | Self::INTERFACE
                | Self::ABSTRACT
                | Self::SYNTHETIC
                | Self::ANNOTATION
                | Self::ENUM,
        )
    }

    pub fn is_inner_class_flag(self) -> bool {
        self.intersects(
            Self::PUBLIC
                | Self::PRIVATE
                | Self::PROTECTED
                | Self::STATIC
                | Self::FINAL
                | Self::INTERFACE
                | Self::ABSTRACT
                | Self::SYNTHETIC
                | Self::ANNOTATION
                | Self::ENUM,
        )
    }

    pub fn is_field_flag(self) -> bool {
        self.intersects(
            Self::PUBLIC
                | Self::PRIVATE
                | Self::PROTECTED
                | Self::STATIC
                | Self::FINAL
                | Self::VOLATILE
                | Self::TRANSIENT
                | Self::SYNTHETIC
                | Self::ENUM,
        )
    }

    pub fn is_method_flag(self) -> bool {
        self.intersects(
            Self::PUBLIC
                | Self::PRIVATE
                | Self::PROTECTED
                | Self::STATIC
                | Self::FINAL
                | Self::SYNCHRONIZED
                | Self::BRIDGE
                | Self::VARARGS
                | Self::NATIVE
                | Self::ABSTRACT
                | Self::STRICT
                | Self::SYNTHETIC
                | Self::CONSTRUCTOR
                | Self::DECLARED_SYNCHRONIZED,
        )
    }
}

#[derive(Debug)]
pub enum Mutf8Error {
    InvalidSequence(usize),
    UnexpectedEndOfInput(usize),
}

#[derive(Debug)]
pub struct DecodedString {
    pub string: String,
    pub error: Option<Mutf8Error>,
}

// Based on https://source.android.com/docs/core/dalvik/dex-format#class-data-item
// Note: Changed from slices to Vecs to hold owned data after parsing.
#[derive(Debug)]
pub struct ClassDataItem {
    pub static_fields_size: u32,
    pub instance_fields_size: u32,
    pub direct_methods_size: u32,
    pub virtual_methods_size: u32,
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

// Based on https://source.android.com/docs/core/dalvik/dex-format#encoded-field-format
#[derive(Debug, Clone)]
#[repr(C)]
pub struct EncodedField {
    pub field_idx_diff: u32, // ULEB128
    pub access_flags: u32,   // ULEB128
}

// Based on https://source.android.com/docs/core/dalvik/dex-format#encoded-method-format
#[derive(Debug, Clone)]
#[repr(C)]
pub struct EncodedMethod {
    pub method_idx_diff: u32, // ULEB128
    pub access_flags: u32,    // ULEB128
    pub code_off: u32,        // ULEB128: offset to code_item or 0
}

// Based on https://source.android.com/docs/core/dalvik/dex-format#code-item
#[derive(Debug)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32, // size of instructions list, in 16-bit code units
    pub insns: Vec<u16>, // Actual bytecode instructions (owned Vec)
    pub try_items: Option<Vec<TryItem>>,
    pub debug_info: Option<Vec<u8>>, // Optional debug_info_item follows instructions
}

// Based on https://source.android.com/docs/core/dalvik/dex-format#try-item-format
#[derive(Debug, Clone)]
#[repr(C)]
pub struct TryItem {
    pub start_addr: u32,  // Offset from start of code_item to start of try block
    pub insn_count: u16,  // Number of instructions in try block
    pub handler_off: u16, // Offset from start of code_item to handler_list
}
