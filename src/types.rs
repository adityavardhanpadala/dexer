use bitflags::bitflags;


#[repr(C)]
pub struct StringDataItem<'a> {
    pub size: u16,
    pub data: &'a [u8]
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct proto_id_item{
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct field_id_item{
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct method_id_item{
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct class_def_item{
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32
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
        self.intersects(Self::PUBLIC | Self::FINAL | Self::INTERFACE | Self::ABSTRACT | 
                        Self::SYNTHETIC | Self::ANNOTATION | Self::ENUM)
    }

    pub fn is_inner_class_flag(self) -> bool {
        self.intersects(Self::PUBLIC | Self::PRIVATE | Self::PROTECTED | Self::STATIC | 
                        Self::FINAL | Self::INTERFACE | Self::ABSTRACT | Self::SYNTHETIC | 
                        Self::ANNOTATION | Self::ENUM)
    }

    pub fn is_field_flag(self) -> bool {
        self.intersects(Self::PUBLIC | Self::PRIVATE | Self::PROTECTED | Self::STATIC | 
                        Self::FINAL | Self::VOLATILE | Self::TRANSIENT | Self::SYNTHETIC | 
                        Self::ENUM)
    }

    pub fn is_method_flag(self) -> bool {
        self.intersects(Self::PUBLIC | Self::PRIVATE | Self::PROTECTED | Self::STATIC | 
                        Self::FINAL | Self::SYNCHRONIZED | Self::BRIDGE | Self::VARARGS | 
                        Self::NATIVE | Self::ABSTRACT | Self::STRICT | Self::SYNTHETIC | 
                        Self::CONSTRUCTOR | Self::DECLARED_SYNCHRONIZED)
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
