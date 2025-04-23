// DEX instruction set and disassembly logic
use std::fmt;
use log::warn;

// Reference type for constant pools
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReferenceType {
    String,
    Type,
    Field,
    Method,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InstructionFormat {
    Format10x,    // 00|op
    Format12x,    // 01|op vA, vB
    Format11x,    // 01|op vAA
    Format10t,    // 01|op +AA
    Format20t,    // 02|op +AAAA
    Format22x,    // 02|op vAA, vBBBB
    Format21t,    // 02|op vAA, +BBBB
    Format21s,    // 02|op vAA, #+BBBB
    Format21c,    // 02|op vAA, kind@BBBB
    Format23x,    // 02|op vAA, vBB, vCC
    Format22t,    // 02|op vA, vB, +CCCC
    Format22c,    // 02|op vA, vB, kind@CCCC
    Format30t,    // 03|op +AAAAAAAA
    Format32x,    // 03|op vAAAA, vBBBB
    Format31i,    // 03|op vAA, #+BBBBBBBB
    Format31c,    // 03|op vAA, string@BBBBBBBB
    Format35c,    // 03|op {vC, vD, vE, vF, vG}, kind@BBBB
    Format3rc,    // 03|op {vCCCC .. vNNNN}, kind@BBBB
    Format51l,    // 05|op vAA, #+BBBBBBBBBBBBBBBB
    PackedSwitch, // variable-size
    SparseSwitch, // variable-size
    FillArrayData, // variable-size
    Unknown,      // for opcodes not implemented yet
}

// Reference enumeration for all DEX opcodes
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(non_camel_case_types)]
pub enum Opcode {
    NOP = 0x00,
    MOVE = 0x01,
    MOVE_FROM16 = 0x02,
    MOVE_16 = 0x03,
    MOVE_WIDE = 0x04,
    MOVE_WIDE_FROM16 = 0x05,
    MOVE_WIDE_16 = 0x06,
    MOVE_OBJECT = 0x07,
    MOVE_OBJECT_FROM16 = 0x08,
    MOVE_OBJECT_16 = 0x09,
    MOVE_RESULT = 0x0a,
    MOVE_RESULT_WIDE = 0x0b,
    MOVE_RESULT_OBJECT = 0x0c,
    MOVE_EXCEPTION = 0x0d,
    RETURN_VOID = 0x0e,
    RETURN = 0x0f,
    RETURN_WIDE = 0x10,
    RETURN_OBJECT = 0x11,
    CONST_4 = 0x12,
    CONST_16 = 0x13,
    CONST = 0x14,
    CONST_HIGH16 = 0x15,
    CONST_WIDE_16 = 0x16,
    CONST_WIDE_32 = 0x17,
    CONST_WIDE = 0x18,
    CONST_WIDE_HIGH16 = 0x19,
    CONST_STRING = 0x1a,
    CONST_STRING_JUMBO = 0x1b,
    CONST_CLASS = 0x1c,
    MONITOR_ENTER = 0x1d,
    MONITOR_EXIT = 0x1e,
    CHECK_CAST = 0x1f,
    INSTANCE_OF = 0x20,
    ARRAY_LENGTH = 0x21,
    NEW_INSTANCE = 0x22,
    NEW_ARRAY = 0x23,
    FILLED_NEW_ARRAY = 0x24,
    FILLED_NEW_ARRAY_RANGE = 0x25,
    FILL_ARRAY_DATA = 0x26,
    THROW = 0x27,
    GOTO = 0x28,
    GOTO_16 = 0x29,
    GOTO_32 = 0x2a,
    PACKED_SWITCH = 0x2b,
    SPARSE_SWITCH = 0x2c,
    CMPL_FLOAT = 0x2d,
    CMPG_FLOAT = 0x2e,
    CMPL_DOUBLE = 0x2f,
    CMPG_DOUBLE = 0x30,
    CMP_LONG = 0x31,
    IF_EQ = 0x32,
    IF_NE = 0x33,
    IF_LT = 0x34,
    IF_GE = 0x35,
    IF_GT = 0x36,
    IF_LE = 0x37,
    IF_EQZ = 0x38,
    IF_NEZ = 0x39,
    IF_LTZ = 0x3a,
    IF_GEZ = 0x3b,
    IF_GTZ = 0x3c,
    IF_LEZ = 0x3d,
    ADD_INT = 0x90,
    SUB_INT = 0x91,
    MUL_INT = 0x92,
    DIV_INT = 0x93,
    REM_INT = 0x94,
    AND_INT = 0x95,
    OR_INT = 0x96,
    XOR_INT = 0x97,
    SHL_INT = 0x98,
    SHR_INT = 0x99,
    USHR_INT = 0x9a,
    INVOKE_VIRTUAL = 0x6e,
    INVOKE_SUPER = 0x6f,
    INVOKE_DIRECT = 0x70,
    INVOKE_STATIC = 0x71,
    INVOKE_INTERFACE = 0x72,
    AGET = 0x44,
    AGET_WIDE = 0x45,
    AGET_OBJECT = 0x46,
    AGET_BOOLEAN = 0x47,
    AGET_BYTE = 0x48,
    AGET_CHAR = 0x49,
    AGET_SHORT = 0x4a,
    APUT = 0x4b,
    APUT_WIDE = 0x4c,
    APUT_OBJECT = 0x4d,
    APUT_BOOLEAN = 0x4e,
    APUT_BYTE = 0x4f,
    APUT_CHAR = 0x50,
    APUT_SHORT = 0x51,
    IGET = 0x52,
    IGET_WIDE = 0x53,
    IGET_OBJECT = 0x54,
    IGET_BOOLEAN = 0x55,
    IGET_BYTE = 0x56,
    IGET_CHAR = 0x57,
    IGET_SHORT = 0x58,
    IPUT = 0x59,
    IPUT_WIDE = 0x5a,
    IPUT_OBJECT = 0x5b,
    IPUT_BOOLEAN = 0x5c,
    IPUT_BYTE = 0x5d,
    IPUT_CHAR = 0x5e,
    IPUT_SHORT = 0x5f,
    SGET = 0x60,
    SGET_WIDE = 0x61,
    SGET_OBJECT = 0x62,
    SGET_BOOLEAN = 0x63,
    SGET_BYTE = 0x64,
    SGET_CHAR = 0x65,
    SGET_SHORT = 0x66,
    SPUT = 0x67,
    SPUT_WIDE = 0x68,
    SPUT_OBJECT = 0x69,
    SPUT_BOOLEAN = 0x6a,
    SPUT_BYTE = 0x6b,
    SPUT_CHAR = 0x6c,
    SPUT_SHORT = 0x6d,
    ADD_INT_2ADDR = 0xb0,
    SUB_INT_2ADDR = 0xb1,
    MUL_INT_2ADDR = 0xb2,
    DIV_INT_2ADDR = 0xb3,
    REM_INT_2ADDR = 0xb4,
    AND_INT_2ADDR = 0xb5,
    OR_INT_2ADDR = 0xb6,
    XOR_INT_2ADDR = 0xb7,
    SHL_INT_2ADDR = 0xb8,
    SHR_INT_2ADDR = 0xb9,
    USHR_INT_2ADDR = 0xba,
    INVOKE_POLYMORPHIC = 0xfa,
    INVOKE_POLYMORPHIC_RANGE = 0xfb,
    INVOKE_CUSTOM = 0xfc,
    INVOKE_CUSTOM_RANGE = 0xfd,
    CONST_METHOD_HANDLE = 0xfe,
    CONST_METHOD_TYPE = 0xff,
    UNKNOWN = 0xfe00,  // Changed from 0xff to a value outside the u8 range
}

impl From<u8> for Opcode {
    fn from(opcode: u8) -> Self {
        match opcode {
            0x00 => Opcode::NOP,
            0x01 => Opcode::MOVE,
            0x02 => Opcode::MOVE_FROM16,
            0x03 => Opcode::MOVE_16,
            0x04 => Opcode::MOVE_WIDE,
            0x05 => Opcode::MOVE_WIDE_FROM16,
            0x06 => Opcode::MOVE_WIDE_16,
            0x07 => Opcode::MOVE_OBJECT,
            0x08 => Opcode::MOVE_OBJECT_FROM16,
            0x09 => Opcode::MOVE_OBJECT_16,
            0x0a => Opcode::MOVE_RESULT,
            0x0b => Opcode::MOVE_RESULT_WIDE,
            0x0c => Opcode::MOVE_RESULT_OBJECT,
            0x0d => Opcode::MOVE_EXCEPTION,
            0x0e => Opcode::RETURN_VOID,
            0x0f => Opcode::RETURN,
            0x10 => Opcode::RETURN_WIDE,
            0x11 => Opcode::RETURN_OBJECT,
            0x12 => Opcode::CONST_4,
            0x13 => Opcode::CONST_16,
            0x14 => Opcode::CONST,
            0x15 => Opcode::CONST_HIGH16,
            0x16 => Opcode::CONST_WIDE_16,
            0x17 => Opcode::CONST_WIDE_32,
            0x18 => Opcode::CONST_WIDE,
            0x19 => Opcode::CONST_WIDE_HIGH16,
            0x1a => Opcode::CONST_STRING,
            0x1b => Opcode::CONST_STRING_JUMBO,
            0x1c => Opcode::CONST_CLASS,
            0x1d => Opcode::MONITOR_ENTER,
            0x1e => Opcode::MONITOR_EXIT,
            0x1f => Opcode::CHECK_CAST,
            0x20 => Opcode::INSTANCE_OF,
            0x21 => Opcode::ARRAY_LENGTH,
            0x22 => Opcode::NEW_INSTANCE,
            0x23 => Opcode::NEW_ARRAY,
            0x24 => Opcode::FILLED_NEW_ARRAY,
            0x25 => Opcode::FILLED_NEW_ARRAY_RANGE,
            0x26 => Opcode::FILL_ARRAY_DATA,
            0x27 => Opcode::THROW,
            0x28 => Opcode::GOTO,
            0x29 => Opcode::GOTO_16,
            0x2a => Opcode::GOTO_32,
            0x2b => Opcode::PACKED_SWITCH,
            0x2c => Opcode::SPARSE_SWITCH,
            0x2d => Opcode::CMPL_FLOAT,
            0x2e => Opcode::CMPG_FLOAT,
            0x2f => Opcode::CMPL_DOUBLE,
            0x30 => Opcode::CMPG_DOUBLE,
            0x31 => Opcode::CMP_LONG,
            0x32 => Opcode::IF_EQ,
            0x33 => Opcode::IF_NE,
            0x34 => Opcode::IF_LT,
            0x35 => Opcode::IF_GE,
            0x36 => Opcode::IF_GT,
            0x37 => Opcode::IF_LE,
            0x38 => Opcode::IF_EQZ,
            0x39 => Opcode::IF_NEZ,
            0x3a => Opcode::IF_LTZ,
            0x3b => Opcode::IF_GEZ,
            0x3c => Opcode::IF_GTZ,
            0x3d => Opcode::IF_LEZ,
            0x90 => Opcode::ADD_INT,
            0x91 => Opcode::SUB_INT,
            0x92 => Opcode::MUL_INT,
            0x93 => Opcode::DIV_INT,
            0x94 => Opcode::REM_INT,
            0x95 => Opcode::AND_INT,
            0x96 => Opcode::OR_INT,
            0x97 => Opcode::XOR_INT,
            0x98 => Opcode::SHL_INT,
            0x99 => Opcode::SHR_INT,
            0x9a => Opcode::USHR_INT,
            0x6e => Opcode::INVOKE_VIRTUAL,
            0x6f => Opcode::INVOKE_SUPER,
            0x70 => Opcode::INVOKE_DIRECT,
            0x71 => Opcode::INVOKE_STATIC,
            0x72 => Opcode::INVOKE_INTERFACE,
            0x44 => Opcode::AGET,
            0x45 => Opcode::AGET_WIDE,
            0x46 => Opcode::AGET_OBJECT,
            0x47 => Opcode::AGET_BOOLEAN,
            0x48 => Opcode::AGET_BYTE,
            0x49 => Opcode::AGET_CHAR,
            0x4a => Opcode::AGET_SHORT,
            0x4b => Opcode::APUT,
            0x4c => Opcode::APUT_WIDE,
            0x4d => Opcode::APUT_OBJECT,
            0x4e => Opcode::APUT_BOOLEAN,
            0x4f => Opcode::APUT_BYTE,
            0x50 => Opcode::APUT_CHAR,
            0x51 => Opcode::APUT_SHORT,
            0x52 => Opcode::IGET,
            0x53 => Opcode::IGET_WIDE,
            0x54 => Opcode::IGET_OBJECT,
            0x55 => Opcode::IGET_BOOLEAN,
            0x56 => Opcode::IGET_BYTE,
            0x57 => Opcode::IGET_CHAR,
            0x58 => Opcode::IGET_SHORT,
            0x59 => Opcode::IPUT,
            0x5a => Opcode::IPUT_WIDE,
            0x5b => Opcode::IPUT_OBJECT,
            0x5c => Opcode::IPUT_BOOLEAN,
            0x5d => Opcode::IPUT_BYTE,
            0x5e => Opcode::IPUT_CHAR,
            0x5f => Opcode::IPUT_SHORT,
            0x60 => Opcode::SGET,
            0x61 => Opcode::SGET_WIDE,
            0x62 => Opcode::SGET_OBJECT,
            0x63 => Opcode::SGET_BOOLEAN,
            0x64 => Opcode::SGET_BYTE,
            0x65 => Opcode::SGET_CHAR,
            0x66 => Opcode::SGET_SHORT,
            0x67 => Opcode::SPUT,
            0x68 => Opcode::SPUT_WIDE,
            0x69 => Opcode::SPUT_OBJECT,
            0x6a => Opcode::SPUT_BOOLEAN,
            0x6b => Opcode::SPUT_BYTE,
            0x6c => Opcode::SPUT_CHAR,
            0x6d => Opcode::SPUT_SHORT,
            0xb0 => Opcode::ADD_INT_2ADDR,
            0xb1 => Opcode::SUB_INT_2ADDR,
            0xb2 => Opcode::MUL_INT_2ADDR,
            0xb3 => Opcode::DIV_INT_2ADDR,
            0xb4 => Opcode::REM_INT_2ADDR,
            0xb5 => Opcode::AND_INT_2ADDR,
            0xb6 => Opcode::OR_INT_2ADDR,
            0xb7 => Opcode::XOR_INT_2ADDR,
            0xb8 => Opcode::SHL_INT_2ADDR,
            0xb9 => Opcode::SHR_INT_2ADDR,
            0xba => Opcode::USHR_INT_2ADDR,
            0xfa => Opcode::INVOKE_POLYMORPHIC,
            0xfb => Opcode::INVOKE_POLYMORPHIC_RANGE,
            0xfc => Opcode::INVOKE_CUSTOM,
            0xfd => Opcode::INVOKE_CUSTOM_RANGE,
            0xfe => Opcode::CONST_METHOD_HANDLE,
            0xff => Opcode::CONST_METHOD_TYPE,
            _ => Opcode::UNKNOWN,
        }
    }
}

impl Opcode {
    pub fn format(&self) -> InstructionFormat {
        match self {
            Opcode::NOP => InstructionFormat::Format10x,
            Opcode::MOVE | Opcode::MOVE_WIDE | Opcode::MOVE_OBJECT | Opcode::CONST_4 => InstructionFormat::Format12x,
            Opcode::MOVE_FROM16 | Opcode::MOVE_WIDE_FROM16 | Opcode::MOVE_OBJECT_FROM16 => InstructionFormat::Format22x,
            Opcode::MOVE_16 | Opcode::MOVE_WIDE_16 | Opcode::MOVE_OBJECT_16 => InstructionFormat::Format32x,
            Opcode::MOVE_RESULT | Opcode::MOVE_RESULT_WIDE | Opcode::MOVE_RESULT_OBJECT | 
            Opcode::MOVE_EXCEPTION | Opcode::RETURN | Opcode::RETURN_WIDE | Opcode::RETURN_OBJECT |
            Opcode::THROW => InstructionFormat::Format11x,
            Opcode::RETURN_VOID => InstructionFormat::Format10x,
            Opcode::CONST_16 | Opcode::CONST_HIGH16 | Opcode::CONST_WIDE_16 |
            Opcode::CONST_WIDE_HIGH16 => InstructionFormat::Format21s,
            Opcode::CONST | Opcode::CONST_WIDE_32 => InstructionFormat::Format31i,
            Opcode::CONST_WIDE => InstructionFormat::Format51l,
            Opcode::CONST_STRING | Opcode::CONST_CLASS | Opcode::CHECK_CAST |
            Opcode::NEW_INSTANCE => InstructionFormat::Format21c,
            Opcode::CONST_STRING_JUMBO => InstructionFormat::Format31c,
            Opcode::GOTO => InstructionFormat::Format10t,
            Opcode::GOTO_16 => InstructionFormat::Format20t,
            Opcode::GOTO_32 => InstructionFormat::Format30t,
            Opcode::PACKED_SWITCH => InstructionFormat::PackedSwitch,
            Opcode::SPARSE_SWITCH => InstructionFormat::SparseSwitch,
            Opcode::FILL_ARRAY_DATA => InstructionFormat::FillArrayData,
            Opcode::IF_EQ | Opcode::IF_NE | Opcode::IF_LT | Opcode::IF_GE |
            Opcode::IF_GT | Opcode::IF_LE => InstructionFormat::Format22t,
            Opcode::IF_EQZ | Opcode::IF_NEZ | Opcode::IF_LTZ | Opcode::IF_GEZ |
            Opcode::IF_GTZ | Opcode::IF_LEZ => InstructionFormat::Format21t,
            Opcode::INVOKE_VIRTUAL | Opcode::INVOKE_SUPER | Opcode::INVOKE_DIRECT |
            Opcode::INVOKE_STATIC | Opcode::INVOKE_INTERFACE => InstructionFormat::Format35c,
            Opcode::AGET | Opcode::AGET_WIDE | Opcode::AGET_OBJECT |
            Opcode::AGET_BOOLEAN | Opcode::AGET_BYTE | Opcode::AGET_CHAR |
            Opcode::AGET_SHORT | Opcode::APUT | Opcode::APUT_WIDE |
            Opcode::APUT_OBJECT | Opcode::APUT_BOOLEAN | Opcode::APUT_BYTE |
            Opcode::APUT_CHAR | Opcode::APUT_SHORT => InstructionFormat::Format23x,
            Opcode::IGET | Opcode::IGET_WIDE | Opcode::IGET_OBJECT |
            Opcode::IGET_BOOLEAN | Opcode::IGET_BYTE | Opcode::IGET_CHAR |
            Opcode::IGET_SHORT | Opcode::IPUT | Opcode::IPUT_WIDE |
            Opcode::IPUT_OBJECT | Opcode::IPUT_BOOLEAN | Opcode::IPUT_BYTE |
            Opcode::IPUT_CHAR | Opcode::IPUT_SHORT => InstructionFormat::Format22c,
            Opcode::SGET | Opcode::SGET_WIDE | Opcode::SGET_OBJECT |
            Opcode::SGET_BOOLEAN | Opcode::SGET_BYTE | Opcode::SGET_CHAR |
            Opcode::SGET_SHORT | Opcode::SPUT | Opcode::SPUT_WIDE |
            Opcode::SPUT_OBJECT | Opcode::SPUT_BOOLEAN | Opcode::SPUT_BYTE |
            Opcode::SPUT_CHAR | Opcode::SPUT_SHORT => InstructionFormat::Format21c,
            Opcode::ADD_INT_2ADDR | Opcode::SUB_INT_2ADDR | Opcode::MUL_INT_2ADDR |
            Opcode::DIV_INT_2ADDR | Opcode::REM_INT_2ADDR | Opcode::AND_INT_2ADDR |
            Opcode::OR_INT_2ADDR | Opcode::XOR_INT_2ADDR | Opcode::SHL_INT_2ADDR |
            Opcode::SHR_INT_2ADDR | Opcode::USHR_INT_2ADDR => InstructionFormat::Format12x,
            Opcode::INVOKE_POLYMORPHIC => InstructionFormat::Format35c,
            Opcode::INVOKE_POLYMORPHIC_RANGE => InstructionFormat::Format3rc,
            Opcode::INVOKE_CUSTOM => InstructionFormat::Format35c,
            Opcode::INVOKE_CUSTOM_RANGE => InstructionFormat::Format3rc,
            Opcode::CONST_METHOD_HANDLE | Opcode::CONST_METHOD_TYPE => InstructionFormat::Format21c,
            _ => InstructionFormat::Unknown,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Opcode::NOP => "nop",
            Opcode::MOVE => "move",
            Opcode::MOVE_FROM16 => "move/from16",
            Opcode::MOVE_16 => "move/16",
            Opcode::MOVE_WIDE => "move-wide",
            Opcode::MOVE_WIDE_FROM16 => "move-wide/from16",
            Opcode::MOVE_WIDE_16 => "move-wide/16",
            Opcode::MOVE_OBJECT => "move-object",
            Opcode::MOVE_OBJECT_FROM16 => "move-object/from16",
            Opcode::MOVE_OBJECT_16 => "move-object/16",
            Opcode::MOVE_RESULT => "move-result",
            Opcode::MOVE_RESULT_WIDE => "move-result-wide",
            Opcode::MOVE_RESULT_OBJECT => "move-result-object",
            Opcode::MOVE_EXCEPTION => "move-exception",
            Opcode::RETURN_VOID => "return-void",
            Opcode::RETURN => "return",
            Opcode::RETURN_WIDE => "return-wide",
            Opcode::RETURN_OBJECT => "return-object",
            Opcode::CONST_4 => "const/4",
            Opcode::CONST_16 => "const/16",
            Opcode::CONST => "const",
            Opcode::CONST_HIGH16 => "const/high16",
            Opcode::CONST_WIDE_16 => "const-wide/16",
            Opcode::CONST_WIDE_32 => "const-wide/32",
            Opcode::CONST_WIDE => "const-wide",
            Opcode::CONST_WIDE_HIGH16 => "const-wide/high16",
            Opcode::CONST_STRING => "const-string",
            Opcode::CONST_STRING_JUMBO => "const-string/jumbo",
            Opcode::CONST_CLASS => "const-class",
            Opcode::MONITOR_ENTER => "monitor-enter",
            Opcode::MONITOR_EXIT => "monitor-exit",
            Opcode::CHECK_CAST => "check-cast",
            Opcode::INSTANCE_OF => "instance-of",
            Opcode::ARRAY_LENGTH => "array-length",
            Opcode::NEW_INSTANCE => "new-instance",
            Opcode::NEW_ARRAY => "new-array",
            Opcode::FILLED_NEW_ARRAY => "filled-new-array",
            Opcode::FILLED_NEW_ARRAY_RANGE => "filled-new-array/range",
            Opcode::FILL_ARRAY_DATA => "fill-array-data",
            Opcode::THROW => "throw",
            Opcode::GOTO => "goto",
            Opcode::GOTO_16 => "goto/16",
            Opcode::GOTO_32 => "goto/32",
            Opcode::PACKED_SWITCH => "packed-switch",
            Opcode::SPARSE_SWITCH => "sparse-switch",
            Opcode::CMPL_FLOAT => "cmpl-float",
            Opcode::CMPG_FLOAT => "cmpg-float",
            Opcode::CMPL_DOUBLE => "cmpl-double",
            Opcode::CMPG_DOUBLE => "cmpg-double",
            Opcode::CMP_LONG => "cmp-long",
            Opcode::IF_EQ => "if-eq",
            Opcode::IF_NE => "if-ne",
            Opcode::IF_LT => "if-lt",
            Opcode::IF_GE => "if-ge",
            Opcode::IF_GT => "if-gt",
            Opcode::IF_LE => "if-le",
            Opcode::IF_EQZ => "if-eqz",
            Opcode::IF_NEZ => "if-nez",
            Opcode::IF_LTZ => "if-ltz",
            Opcode::IF_GEZ => "if-gez",
            Opcode::IF_GTZ => "if-gtz",
            Opcode::IF_LEZ => "if-lez",
            Opcode::ADD_INT => "add-int",
            Opcode::SUB_INT => "sub-int",
            Opcode::MUL_INT => "mul-int",
            Opcode::DIV_INT => "div-int",
            Opcode::REM_INT => "rem-int",
            Opcode::AND_INT => "and-int",
            Opcode::OR_INT => "or-int",
            Opcode::XOR_INT => "xor-int",
            Opcode::SHL_INT => "shl-int",
            Opcode::SHR_INT => "shr-int",
            Opcode::USHR_INT => "ushr-int",
            Opcode::INVOKE_VIRTUAL => "invoke-virtual",
            Opcode::INVOKE_SUPER => "invoke-super",
            Opcode::INVOKE_DIRECT => "invoke-direct",
            Opcode::INVOKE_STATIC => "invoke-static",
            Opcode::INVOKE_INTERFACE => "invoke-interface",
            Opcode::AGET => "aget",
            Opcode::AGET_WIDE => "aget-wide",
            Opcode::AGET_OBJECT => "aget-object",
            Opcode::AGET_BOOLEAN => "aget-boolean",
            Opcode::AGET_BYTE => "aget-byte",
            Opcode::AGET_CHAR => "aget-char",
            Opcode::AGET_SHORT => "aget-short",
            Opcode::APUT => "aput",
            Opcode::APUT_WIDE => "aput-wide",
            Opcode::APUT_OBJECT => "aput-object",
            Opcode::APUT_BOOLEAN => "aput-boolean",
            Opcode::APUT_BYTE => "aput-byte",
            Opcode::APUT_CHAR => "aput-char",
            Opcode::APUT_SHORT => "aput-short",
            Opcode::IGET => "iget",
            Opcode::IGET_WIDE => "iget-wide",
            Opcode::IGET_OBJECT => "iget-object",
            Opcode::IGET_BOOLEAN => "iget-boolean",
            Opcode::IGET_BYTE => "iget-byte",
            Opcode::IGET_CHAR => "iget-char",
            Opcode::IGET_SHORT => "iget-short",
            Opcode::IPUT => "iput",
            Opcode::IPUT_WIDE => "iput-wide",
            Opcode::IPUT_OBJECT => "iput-object",
            Opcode::IPUT_BOOLEAN => "iput-boolean",
            Opcode::IPUT_BYTE => "iput-byte",
            Opcode::IPUT_CHAR => "iput-char",
            Opcode::IPUT_SHORT => "iput-short",
            Opcode::SGET => "sget",
            Opcode::SGET_WIDE => "sget-wide",
            Opcode::SGET_OBJECT => "sget-object",
            Opcode::SGET_BOOLEAN => "sget-boolean",
            Opcode::SGET_BYTE => "sget-byte",
            Opcode::SGET_CHAR => "sget-char",
            Opcode::SGET_SHORT => "sget-short",
            Opcode::SPUT => "sput",
            Opcode::SPUT_WIDE => "sput-wide",
            Opcode::SPUT_OBJECT => "sput-object",
            Opcode::SPUT_BOOLEAN => "sput-boolean",
            Opcode::SPUT_BYTE => "sput-byte",
            Opcode::SPUT_CHAR => "sput-char",
            Opcode::SPUT_SHORT => "sput-short",
            Opcode::ADD_INT_2ADDR => "add-int/2addr",
            Opcode::SUB_INT_2ADDR => "sub-int/2addr",
            Opcode::MUL_INT_2ADDR => "mul-int/2addr",
            Opcode::DIV_INT_2ADDR => "div-int/2addr",
            Opcode::REM_INT_2ADDR => "rem-int/2addr",
            Opcode::AND_INT_2ADDR => "and-int/2addr",
            Opcode::OR_INT_2ADDR => "or-int/2addr",
            Opcode::XOR_INT_2ADDR => "xor-int/2addr",
            Opcode::SHL_INT_2ADDR => "shl-int/2addr",
            Opcode::SHR_INT_2ADDR => "shr-int/2addr",
            Opcode::USHR_INT_2ADDR => "ushr-int/2addr",
            Opcode::INVOKE_POLYMORPHIC => "invoke-polymorphic",
            Opcode::INVOKE_POLYMORPHIC_RANGE => "invoke-polymorphic/range",
            Opcode::INVOKE_CUSTOM => "invoke-custom",
            Opcode::INVOKE_CUSTOM_RANGE => "invoke-custom/range",
            Opcode::CONST_METHOD_HANDLE => "const-method-handle",
            Opcode::CONST_METHOD_TYPE => "const-method-type",
            _ => "unknown",
        }
    }

    pub fn reference_type(&self) -> ReferenceType {
        match self {
            Opcode::CONST_STRING | Opcode::CONST_STRING_JUMBO => ReferenceType::String,
            Opcode::CONST_CLASS | Opcode::CHECK_CAST | Opcode::INSTANCE_OF | 
            Opcode::NEW_INSTANCE | Opcode::NEW_ARRAY => ReferenceType::Type,
            Opcode::IGET | Opcode::IGET_WIDE | Opcode::IGET_OBJECT |
            Opcode::IGET_BOOLEAN | Opcode::IGET_BYTE | Opcode::IGET_CHAR |
            Opcode::IGET_SHORT | Opcode::IPUT | Opcode::IPUT_WIDE |
            Opcode::IPUT_OBJECT | Opcode::IPUT_BOOLEAN | Opcode::IPUT_BYTE |
            Opcode::IPUT_CHAR | Opcode::IPUT_SHORT | Opcode::SGET | 
            Opcode::SGET_WIDE | Opcode::SGET_OBJECT | Opcode::SGET_BOOLEAN | 
            Opcode::SGET_BYTE | Opcode::SGET_CHAR | Opcode::SGET_SHORT | 
            Opcode::SPUT | Opcode::SPUT_WIDE | Opcode::SPUT_OBJECT | 
            Opcode::SPUT_BOOLEAN | Opcode::SPUT_BYTE | Opcode::SPUT_CHAR | 
            Opcode::SPUT_SHORT => ReferenceType::Field,
            Opcode::INVOKE_VIRTUAL | Opcode::INVOKE_SUPER | Opcode::INVOKE_DIRECT |
            Opcode::INVOKE_STATIC | Opcode::INVOKE_INTERFACE | Opcode::INVOKE_POLYMORPHIC |
            Opcode::INVOKE_CUSTOM => ReferenceType::Method,
            Opcode::CONST_METHOD_HANDLE => ReferenceType::Method,
            Opcode::CONST_METHOD_TYPE => ReferenceType::Type,
            _ => ReferenceType::None,
        }
    }
}

#[derive(Debug)]
pub struct Instruction {
    pub offset: usize,
    pub opcode: Opcode,
    pub format: InstructionFormat,
    pub instruction_size: usize,
    pub operands: Vec<u16>,
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}: {}", self.offset, self.opcode.name())?;
        
        match self.format {
            InstructionFormat::Format10x => Ok(()),
            InstructionFormat::Format11x => write!(f, " v{}", self.operands[0]),
            InstructionFormat::Format12x => write!(f, " v{}, v{}", self.operands[0], self.operands[1]),
            InstructionFormat::Format21c => write!(f, " v{}, @{:04x}", self.operands[0], self.operands[1]),
            InstructionFormat::Format21s => 
                write!(f, " v{}, #{}", self.operands[0], self.operands[1] as i16),
            InstructionFormat::Format21t => 
                write!(f, " v{}, {:+#x}", self.operands[0], self.operands[1] as i16),
            InstructionFormat::Format22x => 
                write!(f, " v{}, v{}", self.operands[0], self.operands[1]),
            InstructionFormat::Format22c => 
                write!(f, " v{}, v{}, @{:04x}", self.operands[0], self.operands[1], self.operands[2]),
            InstructionFormat::Format22t => 
                write!(f, " v{}, v{}, {:+#x}", self.operands[0], self.operands[1], self.operands[2] as i16),
            InstructionFormat::Format23x => 
                write!(f, " v{}, v{}, v{}", self.operands[0], self.operands[1], self.operands[2]),
            InstructionFormat::Format31c => 
                write!(f, " v{}, @{:08x}", self.operands[0], 
                       ((self.operands[1] as u32) << 16) | (self.operands[2] as u32)),
            InstructionFormat::Format31i => {
                let value = ((self.operands[1] as i32) << 16) | (self.operands[2] as i32);
                write!(f, " v{}, #{}", self.operands[0], value)
            },
            InstructionFormat::Format32x => 
                write!(f, " v{}, v{}", self.operands[0], self.operands[1]),
            InstructionFormat::Format35c => {
                let count = self.operands[0];
                write!(f, " {{")?;
                for i in 0..count as usize {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "v{}", self.operands[i+1])?;
                }
                write!(f, "}}, @{:04x}", self.operands[count as usize + 1])
            },
            InstructionFormat::Format3rc => {
                let count = self.operands[0];
                let start_reg = self.operands[1];
                write!(f, " {{v{} .. v{}}}, @{:04x}", 
                       start_reg, start_reg + count - 1, self.operands[2])
            },
            InstructionFormat::Format10t | InstructionFormat::Format20t | InstructionFormat::Format30t => {
                let offset = match self.format {
                    InstructionFormat::Format10t => self.operands[0] as i8 as i32,
                    InstructionFormat::Format20t => self.operands[0] as i16 as i32,
                    InstructionFormat::Format30t => ((self.operands[0] as i32) << 16) | (self.operands[1] as i32),
                    _ => unreachable!(),
                };
                write!(f, " {:+#x}", offset)
            },
            InstructionFormat::Format51l => {
                let low = ((self.operands[1] as u64) << 16) | (self.operands[2] as u64);
                let high = ((self.operands[3] as u64) << 16) | (self.operands[4] as u64);
                let value = (high << 32) | low;
                write!(f, " v{}, #{}", self.operands[0], value as i64)
            },
            InstructionFormat::PackedSwitch | InstructionFormat::SparseSwitch | InstructionFormat::FillArrayData => {
                write!(f, " [data]") // Simplified for now
            },
            _ => write!(f, " [format not implemented]"),
        }
    }
}

// Function to read an instruction from bytes
pub fn read_instruction(bytes: &[u8], offset: usize) -> Option<Instruction> {
    if offset >= bytes.len() {
        return None;
    }

    let opcode = bytes[offset];
    let opcode = Opcode::from(opcode);
    let format = opcode.format();

    // Get size and registers based on format
    let (size, registers) = match format {
        InstructionFormat::Format10x => (2, vec![]),
        InstructionFormat::Format12x => {
            if offset + 1 >= bytes.len() { return None; }
            let byte2 = bytes[offset + 1];
            (2, vec![(byte2 & 0xF) as u16, (byte2 >> 4) as u16])
        },
        InstructionFormat::Format11x => {
            if offset + 1 >= bytes.len() { return None; }
            (2, vec![bytes[offset + 1] as u16])
        },
        InstructionFormat::Format10t => {
            (2, vec![bytes[offset + 1] as u16])
        },
        InstructionFormat::Format20t => {
            if offset + 3 >= bytes.len() { return None; }
            let offset_val = (bytes[offset + 2] as u16) | ((bytes[offset + 3] as u16) << 8);
            (4, vec![offset_val])
        },
        InstructionFormat::Format21c | InstructionFormat::Format21s | InstructionFormat::Format21t => {
            if offset + 3 >= bytes.len() { return None; }
            let reg = bytes[offset + 1] as u16;
            let value = (bytes[offset + 2] as u16) | ((bytes[offset + 3] as u16) << 8);
            (4, vec![reg, value])
        },
        InstructionFormat::Format22x => {
            if offset + 3 >= bytes.len() { return None; }
            let reg = bytes[offset + 1] as u16;
            let value = (bytes[offset + 2] as u16) | ((bytes[offset + 3] as u16) << 8);
            (4, vec![reg, value])
        },
        InstructionFormat::Format22c | InstructionFormat::Format22t => {
            if offset + 3 >= bytes.len() { return None; }
            let byte2 = bytes[offset + 1];
            let reg1 = (byte2 & 0xF) as u16;
            let reg2 = (byte2 >> 4) as u16;
            let value = (bytes[offset + 2] as u16) | ((bytes[offset + 3] as u16) << 8);
            (4, vec![reg1, reg2, value])
        },
        InstructionFormat::Format23x => {
            if offset + 3 >= bytes.len() { return None; }
            let reg1 = bytes[offset + 1] as u16;
            let reg2 = bytes[offset + 2] as u16;
            let reg3 = bytes[offset + 3] as u16;
            (4, vec![reg1, reg2, reg3])
        },
        InstructionFormat::Format30t => {
            if offset + 5 >= bytes.len() { return None; }
            let value_low = (bytes[offset + 2] as u16) | ((bytes[offset + 3] as u16) << 8);
            let value_high = (bytes[offset + 4] as u16) | ((bytes[offset + 5] as u16) << 8);
            (6, vec![value_low, value_high])
        },
        InstructionFormat::Format31i | InstructionFormat::Format31c => {
            if offset + 5 >= bytes.len() { return None; }
            let reg = bytes[offset + 1] as u16;
            let value_low = (bytes[offset + 2] as u16) | ((bytes[offset + 3] as u16) << 8);
            let value_high = (bytes[offset + 4] as u16) | ((bytes[offset + 5] as u16) << 8);
            (6, vec![reg, value_high, value_low])
        },
        InstructionFormat::Format32x => {
            if offset + 5 >= bytes.len() { return None; }
            let reg1 = (bytes[offset + 2] as u16) | ((bytes[offset + 3] as u16) << 8);
            let reg2 = (bytes[offset + 4] as u16) | ((bytes[offset + 5] as u16) << 8);
            (6, vec![reg1, reg2])
        },
        InstructionFormat::Format35c => {
            if offset + 5 >= bytes.len() { return None; }
            let byte1 = bytes[offset + 1];
            let max_registers = 5; // Maximum registers allowed for Format35c
            let count = std::cmp::min((byte1 >> 4) & 0xF, max_registers) as u16;
            
            // Read method reference index
            let ref_idx = (bytes[offset + 2] as u16) | ((bytes[offset + 3] as u16) << 8);
            
            // Read register arguments
            let mut registers = Vec::with_capacity(7); // Increased from 5 to support count + 5 registers + ref_idx
            registers.push(count); // Store count as first operand
            
            if count > 0 {
                registers.push((byte1 & 0xF) as u16); // First reg
            }
            
            let byte4 = bytes[offset + 4];
            let byte5 = bytes[offset + 5];
            
            if count > 1 {
                registers.push((byte4 & 0xF) as u16); // Second reg
            }
            if count > 2 {
                registers.push(((byte4 >> 4) & 0xF) as u16); // Third reg
            }
            if count > 3 {
                registers.push((byte5 & 0xF) as u16); // Fourth reg
            }
            if count > 4 {
                registers.push(((byte5 >> 4) & 0xF) as u16); // Fifth reg
            }
            
            registers.push(ref_idx);
            (6, registers)
        },
        InstructionFormat::Format3rc => {
            if offset + 5 >= bytes.len() { return None; }
            let byte1 = bytes[offset + 1];
            let count = byte1 as u16;
            let start_reg = (bytes[offset + 4] as u16) | ((bytes[offset + 5] as u16) << 8);
            let ref_idx = (bytes[offset + 2] as u16) | ((bytes[offset + 3] as u16) << 8);
            (6, vec![count, start_reg, ref_idx])
        },
        InstructionFormat::Format51l => {
            if offset + 9 >= bytes.len() { return None; }
            let reg = bytes[offset + 1] as u16;
            
            let value_0 = (bytes[offset + 2] as u16) | ((bytes[offset + 3] as u16) << 8);
            let value_1 = (bytes[offset + 4] as u16) | ((bytes[offset + 5] as u16) << 8);
            let value_2 = (bytes[offset + 6] as u16) | ((bytes[offset + 7] as u16) << 8);
            let value_3 = (bytes[offset + 8] as u16) | ((bytes[offset + 9] as u16) << 8);
            
            (10, vec![reg, value_0, value_1, value_2, value_3])
        },
        InstructionFormat::PackedSwitch | 
        InstructionFormat::SparseSwitch | 
        InstructionFormat::FillArrayData => {
            if offset + 5 >= bytes.len() { return None; }
            // Read data size
            let size = (bytes[offset + 2] as u16) | ((bytes[offset + 3] as u16) << 8);
            // Calculate total instruction size including payload, using checked arithmetic
            let total_size = size.checked_mul(2)
                .and_then(|x| x.checked_add(4))
                .map(|x| x as usize)
                .filter(|&x| offset + x <= bytes.len())
                .or_else(|| Some(2))?; // Fallback to minimal size on overflow
            (total_size, vec![size])
        },
        InstructionFormat::Unknown => {
            warn!("Unknown instruction format for opcode 0x{:02x}", opcode);
            (2, vec![])
        },
    };

    Some(Instruction {
        offset,
        opcode,
        format,
        instruction_size: size,
        operands: registers,
    })
}

pub fn disassemble_bytecode(bytecode: &[u8], offset: usize) -> Vec<Instruction> {
    let mut result = Vec::new();
    let mut current_offset = offset;

    while current_offset < bytecode.len() {
        if let Some(instruction) = read_instruction(bytecode, current_offset) {
            current_offset += instruction.instruction_size;
            result.push(instruction);
        } else {
            // We couldn't read this instruction, just move to the next byte
            current_offset += 1;
        }
    }

    result
}