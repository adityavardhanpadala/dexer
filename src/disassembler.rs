use crate::types::CodeItem;
use lazy_static::lazy_static;
use log::{debug, info, warn};
use std::collections::{BTreeMap, HashMap};

/// Dex Instructions are not fixed size so like x86/amd64 we each instruction has a decode format associated with it.
// --- Instruction Formats ---
// | Bitwise                                | Format ID | Syntax                                                                                         |
// |----------------------------------------|-----------|------------------------------------------------------------------------------------------------|
// | N/A                                    | 00x       | `N/A`                                                                                          |
// | `ØØ|op`                                | 10x       | `op`                                                                                           |
// | `B|A|op`                               | 12x       | `op vA, vB`                                                                                    |
// | `11n`                                  | 11n       | `op vA, #+B`                                                                                   |
// | `AA|op`                                | 11x       | `op vAA`                                                                                       |
// | `10t`                                  | 10t       | `op +AA`                                                                                       |
// | `ØØ|op AAAA`                           | 20t       | `op +AAAA`                                                                                     |
// | `AA|op BBBB`                           | 20bc      | `op AA, kind@BBBB`                                                                             |
// | `AA|op BBBB`                           | 22x       | `op vAA, vBBBB`                                                                                |
// | `B|A|op AA`                            | 21t       | `op vAA, +BBBB`                                                                                |
// | `B|A|op BB`                            | 21s       | `op vAA, #+BBBB`                                                                               |
// | `B|A|op HH`                            | 21h       | `op vAA, #+BBBB0000` / `op vAA, #+BBBB000000000000`                                            |
// | `B|A|op CC`                            | 21c       | `op vAA, type@BBBB` / `op vAA, field@BBBB`                                                     |
// |                                        |           |  / `op vAA, method_handle@BBBB` / `op vAA, proto@BBBB` / `op vAA, string@BBBB` |               |
// | `AA|op CC|BB`                          | 23x       | `op vAA, vBB, vCC`                                                                             |
// | `AA|op CC|BB`                          | 22b       | `op vAA, vBB, #+CC`                                                                            |
// | `B|A|op CCCC`                          | 22t       | `op vA, vB, +CCCC`                                                                             |
// | `B|A|op CCCC`                          | 22s       | `op vA, vB, #+CCCC`                                                                            |
// | `B|A|op CCCC`                          | 22c       | `op vA, vB, type@CCCC` / `op vA, vB, field@CCCC`                                               |
// | `B|A|op CCCC`                          | 22cs      | `op vA, vB, fieldoff@CCCC`                                                                     |
// | `ØØ|op AAAA_{lo} AAAA_{hi}`            | 30t       | `op +AAAAAAAA`                                                                                 |
// | `ØØ|op AAAA BBBB`                      | 32x       | `op vAAAA, vBBBB`                                                                              |
// | `AA|op BBBB_{lo} BBBB_{hi}`            | 31i       | `op vAA, #+BBBBBBBB`                                                                           |
// | `AA|op BBBB_{lo} BBBB_{hi}`            | 31t       | `op vAA, +BBBBBBBB`                                                                            |
// | `AA|op BBBB_{lo} BBBB_{hi}`            | 31c       | `op vAA, string@BBBBBBBB`                                                                      |
// | `A|G|op BBBB F|E|D|C`                  | 35c       | variadic: [`A=5`] `op {vC..vG}, meth@BBBB`; …; [`A=0`] `op {}, kind@BBBB`                      |
// | `A|G|op BBBB F|E|D|C`                  | 35ms      | variadic: [`A=5`] `op {vC..vG}, vtaboff@BBBB`; …; [`A=1`] `op {vC}, vtaboff@BBBB`              |
// | `A|G|op BBBB F|E|D|C`                  | 35mi      | variadic: [`A=5`] `op {vC..vG}, inline@BBBB`; …; [`A=1`] `op {vC}, inline@BBBB`                |
// | `AA|op BBBB CCCC`                      | 3rc       | `op {vCCCC..vNNNN}, meth@BBBB`; `op {vCCCC..vNNNN}, site@BBBB`; `op {vCCCC..vNNNN}, type@BBBB` |
// | `AA|op BBBB CCCC`                      | 3rms      | `op {vCCCC..vNNNN}, vtaboff@BBBB`                                                              |
// | `AA|op BBBB CCCC`                      | 3rmi      | `op {vCCCC..vNNNN}, inline@BBBB`                                                               |
// | `A|G|op BBBB F|E|D|C HHHH`             | 45cc      | variadic: [`A=5`] `op {vC..vG}, meth@BBBB, proto@HHHH`; …                                      |
// | `AA|op BBBB CCCC HHHH`                 | 4rcc      | `op> {vCCCC..vNNNN}, meth@BBBB, proto@HHHH`                                                    |
// | `AA|op BBBB_{lo} BBBB BBBB BBBB_{hi}`  | 51l       | `op vAA, #+BBBBBBBBBBBBBBBB`                                                                   |

// Table Source: https://source.android.com/docs/core/runtime/instruction-formats

/// Represents the various formats for Dalvik bytecode instructions
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InstructionFormat {
    /// N/A
    Format00x,
    /// ØØ|op
    Format10x,
    /// B|A|op
    Format12x,
    /// op vA, #+B
    Format11n,
    /// op vAA
    Format11x,
    /// op +AA
    Format10t,
    /// op +AAAA
    Format20t,
    /// op AA, kind@BBBB
    Format20bc,
    /// op vAA, vBBBB
    Format22x,
    /// op vAA, +BBBB
    Format21t,
    /// op vAA, #+BBBB
    Format21s,
    /// op vAA, #+BBBB0000 / op vAA, #+BBBB000000000000
    Format21h,
    /// op vAA, type@BBBB / field@BBBB / method_handle@BBBB / proto@BBBB / string@BBBB
    Format21c,
    /// op vAA, vBB, vCC
    Format23x,
    /// op vAA, vBB, #+CC
    Format22b,
    // op vA, vB, #+CC
    Format22t,
    /// op vA, vB, #+CCCC
    Format22s,
    /// op vA, vB, type@CCCC / field@CCCC
    Format22c,
    /// op vA, vB, fieldoff@CCCC
    Format22cs,
    /// op +AAAAAAAA
    Format30t,
    /// op vAAAA, vBBBB
    Format32x,
    /// op vAA, #+BBBBBBBB
    Format31i,
    /// op vAA, +BBBBBBBB
    Format31t,
    /// op vAA, string@BBBBBBBB
    Format31c,
    /// variadic: [A=5] op {vC..vG}, meth@BBBB; …; [A=0] op {}, kind@BBBB
    Format35c,
    /// variadic: [A=5] op {vC..vG}, vtaboff@BBBB; …; [A=1] op {vC}, vtaboff@BBBB
    Format35ms,
    /// variadic: [A=5] op {vC..vG}, inline@BBBB; …; [A=1] op {vC}, inline@BBBB
    Format35mi,
    /// op {vCCCC..vNNNN}, meth@BBBB / site@BBBB / type@BBBB
    Format3rc,
    /// op {vCCCC..vNNNN}, vtaboff@BBBB
    Format3rms,
    /// op {vCCCC..vNNNN}, inline@BBBB
    Format3rmi,
    /// variadic: [A=5] op {vC..vG}, meth@BBBB, proto@HHHH; …
    Format45cc,
    /// op> {vCCCC..vNNNN}, meth@BBBB, proto@HHHH
    Format4rcc,
    /// op vAA, #+BBBBBBBBBBBBBBBB
    Format51l,
}

macro_rules! declare_opcodes {
    (
        $(
            $value:literal => $name:ident, $str_name:literal, $format:ident;
        )*
    ) => {
        #[allow(non_camel_case_types)] // This convention looks better for opcodes.
        #[derive(Debug, Copy, Clone, Ord, PartialEq, PartialOrd, Eq)]
        pub enum Opcode {
            $(
                $name = $value,
            )*
        }

        impl Opcode {
            pub fn from_byte(byte: u8) -> Option<Opcode> {
                match byte {
                    $(
                        $value => Some(Opcode::$name),
                    )*
                    _ => {
                        warn!("Unknown Opcode byte: 0x{:02x}", byte);
                        None
                    },
                }
            }

            pub fn name(&self) -> &'static str {
                match self {
                    $(
                        Opcode::$name => $str_name,
                    )*
                }
            }

            pub fn format(&self) -> InstructionFormat {
                match self {
                    $(
                        Opcode::$name => InstructionFormat::$format,
                    )*
                }
            }
        }
    };
}

// --- Opcode Constants ---
// Refer to: https://source.android.com/docs/core/dalvik/dalvik-bytecode
declare_opcodes! {
    0x00 => NOP, "nop", Format10x;
    0x01 => MOVE, "move", Format12x;
    0x02 => MOVE_FROM16, "move/from16", Format22x;
    0x03 => MOVE_16, "move/16", Format32x;
    0x04 => MOVE_WIDE, "move-wide", Format12x;
    0x05 => MOVE_WIDE_FROM16, "move-wide/from16", Format22x;
    0x06 => MOVE_WIDE_16, "move-wide/16", Format32x;
    0x07 => MOVE_OBJECT, "move-object", Format12x;
    0x08 => MOVE_OBJECT_FROM16, "move-object/from16", Format22x;
    0x09 => MOVE_OBJECT_16, "move-object/16", Format32x;
    0x0a => MOVE_RESULT, "move-result", Format11x;
    0x0b => MOVE_RESULT_WIDE, "move-result-wide", Format11x;
    0x0c => MOVE_RESULT_OBJECT, "move-result-object", Format11x;
    0x0d => MOVE_EXCEPTION, "move-exception", Format11x;
    0x0e => RETURN_VOID, "return-void", Format10x;
    0x0f => RETURN, "return", Format11x;
    0x10 => RETURN_WIDE, "return-wide", Format11x;
    0x11 => RETURN_OBJECT, "return-object", Format11x;
    0x12 => CONST_4, "const/4", Format11n;
    0x13 => CONST_16, "const/16", Format21s;
    0x14 => CONST, "const", Format31i;
    0x15 => CONST_HIGH16, "const/high16", Format21h;
    0x16 => CONST_WIDE_16, "const-wide/16", Format21s;
    0x17 => CONST_WIDE_32, "const-wide/32", Format31i;
    0x18 => CONST_WIDE, "const-wide", Format51l;
    0x19 => CONST_WIDE_HIGH16, "const-wide/high16", Format21h;
    0x1a => CONST_STRING, "const-string", Format21c;
    0x1b => CONST_STRING_JUMBO, "const-string/jumbo", Format31c;
    0x1c => CONST_CLASS, "const-class", Format21c;
    0x1d => MONITOR_ENTER, "monitor-enter", Format11x;
    0x1e => MONITOR_EXIT, "monitor-exit", Format11x;
    0x1f => CHECK_CAST, "check-cast", Format21c;
    0x20 => INSTANCE_OF, "instance-of", Format22c;
    0x21 => ARRAY_LENGTH, "array-length", Format12x;
    0x22 => NEW_INSTANCE, "new-instance", Format21c;
    0x23 => NEW_ARRAY, "new-array", Format22c;
    0x24 => FILLED_NEW_ARRAY, "filled-new-array", Format35c;
    0x25 => FILLED_NEW_ARRAY_RANGE, "filled-new-array/range", Format3rc;
    0x26 => FILL_ARRAY_DATA, "fill-array-data", Format31t;
    0x27 => THROW, "throw", Format11x;
    0x28 => GOTO, "goto", Format10t;
    0x29 => GOTO_16, "goto/16", Format20t;
    0x2a => GOTO_32, "goto/32", Format30t;
    0x2b => PACKED_SWITCH, "packed-switch", Format31t;
    0x2c => SPARSE_SWITCH, "sparse-switch", Format31t;
    0x2d => CMPL_FLOAT, "cmpl-float", Format23x;
    0x2e => CMPG_FLOAT, "cmpg-float", Format23x;
    0x2f => CMPL_DOUBLE, "cmpl-double", Format23x;
    0x30 => CMPG_DOUBLE, "cmpg-double", Format23x;
    0x31 => CMP_LONG, "cmp-long", Format23x;
    0x32 => IF_EQ, "if-eq", Format22t;
    0x33 => IF_NE, "if-ne", Format22t;
    0x34 => IF_LT, "if-lt", Format22t;
    0x35 => IF_GE, "if-ge", Format22t;
    0x36 => IF_GT, "if-gt", Format22t;
    0x37 => IF_LE, "if-le", Format22t;
    0x38 => IF_EQZ, "if-eqz", Format21t;
    0x39 => IF_NEZ, "if-nez", Format21t;
    0x3a => IF_LTZ, "if-ltz", Format21t;
    0x3b => IF_GEZ, "if-gez", Format21t;
    0x3c => IF_GTZ, "if-gtz", Format21t;
    0x3d => IF_LEZ, "if-lex", Format21t;
    0x44 => AGET, "aget", Format23x;
    0x45 => AGET_WIDE, "aget-wide", Format23x;
    0x46 => AGET_OBJECT, "aget-object", Format23x;
    0x47 => AGET_BOOLEAN, "aget-boolean", Format23x;
    0x48 => AGET_BYTE, "aget-byte", Format23x;
    0x49 => AGET_CHAR, "aget-char", Format23x;
    0x4a => AGET_SHORT, "aget-short", Format23x;
    0x4b => APUT, "aput", Format23x;
    0x4c => APUT_WIDE, "aput-wide", Format23x;
    0x4d => APUT_OBJECT, "aput-object", Format23x;
    0x4e => APUT_BOOLEAN, "aput-boolean", Format23x;
    0x4f => APUT_BYTE, "aput-byte", Format23x;
    0x50 => APUT_CHAR, "aput-char", Format23x;
    0x51 => APUT_SHORT, "aput-short", Format23x;
    0x52 => IGET, "iget", Format22c;
    0x53 => IGET_WIDE, "iget-wide", Format22c;
    0x54 => IGET_OBJECT, "iget-object", Format22c;
    0x55 => IGET_BOOLEAN, "iget-boolean", Format22c;
    0x56 => IGET_BYTE, "iget-byte", Format22c;
    0x57 => IGET_CHAR, "iget-char", Format22c;
    0x58 => IGET_SHORT, "iget-short", Format22c;
    0x59 => IPUT, "iput", Format22c;
    0x5a => IPUT_WIDE, "iput-wide", Format22c;
    0x5b => IPUT_OBJECT, "iput-object", Format22c;
    0x5c => IPUT_BOOLEAN, "iput-boolean", Format22c;
    0x5d => IPUT_BYTE, "iput-byte", Format22c;
    0x5e => IPUT_CHAR, "iput-char", Format22c;
    0x5f => IPUT_SHORT, "iput-short", Format22c;
    0x60 => SGET, "sget", Format21c;
    0x61 => SGET_WIDE, "sget-wide", Format21c;
    0x62 => SGET_OBJECT, "sget-object", Format21c;
    0x63 => SGET_BOOLEAN, "sget-boolean", Format21c;
    0x64 => SGET_BYTE, "sget-byte", Format21c;
    0x65 => SGET_CHAR, "sget-char", Format21c;
    0x66 => SGET_SHORT, "sget-short", Format21c;
    0x67 => SPUT, "sput", Format21c;
    0x68 => SPUT_WIDE, "sput-wide", Format21c;
    0x69 => SPUT_OBJECT, "sput-object", Format21c;
    0x6a => SPUT_BOOLEAN, "sput-boolean", Format21c;
    0x6b => SPUT_BYTE, "sput-byte", Format21c;
    0x6c => SPUT_CHAR, "sput-char", Format21c;
    0x6d => SPUT_SHORT, "sput-short", Format21c;
    0x6e => INVOKE_VIRTUAL, "invoke-virtual", Format35c;
    0x6f => INVOKE_SUPER, "invoke-super", Format35c;
    0x70 => INVOKE_DIRECT, "invoke-direct", Format35c;
    0x71 => INVOKE_STATIC, "invoke-static", Format35c;
    0x72 => INVOKE_INTERFACE, "invoke-interface", Format35c;
    0x74 => INVOKE_VIRTUAL_RANGE, "invoke-virtual/range", Format3rc;
    0x75 => INVOKE_SUPER_RANGE, "invoke-super/range", Format3rc;
    0x76 => INVOKE_DIRECT_RANGE, "invoke-direct/range", Format3rc;
    0x77 => INVOKE_STATIC_RANGE, "invoke-static/range", Format3rc;
    0x78 => INVOKE_INTERFACE_RANGE, "invoke-interface/range", Format3rc;
    0x7b => NEG_INT, "neg-int", Format12x;
    0x7c => NOT_INT, "not-int", Format12x;
    0x7d => NEG_LONG, "neg-long", Format12x;
    0x7e => NOT_LONG, "not-long", Format12x;
    0x7f => NEG_FLOAT, "neg-float", Format12x;
    0x80 => NEG_DOUBLE, "neg-double", Format12x;
    0x81 => INT_TO_LONG, "int-to-long", Format12x;
    0x82 => INT_TO_FLOAT, "int-to-float", Format12x;
    0x83 => INT_TO_DOUBLE, "int-to-double", Format12x;
    0x84 => LONG_TO_INT, "long-to-int", Format12x;
    0x85 => LONG_TO_FLOAT, "long-to-float", Format12x;
    0x86 => LONG_TO_DOUBLE, "long-to-double", Format12x;
    0x87 => FLOAT_TO_INT, "float-to-int", Format12x;
    0x88 => FLOAT_TO_LONG, "float-to-long", Format12x;
    0x89 => FLOAT_TO_DOUBLE, "float-to-double", Format12x;
    0x8a => DOUBLE_TO_INT, "double-to-int", Format12x;
    0x8b => DOUBLE_TO_LONG, "double-to-long", Format12x;
    0x8c => DOUBLE_TO_FLOAT, "double-to-float", Format12x;
    0x8d => INT_TO_BYTE, "int-to-byte", Format12x;
    0x8e => INT_TO_CHAR, "int-to-char", Format12x;
    0x8f => INT_TO_SHORT, "int-to-short", Format12x;
    0x90 => ADD_INT, "add-int", Format23x;
    0x91 => SUB_INT, "sub-int", Format23x;
    0x92 => MUL_INT, "mul-int", Format23x;
    0x93 => DIV_INT, "div-int", Format23x;
    0x94 => REM_INT, "rem-int", Format23x;
    0x95 => AND_INT, "and-int", Format23x;
    0x96 => OR_INT, "or-int", Format23x;
    0x97 => XOR_INT, "xor-int", Format23x;
    0x98 => SHL_INT, "shl-int", Format23x;
    0x99 => SHR_INT, "shr-int", Format23x;
    0x9a => USHR_INT, "ushr-int", Format23x;
    0x9b => ADD_LONG, "add-long", Format23x;
    0x9c => SUB_LONG, "sub-long", Format23x;
    0x9d => MUL_LONG, "mul-long", Format23x;
    0x9e => DIV_LONG, "div-long", Format23x;
    0x9f => REM_LONG, "rem-long", Format23x;
    0xa0 => AND_LONG, "and-long", Format23x;
    0xa1 => OR_LONG, "or-long", Format23x;
    0xa2 => XOR_LONG, "xor-long", Format23x;
    0xa3 => SHL_LONG, "shl-long", Format23x;
    0xa4 => SHR_LONG, "shr-long", Format23x;
    0xa5 => USHR_LONG, "ushr-long", Format23x;
    0xa6 => ADD_FLOAT, "add-float", Format23x;
    0xa7 => SUB_FLOAT, "sub-float", Format23x;
    0xa8 => MUL_FLOAT, "mul-float", Format23x;
    0xa9 => DIV_FLOAT, "div-float", Format23x;
    0xaa => REM_FLOAT, "rem-float", Format23x;
    0xab => ADD_DOUBLE, "add-double", Format23x;
    0xac => SUB_DOUBLE, "sub-double", Format23x;
    0xad => MUL_DOUBLE, "mul-double", Format23x;
    0xae => DIV_DOUBLE, "div-double", Format23x;
    0xaf => REM_DOUBLE, "rem-double", Format23x;
    0xb0 => ADD_INT_2ADDR, "add-int/2addr", Format12x;
    0xb1 => SUB_INT_2ADDR, "sub-int/2addr", Format12x;
    0xb2 => MUL_INT_2ADDR, "mul-int/2addr", Format12x;
    0xb3 => DIV_INT_2ADDR, "div-int/2addr", Format12x;
    0xb4 => REM_INT_2ADDR, "rem-int/2addr", Format12x;
    0xb5 => AND_INT_2ADDR, "and-int/2addr", Format12x;
    0xb6 => OR_INT_2ADDR, "or-int/2addr", Format12x;
    0xb7 => XOR_INT_2ADDR, "xor-int/2addr", Format12x;
    0xb8 => SHL_INT_2ADDR, "shl-int/2addr", Format12x;
    0xb9 => SHR_INT_2ADDR, "shr-int/2addr", Format12x;
    0xba => USHR_INT_2ADDR, "ushr-int/2addr", Format12x;
    0xbb => ADD_LONG_2ADDR, "add-long/2addr", Format12x;
    0xbc => SUB_LONG_2ADDR, "sub-long/2addr", Format12x;
    0xbd => MUL_LONG_2ADDR, "mul-long/2addr", Format12x;
    0xbe => DIV_LONG_2ADDR, "div-long/2addr", Format12x;
    0xbf => REM_LONG_2ADDR, "rem-long/2addr", Format12x;
    0xc0 => AND_LONG_2ADDR, "and-long/2addr", Format12x;
    0xc1 => OR_LONG_2ADDR, "or-long/2addr", Format12x;
    0xc2 => XOR_LONG_2ADDR, "xor-long/2addr", Format12x;
    0xc3 => SHL_LONG_2ADDR, "shl-long/2addr", Format12x;
    0xc4 => SHR_LONG_2ADDR, "shr-long/2addr", Format12x;
    0xc5 => USHR_LONG_2ADDR, "ushr-long/2addr", Format12x;
    0xc6 => ADD_FLOAT_2ADDR, "add-float/2addr", Format12x;
    0xc7 => SUB_FLOAT_2ADDR, "sub-float/2addr", Format12x;
    0xc8 => MUL_FLOAT_2ADDR, "mul-float/2addr", Format12x;
    0xc9 => DIV_FLOAT_2ADDR, "div-float/2addr", Format12x;
    0xca => REM_FLOAT_2ADDR, "rem-float/2addr", Format12x;
    0xcb => ADD_DOUBLE_2ADDR, "add-double/2addr", Format12x;
    0xcc => SUB_DOUBLE_2ADDR, "sub-double/2addr", Format12x;
    0xcd => MUL_DOUBLE_2ADDR, "mul-double/2addr", Format12x;
    0xce => DIV_DOUBLE_2ADDR, "div-double/2addr", Format12x;
    0xcf => REM_DOUBLE_2ADDR, "rem-double/2addr", Format12x;
    0xd0 => ADD_INT_LIT16, "add-int/lit16", Format22s;
    0xd1 => RSUB_INT, "rsub-int", Format22s;
    0xd2 => MUL_INT_LIT16, "mul-int/lit16", Format22s;
    0xd3 => DIV_INT_LIT16, "div-int/lit16", Format22s;
    0xd4 => REM_INT_LIT16, "rem-int/lit16", Format22s;
    0xd5 => AND_INT_LIT16, "and-int/lit16", Format22s;
    0xd6 => OR_INT_LIT16, "or-int/lit16", Format22s;
    0xd7 => XOR_INT_LIT16, "xor-int/lit16", Format22s;
    0xd8 => ADD_INT_LIT8, "add-int/lit8", Format22b;
    0xd9 => RSUB_INT_LIT8, "rsub-int/lit8", Format22b;
    0xda => MUL_INT_LIT8, "mul-int/lit8", Format22b;
    0xdb => DIV_INT_LIT8, "div-int/lit8", Format22b;
    0xdc => REM_INT_LIT8, "rem-int/lit8", Format22b;
    0xdd => AND_INT_LIT8, "and-int/lit8", Format22b;
    0xde => OR_INT_LIT8, "or-int/lit8", Format22b;
    0xdf => XOR_INT_LIT8, "xor-int/lit8", Format22b;
    0xe0 => SHL_INT_LIT8, "shl-int/lit8", Format22b;
    0xe1 => SHR_INT_LIT8, "shr-int/lit8", Format22b;
    0xe2 => USHR_INT_LIT8, "ushr-int/lit8", Format22b;
    0xfa => INVOKE_POLYMORPHIC, "invoke-polymorphic", Format45cc;
    0xfb => INVOKE_POLYMORPHIC_RANGE, "invoke-polymorphic/range", Format4rcc;
    0xfc => INVOKE_CUSTOM, "invoke-custom", Format35c;
    0xfd => INVOKE_CUSTOM_RANGE, "invoke-custom/range", Format3rc;
    0xfe => CONST_METHOD_HANDLE, "const-method-handle", Format21c;
    0xff => CONST_METHOD_TYPE, "const-method-type", Format21c;
}

pub fn disassemble_method(
    code_item: &CodeItem,
    string_ids: &[u32],
    string_map: &HashMap<u32, String>,
    type_map: &HashMap<u32, String>,
) -> (Vec<String>, u64) {
    let mut disassembled_instructions = Vec::new();
    let insns = &code_item.insns;
    let mut pc: usize = 0;
    let mut instruction_count: u64 = 0;

    // All pc increments of 1 are of 16-bit(2 bytes) units not 8-bits(1 byte)
    while pc < insns.len() {
        instruction_count += 1;
        let address = pc * 2;
        let instruction_unit = insns[pc];
        let opcode = Opcode::from_byte(instruction_unit as u8) // Low byte is the primary opcode
            .expect("Unknown opcode found");

        let name = opcode.name();
        let format = opcode.format();

        let (disassembly, size_units) = match format {
            InstructionFormat::Format00x => (name.to_string(), 1),
            InstructionFormat::Format10x => (name.to_string(), 1),
            InstructionFormat::Format12x => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_b = (instruction_unit >> 12) & 0x0F;
                (format!("{} v{}, v{}", name, v_a, v_b), 1)
            }
            InstructionFormat::Format11n => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                let imm_b = (instruction_unit >> 12) & 0x0F;
                (format!("{} v{}, #+{}", name, v_a, imm_b), 1)
            }
            InstructionFormat::Format11x => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                (format!("{} v{}", name, v_a), 1)
            }
            InstructionFormat::Format10t => {
                //op +AA
                let offset = (instruction_unit >> 8) & 0xFF;
                let target_address = address + (offset as usize);
                let target_address_str = if target_address < insns.len() * 2 {
                    format!("0x{:04x}", target_address)
                } else {
                    "invalid".to_string()
                };
                (format!("{} {}", name, target_address_str), 1)
            }
            InstructionFormat::Format20t => {
                // op +AAAA
                let literal = insns[pc + 1];
                (format!("{} {}", name, literal), 2)
            }
            InstructionFormat::Format20bc => {
                // op vAA, kind@BBBB
                let v_aa = (instruction_unit >> 8) & 0x0F;
                let k_bbbb = insns[pc + 1];
                (format!("{} v{}, kind_{}", name, v_aa, k_bbbb), 2)
            }
            InstructionFormat::Format22x => {
                // op vAA, vBBBB
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_bbbb = insns[pc + 1];
                (format!("{} v{}, v{}", name, v_a, v_bbbb), 2)
            }
            InstructionFormat::Format21t => {
                // op vAA, +BBBB
                let v_aa = (instruction_unit >> 8) & 0x0F;
                let imm = insns[pc + 1];
                (format!("{} v{}, +{}", name, v_aa, imm), 2)
            }
            InstructionFormat::Format21s => {
                // op vAA, #+BBBB
                let v_aa = (instruction_unit >> 8) & 0x0F;
                let imm = insns[pc + 1];
                (format!("{} v{}, #+{}", name, v_aa, imm), 2)
            }
            InstructionFormat::Format21h => {
                // op vAA, #+BBBB0000
                // op vAA, #+BBBB000000000000
                let v_aa = (instruction_unit >> 8) & 0x0F;
                let imm = insns[pc + 1];
                (format!("{} v{}, #+{}", name, v_aa, imm), 2)
            }
            InstructionFormat::Format21c => {
                let v_aa = (instruction_unit >> 8) & 0x0F;
                let bbbb = insns[pc + 1];

                (
                    format!("{} v{}, <type,field,met,proto,string>@{}", name, v_aa, bbbb),
                    2,
                )
            }
            InstructionFormat::Format23x => {
                // byte 1 AA|op
                // byte 2 CC|BB
                let v_aa = (instruction_unit >> 8) & 0x0F;
                let v_bb = insns[pc + 1] >> 8;
                let v_cc = insns[pc + 1] & 0xFF;
                (format!("{} v{}, v{}, v{}", name, v_aa, v_bb, v_cc), 2)
            }
            InstructionFormat::Format22b => {
                // op vAA, vBB, #+CC
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_bb = insns[pc + 1] >> 8;
                let v_cc = insns[pc + 1] & 0xFF;
                (format!("{} v{}, v{}, #+{}", name, v_a, v_bb, v_cc), 2)
            }
            InstructionFormat::Format22t => {
                // op vA, vB, #+CCCC
                // B|A|op CCCC
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_b = (instruction_unit >> 12) & 0x0F;
                let offset = insns[pc + 1];
                let target_address = address + (offset as usize);
                let target_address_str = if target_address < insns.len() * 2 {
                    format!("0x{:04x}", target_address)
                } else {
                    "invalid".to_string()
                };
                (
                    format!("{} v{}, v{}, {}", name, v_a, v_b, target_address_str),
                    2,
                )
            }
            InstructionFormat::Format22s => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_b = (instruction_unit >> 12) & 0x0F;
                let imm_cccc = insns[pc + 1];
                (format!("{} v{}, v{}, #+{}", name, v_a, v_b, imm_cccc), 2)
            }
            InstructionFormat::Format22c => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_b = (instruction_unit >> 12) & 0x0F;
                let cccc = insns[pc + 1];
                (
                    format!("{} v{}, v{}, <type,field>@{}", name, v_a, v_b, cccc),
                    2,
                )
            }
            InstructionFormat::Format22cs => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_b = (instruction_unit >> 12) & 0x0F;
                let cccc = insns[pc + 1];
                (format!("{} v{}, v{}, fieldoff_{}", name, v_a, v_b, cccc), 2)
            }
            InstructionFormat::Format30t => {
                // `ØØ|op AAAA_{lo} AAAA_{hi}`
                let literal_lo = insns[pc + 1];
                let literal_hi = insns[pc + 2];
                let literal = ((literal_hi as u32) << 16) | (literal_lo as u32);
                (format!("{} +{}", name, literal), 3)
            }
            InstructionFormat::Format32x => {
                let v_aaaa = insns[pc + 1];
                let v_bbbb = insns[pc + 2];
                (format!("{} v{}, v{}", name, v_aaaa, v_bbbb), 3)
            }
            InstructionFormat::Format31i => {
                let v_aa = (instruction_unit >> 8) & 0x0F;
                let bb_low = insns[pc + 1];
                let bb_high = insns[pc + 2];
                let bb = ((bb_high as u32) << 16) | (bb_low as u32);
                (format!("{} v{}, #+{}", name, v_aa, bb), 3)
            }
            InstructionFormat::Format31t => {
                let v_aa = (instruction_unit >> 8) & 0x0F;
                let bb_low = insns[pc + 1];
                let bb_high = insns[pc + 2];
                let bb = ((bb_high as u32) << 16) | (bb_low as u32);
                let target_address = address + (bb as usize);
                let target_address_str = if target_address < insns.len() * 2 {
                    format!("0x{:04x}", target_address)
                } else {
                    "invalid".to_string()
                };

                (format!("{} v{}, +{}", name, v_aa, target_address_str), 3)
            }
            InstructionFormat::Format31c => {
                let v_aa = (instruction_unit >> 8) & 0x0F;
                let bbbb_low = insns[pc + 1];
                let bbbb_high = insns[pc + 2];
                let bbbb = ((bbbb_high as u32) << 16) | (bbbb_low as u32);
                let string_val = string_ids.get(bbbb as usize).cloned().unwrap_or(0xFFFFFFFF);
                let string_repr = string_map
                    .get(&string_val)
                    .cloned()
                    .unwrap_or_else(|| "<invalid_string>".to_string());

                (
                    format!("{} v{}, \"{}\"string@{}", name, v_aa, string_repr, bbbb),
                    3,
                )
            }
            InstructionFormat::Format35c => {
                // A|G|op BBBB F|E|D|C
                // [A=5] op {vC, vD, vE, vF, vG}, meth@BBBB
                // [A=5] op {vC, vD, vE, vF, vG}, site@BBBB
                // [A=5] op {vC, vD, vE, vF, vG}, type@BBBB
                // [A=4] op {vC, vD, vE, vF}, kind@BBBB
                // [A=3] op {vC, vD, vE}, kind@BBBB
                // [A=2] op {vC, vD}, kind@BBBB
                // [A=1] op {vC}, kind@BBBB
                // [A=0] op {}, kind@BBBB
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_g = (instruction_unit >> 12) & 0x0F;
                let bbbb = insns[pc + 1];
                let v_c = (insns[pc + 2] >> 0) & 0x0F;
                let v_d = (insns[pc + 2] >> 4) & 0x0F;
                let v_e = (insns[pc + 2] >> 8) & 0x0F;
                let v_f = (insns[pc + 2] >> 12) & 0x0F;

                match v_a {
                    5 => (
                        format!(
                            "{} {{v{}, v{}, v{}, v{}, v{}}}, <meth,site,type>@{}",
                            name, v_c, v_d, v_e, v_f, v_g, bbbb
                        ),
                        3,
                    ),
                    4 => (
                        format!(
                            "{} {{v{}, v{}, v{}, v{}}}, kind_{}",
                            name, v_c, v_d, v_e, v_f, bbbb
                        ),
                        3,
                    ),
                    3 => (
                        format!("{} {{v{}, v{}, v{}}}, kind_{}", name, v_c, v_d, v_e, bbbb),
                        3,
                    ),
                    2 => (format!("{} {{v{}, v{}}}, kind_{}", name, v_c, v_d, bbbb), 3),
                    1 => (format!("{} {{v{}}}, kind_{}", name, v_c, bbbb), 3),
                    0 => (format!("{} {{}}, kind_{}", name, bbbb), 3),
                    _ => (
                        format!("{} (Error: invalid register count {})", name, v_a),
                        3,
                    ),
                }
            }
            InstructionFormat::Format35ms => {
                // [A=5] op {vC, vD, vE, vF, vG}, vtaboff@BBBB
                // [A=4] op {vC, vD, vE, vF}, vtaboff@BBBB
                // [A=3] op {vC, vD, vE}, vtaboff@BBBB
                // [A=2] op {vC, vD}, vtaboff@BBBB
                // [A=1] op {vC}, vtaboff@BBBB
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_g = (instruction_unit >> 12) & 0x0F;
                let bbbb = insns[pc + 1];
                let v_c = (insns[pc + 2] >> 0) & 0x0F;
                let v_d = (insns[pc + 2] >> 4) & 0x0F;
                let v_e = (insns[pc + 2] >> 8) & 0x0F;
                let v_f = (insns[pc + 2] >> 12) & 0x0F;

                match v_a {
                    5 => (
                        format!(
                            "{} {{v{}, v{}, v{}, v{}, v{}}}, vtaboff_{}",
                            name, v_c, v_d, v_e, v_f, v_g, bbbb
                        ),
                        3,
                    ),
                    4 => (
                        format!(
                            "{} {{v{}, v{}, v{}, v{}}}, vtaboff_{}",
                            name, v_c, v_d, v_e, v_f, bbbb
                        ),
                        3,
                    ),
                    3 => (
                        format!(
                            "{} {{v{}, v{}, v{}}}, vtaboff_{}",
                            name, v_c, v_d, v_e, bbbb
                        ),
                        3,
                    ),
                    2 => (
                        format!("{} {{v{}, v{}}}, vtaboff_{}", name, v_c, v_d, bbbb),
                        3,
                    ),
                    1 => (format!("{} {{v{}}}, vtaboff_{}", name, v_c, bbbb), 3),
                    _ => (
                        format!("{} (Error: invalid register count {})", name, v_a),
                        3,
                    ),
                }
            }
            InstructionFormat::Format35mi => {
                // [A=5] op {vC, vD, vE, vF, vG}, inline@BBBB
                // [A=4] op {vC, vD, vE, vF}, inline@BBBB
                // [A=3] op {vC, vD, vE}, inline@BBBB
                // [A=2] op {vC, vD}, inline@BBBB
                // [A=1] op {vC}, inline@BBBB
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_g = (instruction_unit >> 12) & 0x0F;
                let bbbb = insns[pc + 1];
                let v_c = (insns[pc + 2] >> 0) & 0x0F;
                let v_d = (insns[pc + 2] >> 4) & 0x0F;
                let v_e = (insns[pc + 2] >> 8) & 0x0F;
                let v_f = (insns[pc + 2] >> 12) & 0x0F;

                match v_a {
                    5 => (
                        format!(
                            "{} {{v{}, v{}, v{}, v{}, v{}}}, inline_{}",
                            name, v_c, v_d, v_e, v_f, v_g, bbbb
                        ),
                        3,
                    ),
                    4 => (
                        format!(
                            "{} {{v{}, v{}, v{}, v{}}}, inline_{}",
                            name, v_c, v_d, v_e, v_f, bbbb
                        ),
                        3,
                    ),
                    3 => (
                        format!("{} {{v{}, v{}, v{}}}, inline_{}", name, v_c, v_d, v_e, bbbb),
                        3,
                    ),
                    2 => (
                        format!("{} {{v{}, v{}}}, inline_{}", name, v_c, v_d, bbbb),
                        3,
                    ),
                    1 => (format!("{} {{v{}}}, inline_{}", name, v_c, bbbb), 3),
                    _ => (
                        format!("{} (Error: invalid register count {})", name, v_a),
                        3,
                    ),
                }
            }
            // TODO(sfx): check for off by ones.
            InstructionFormat::Format3rc => {
                // AA|op BBBB CCCC....NNNN
                // Here v_a determines the number of arguments passed
                // for this instruction.
                let v_a = (instruction_unit >> 8) & 0x0F;
                let bbbb = insns[pc + 1];
                let cccc = insns[pc + 2];
                // each register is as usual identified by a
                // full 16bit value, so we need to read v_a
                // number of u16 values from insns[pc + 2] onwards
                // the register ids start from cccc to cccc + v_a -1
                let mut registers = Vec::with_capacity(v_a as usize);
                for i in 1..v_a {
                    // let _reg_id = insns[pc + 1 + (i as usize)];
                    registers.push(format!("v{}", cccc + i));
                }

                let registers_str = registers.join(", ");
                (
                    format!("{} {{{}}}, <meth,site,type>@{}", name, registers_str, bbbb),
                    3 + (v_a as usize),
                )
            }
            InstructionFormat::Format3rms => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                let bbbb = insns[pc + 1];
                let cccc = insns[pc + 2];
                // each register is as usual identified by a
                // full 16bit value, so we need to read v_a
                // number of u16 values from insns[pc + 2] onwards
                // the register ids start from cccc to cccc + v_a -1
                let mut registers = Vec::with_capacity(v_a as usize);
                for i in 1..v_a {
                    let reg_id = insns[pc + 2 + (i as usize)];
                    registers.push(format!("v{}", cccc + i));
                }

                let registers_str = registers.join(", ");
                (
                    format!("{} {{{}}}, vtaboff@{}", name, registers_str, bbbb),
                    3 + (v_a as usize - 1),
                )
            }
            InstructionFormat::Format3rmi => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                let bbbb = insns[pc + 1];
                let cccc = insns[pc + 2];
                let mut registers = Vec::with_capacity(v_a as usize);
                for i in 1..v_a {
                    let reg_id = insns[pc + 2 + (i as usize)];
                    registers.push(format!("v{}", cccc + i));
                }

                let registers_str = registers.join(", ");
                (
                    format!("{} {{{}}}, inline@{}", name, registers_str, bbbb),
                    3 + (v_a as usize - 1),
                )
            }
            InstructionFormat::Format45cc => (format!("{}", name,), 4),
            InstructionFormat::Format4rcc => (format!("{}", name,), 4),
            InstructionFormat::Format51l => {
                // AA|op BBBBlo BBBB BBBB BBBBhi 5 bytes
                let v_aa = (instruction_unit >> 8) & 0x0F;
                let bbbb_lo1 = insns[pc + 1];
                let bbbb_lo2 = insns[pc + 2];
                let bbbb_hi1 = insns[pc + 3];
                let bbbb_hi2 = insns[pc + 4];
                let bbbb = ((bbbb_hi2 as u64) << 48)
                    | ((bbbb_hi1 as u64) << 32)
                    | ((bbbb_lo2 as u64) << 16)
                    | (bbbb_lo1 as u64);
                (format!("{} v{}, #+{}", name, v_aa, bbbb), 5)
            }
        };

        if pc + size_units > insns.len() {
            let formatted_line = format!(
                "0x{:04x}: {} (Error: instruction truncated)",
                address, disassembly
            );
            disassembled_instructions.push(formatted_line);
            break; // Stop processing if we hit truncated data
        }

        let formatted_line = format!("0x{:04x}: {}", address, disassembly);
        disassembled_instructions.push(formatted_line);

        pc += size_units;
    }

    (disassembled_instructions, instruction_count)
}
