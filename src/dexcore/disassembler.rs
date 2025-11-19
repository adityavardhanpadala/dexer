use crate::Cli;
use crate::dexcore::Dex;
use crate::dexcore::types::{CodeItem, class_def_item};
use crate::dexcore::utils::{get_method_signature, parse_class_data_item, parse_code_item};
use log::{debug, warn};
use memmap::Mmap;
use std::num;
use std::{
    collections::HashMap,
    fmt::{Display, format},
};
use thiserror::Error;

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

        const OPCODE_TABLE: [Option<Opcode>; 256] = {
            let mut table = [None; 256];
            $(
                table[$value] = Some(Opcode::$name);
            )*
            table
        };

        impl Opcode {
            #[inline]
            pub fn from_byte(byte: u8) -> Option<Opcode> {
               let res = OPCODE_TABLE[byte as usize];
               #[cfg(debug_assertions)]
               {
                   if res.is_none() {
                       warn!("Unknown opcode byte: 0x{:02x}", byte);
                   }
               }
                res
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
    0x3d => IF_LEZ, "if-lez", Format21t;

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
    0x73 => RETURN_VOID_NO_BARRIER, "return-void-no-barrier", Format10x;
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
    // Some odex shit
    0xe3 => IGET_QUICK, "iget-quick", Format22c;
    0xe4 => IGET_WIDE_QUICK, "iget-wide-quick", Format22c;
    0xe5 => IGET_OBJECT_QUICK, "iget-object-quick", Format22c;
    0xe6 => IPUT_QUICK, "iput-quick", Format22c;
    0xe7 => IPUT_WIDE_QUICK, "iput-wide-quick", Format22c;
    0xe8 => IPUT_OBJECT_QUICK, "iput-object-quick", Format22c;
    0xe9 => INVOKE_VIRTUAL_QUICK, "invoke-virtual-quick", Format35c;
    0xea => INVOKE_VIRTUAL_QUICK_RANGE, "invoke-virtual-quick/range", Format3rc;
    0xeb => INVOKE_IPUT_BOOLEAN_QUICK, "invoke-iput-boolean-quick", Format35c;
    0xec => INVOKE_IPUT_BYTE_QUICK, "invoke-iput-byte-quick", Format22c;
    0xed => INVOKE_IPUT_CHAR_QUICK, "invoke-iput-char-quick", Format22cs;
    0xee => INVOKE_IPUT_SHORT_QUICK, "invoke-iput-short-quick", Format22c;
    0xef => INVOKE_IGET_BOOLEAN_QUICK, "invoke-iget-boolean-quick", Format22c;
    0xf0 => INVOKE_IGET_BYTE_QUICK, "invoke-iget-byte-quick", Format22c;
    0xf1 => INVOKE_IGET_CHAR_QUICK, "invoke-iget-char-quick", Format22c;
    0xf2 => INVOKE_IGET_SHORT_QUICK, "invoke-iget-short-quick", Format22c;

    0xfa => INVOKE_POLYMORPHIC, "invoke-polymorphic", Format45cc;
    0xfb => INVOKE_POLYMORPHIC_RANGE, "invoke-polymorphic/range", Format4rcc;
    0xfc => INVOKE_CUSTOM, "invoke-custom", Format35c;
    0xfd => INVOKE_CUSTOM_RANGE, "invoke-custom/range", Format3rc;
    0xfe => CONST_METHOD_HANDLE, "const-method-handle", Format21c;
    0xff => CONST_METHOD_TYPE, "const-method-type", Format21c;
}

/// Returns the size in 16-bit units for a given instruction format
#[inline]
fn format_size(format: InstructionFormat) -> usize {
    match format {
        InstructionFormat::Format10x
        | InstructionFormat::Format12x
        | InstructionFormat::Format11n
        | InstructionFormat::Format11x
        | InstructionFormat::Format10t => 1,
        InstructionFormat::Format20t
        | InstructionFormat::Format20bc
        | InstructionFormat::Format22x
        | InstructionFormat::Format21t
        | InstructionFormat::Format21s
        | InstructionFormat::Format21h
        | InstructionFormat::Format21c
        | InstructionFormat::Format23x
        | InstructionFormat::Format22b
        | InstructionFormat::Format22t
        | InstructionFormat::Format22s
        | InstructionFormat::Format22c
        | InstructionFormat::Format22cs => 2,
        InstructionFormat::Format30t
        | InstructionFormat::Format32x
        | InstructionFormat::Format31i
        | InstructionFormat::Format31t
        | InstructionFormat::Format31c
        | InstructionFormat::Format35c
        | InstructionFormat::Format35ms
        | InstructionFormat::Format35mi
        | InstructionFormat::Format3rc
        | InstructionFormat::Format3rms
        | InstructionFormat::Format3rmi => 3,
        InstructionFormat::Format45cc | InstructionFormat::Format4rcc => 4,
        InstructionFormat::Format51l => 5,
        _ => 1,
    }
}

#[derive(Debug, Clone)]
pub struct Instruction {
    opcode: Opcode,
    format: InstructionFormat,
    address: u32,
    size: u8, // in 16bit units
    operands: [Operand; 5],
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {:?}", self.opcode.name(), self.operands)
    }
}

impl Instruction {
    #[inline]
    const fn new(opcode: Opcode, format: InstructionFormat, address: u32, size: u8) -> Self {
        Self {
            opcode,
            format,
            address,
            size,
            operands: [Operand::None; 5],
        }
    }

    #[inline]
    fn with_operands(mut self, operands: &[Operand]) -> Self {
        self.operands[..operands.len()].copy_from_slice(operands);
        self
    }

    pub fn is_branch(&self) -> bool {
        matches!(
            self.format,
            InstructionFormat::Format10t
                | InstructionFormat::Format20t
                | InstructionFormat::Format21t
                | InstructionFormat::Format22t
                | InstructionFormat::Format30t
                | InstructionFormat::Format31t
        )
    }

    pub fn is_invoke(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::INVOKE_DIRECT
                | Opcode::INVOKE_DIRECT_RANGE
                | Opcode::INVOKE_STATIC
                | Opcode::INVOKE_STATIC_RANGE
                | Opcode::INVOKE_SUPER
                | Opcode::INVOKE_SUPER_RANGE
                | Opcode::INVOKE_VIRTUAL
                | Opcode::INVOKE_VIRTUAL_RANGE
                | Opcode::INVOKE_INTERFACE
                | Opcode::INVOKE_INTERFACE_RANGE
        )
    }
}

#[derive(Debug, Clone, Copy)]
enum Operand {
    None,
    Register(u16),
    RegisterRange { start: u16, end: u16 },
    I32(i32),
    I64(i64),
    Literal(i64),
    StringId(u32),
    TypeId(u16),
    MethodId(u16),
    Vtaboff(u32),
    Offset(i32),
    FieldId(u16),
    ProtoId(u32),
    MethodHandle(u32),
    FieldOffset(u16),
}

impl std::fmt::Display for Operand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operand::None => write!(f, "none"),
            Operand::Register(reg) => write!(f, "v{}", reg),
            Operand::RegisterRange { start, end } => write!(f, "v{}-v{}", start, end),
            Operand::Literal(lit) => write!(f, "{}", lit),
            Operand::I32(val) => write!(f, "{}", val),
            Operand::I64(val) => write!(f, "{}", val),
            Operand::StringId(id) => write!(f, "string_id({})", id),
            Operand::TypeId(id) => write!(f, "type_id({})", id),
            Operand::MethodId(id) => write!(f, "method_id({})", id),
            Operand::Vtaboff(id) => write!(f, "vtaboff({})", id),
            Operand::Offset(off) => write!(f, "offset({})", off),
            Operand::FieldId(id) => write!(f, "field_id({})", id),
            Operand::ProtoId(id) => write!(f, "proto_id({})", id),
            Operand::MethodHandle(id) => write!(f, "method_handle({})", id),
            Operand::FieldOffset(off) => write!(f, "field_offset({})", off),
        }
    }
}

#[derive(Error, Debug)]
pub enum DisassemblyError {
    #[error("Invalid opcode")]
    InvalidOpcode(u8),
    #[error("Invalid format")]
    InvalidFormat,
    #[error("Invalid operand")]
    InvalidOperand,
    #[error("Out of bounds?")]
    OutOfBounds,
    #[error("Invalid operand")]
    FromInvalidOperand,
    #[error("Proto ID index {proto_idx} out of bounds for method index {method_idx}")]
    ProtoIndexOutOfBounds { proto_idx: u16, method_idx: usize },
    #[error("Failed to get method signature for method index {method_idx}")]
    MethodSignatureError { method_idx: usize, error: String },
}

pub fn disassemble_method(
    code_item: &CodeItem,
    string_ids: &[u32],
    string_map: &HashMap<u32, String>,
    _type_map: &[String],
    class_name: Option<&str>,
    method_name: Option<&str>,
) -> Result<Vec<Instruction>, DisassemblyError> {
    let mut instructions: Vec<Instruction> = Vec::with_capacity(code_item.insns_size as usize);
    let insns = &code_item.insns;
    let mut pc: usize = 0;
    let mut instruction_count: u64 = 0;

    // First pass: collect all payload locations
    // Use a fixed-size boolean array for better cache performance
    let mut payload_pcs = vec![false; insns.len()];

    let mut scan_pc = 0;
    let mut payload_count = 0;
    while scan_pc < insns.len() {
        let opcode_byte = insns[scan_pc] as u8;
        if let Some(opcode) = Opcode::from_byte(opcode_byte) {
            match opcode {
                Opcode::PACKED_SWITCH | Opcode::SPARSE_SWITCH | Opcode::FILL_ARRAY_DATA => {
                    // These instructions have Format31t: 3 units with a 32-bit offset
                    if scan_pc + 2 < insns.len() {
                        let offset_low = insns[scan_pc + 1] as u32;
                        let offset_high = insns[scan_pc + 2] as u32;
                        let offset_raw = ((offset_high << 16) | offset_low) as i32;
                        let payload_pc = ((scan_pc as i32) + offset_raw) as usize;

                        if payload_pc < insns.len() {
                            // Calculate payload size
                            let payload_size = match opcode {
                                Opcode::PACKED_SWITCH => {
                                    if payload_pc + 1 < insns.len() && insns[payload_pc] == 0x0100 {
                                        let size = insns[payload_pc + 1] as usize;
                                        4 + size * 2
                                    } else {
                                        0
                                    }
                                }
                                Opcode::SPARSE_SWITCH => {
                                    if payload_pc + 1 < insns.len() && insns[payload_pc] == 0x0200 {
                                        let size = insns[payload_pc + 1] as usize;
                                        2 + size * 4
                                    } else {
                                        0
                                    }
                                }
                                Opcode::FILL_ARRAY_DATA => {
                                    if payload_pc + 3 < insns.len() && insns[payload_pc] == 0x0300 {
                                        let element_width = insns[payload_pc + 1] as usize;
                                        let size_low = insns[payload_pc + 2] as u32;
                                        let size_high = insns[payload_pc + 3] as u32;
                                        let size = ((size_high << 16) | size_low) as usize;
                                        let data_size_bytes = size * element_width;
                                        let data_size_units = (data_size_bytes + 1) / 2;
                                        4 + data_size_units
                                    } else {
                                        0
                                    }
                                }
                                _ => 0,
                            };

                            // Mark all PCs in the payload range
                            for i in 0..payload_size {
                                if payload_pc + i < payload_pcs.len() {
                                    payload_pcs[payload_pc + i] = true;
                                }
                            }
                            payload_count += 1;
                            if payload_count <= 3 {
                                debug!(
                                    "Found payload for {:?} at scan_pc={}, payload at PC {}, size {}",
                                    opcode.name(),
                                    scan_pc,
                                    payload_pc,
                                    payload_size
                                );
                            }
                        }
                    }
                    scan_pc += 3; // Format31t is 3 units
                }
                _ => {
                    // Get instruction size from format
                    let size = format_size(opcode.format());
                    scan_pc += size;
                }
            }
        } else {
            // check for payload data?
            let ident = insns[scan_pc];
            if ident == 0x0100 && scan_pc + 1 < insns.len() {
                // Packed-switch payload
                let size = insns[scan_pc + 1] as usize;
                let payload_size = 4 + size * 2;
                if scan_pc + payload_size <= insns.len() {
                    scan_pc += payload_size;
                    continue;
                }
            } else if ident == 0x0200 && scan_pc + 1 < insns.len() {
                // Sparse-switch payload
                let size = insns[scan_pc + 1] as usize;
                let payload_size = 2 + size * 4;
                if scan_pc + payload_size <= insns.len() {
                    scan_pc += payload_size;
                    continue;
                }
            } else if ident == 0x0300 && scan_pc + 3 < insns.len() {
                // Fill-array-data payload
                let element_width = insns[scan_pc + 1] as usize;
                let size_low = insns[scan_pc + 2] as u32;
                let size_high = insns[scan_pc + 3] as u32;
                let size = ((size_high << 16) | size_low) as usize;
                let data_size_bytes = size * element_width;
                let data_size_units = (data_size_bytes + 1) / 2;
                let payload_size = 4 + data_size_units;
                if scan_pc + payload_size <= insns.len() {
                    scan_pc += payload_size;
                    continue;
                }
            }
            scan_pc += 1; // Unknown opcode, move forward
        }
    }

    // All pc increments of 1 are of 16-bit(2 bytes) units not 8-bits(1 byte)
    while pc < insns.len() {
        // Skip if this PC is part of a payload
        if pc < payload_pcs.len() && payload_pcs[pc] {
            pc += 1;
            continue;
        }

        let address = pc * 2;
        let instruction_unit = insns[pc];

        instruction_count += 1;
        let opcode_byte = instruction_unit as u8;
        let opcode = match Opcode::from_byte(opcode_byte) {
            Some(op) => op,
            None => {
                eprintln!("\n==== UNKNOWN OPCODE ERROR ====");
                if let Some(cls) = class_name {
                    eprintln!("Class: {}", cls);
                }
                if let Some(mth) = method_name {
                    eprintln!("Method: {}", mth);
                }
                eprintln!("Address: 0x{:04x} (PC: {} units)", address, pc);
                eprintln!("Unknown opcode: 0x{:02x}", opcode_byte);

                eprintln!("\nSurrounding instruction units (PC ± 20):");
                let start = if pc >= 20 { pc - 20 } else { 0 };
                let end = (pc + 20).min(insns.len());
                for i in start..end {
                    let marker = if i == pc { " <-- HERE" } else { "" };
                    let low_byte = insns[i] as u8;
                    let high_byte = (insns[i] >> 8) as u8;
                    let maybe_opcode = Opcode::from_byte(low_byte);
                    let opcode_str = match maybe_opcode {
                        Some(op) => op.name(),
                        None => "UNKNOWN",
                    };
                    eprintln!(
                        "  PC {:4}: 0x{:04x} (opcode {:02x}={:20}) {}",
                        i, insns[i], low_byte, opcode_str, marker
                    );
                }

                eprintln!("\nRaw bytes around address 0x{:04x}:", address);
                let byte_start = if pc >= 10 { (pc - 10) * 2 } else { 0 };
                let byte_end = ((pc + 10) * 2).min(insns.len() * 2);
                eprint!("  ");
                for i in byte_start..byte_end {
                    if i == address {
                        eprint!("[");
                    }
                    if i % 2 == 0 {
                        eprint!("{:02x}", (insns[i / 2] & 0xFF) as u8);
                    } else {
                        eprint!("{:02x}", (insns[i / 2] >> 8) as u8);
                    }
                    if i == address + 1 {
                        eprint!("]");
                    }
                    if (i + 1 - byte_start) % 16 == 0 {
                        eprintln!();
                        eprint!("  ");
                    } else {
                        eprint!(" ");
                    }
                }
                eprintln!("\n==============================\n");

                return Err(DisassemblyError::InvalidOpcode(opcode_byte));
            }
        };

        let name = opcode.name();
        let format = opcode.format();

        let format_size = format_size(format);

        if pc + format_size > insns.len() {
            break;
        }

        let size_units = match format {
            InstructionFormat::Format00x => {
                instructions.push(Instruction::new(opcode, format, address as u32, 1));
                1
            }
            InstructionFormat::Format10x => {
                instructions.push(Instruction::new(opcode, format, address as u32, 1));
                1
            }
            InstructionFormat::Format12x => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_b = (instruction_unit >> 12) & 0x0F;

                let operand_a = Operand::Register(v_a);
                let operand_b = Operand::Register(v_b);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 1)
                        .with_operands(&[operand_a, operand_b]),
                );
                1
            }
            InstructionFormat::Format11n => {
                // B|A|op - B is signed 4-bit immediate, A is register
                let v_a = (instruction_unit >> 8) & 0x0F;
                // Sign-extend 4-bit value from bit 12
                let imm_b_raw = (instruction_unit >> 12) & 0x0F;
                let imm_b = if (imm_b_raw & 0x08) != 0 {
                    // Negative: sign-extend from bit 3
                    (imm_b_raw | 0xF0) as i8 as i32
                } else {
                    imm_b_raw as i32
                };
                let _sign = if imm_b >= 0 { "+" } else { "" };

                let operand_a = Operand::Register(v_a);
                let operand_b = Operand::I32(imm_b);

                instructions.push(
                    Instruction::new(opcode, format, address as u32, 1)
                        .with_operands(&[operand_a, operand_b]),
                );
                1
            }
            InstructionFormat::Format11x => {
                let v_aa = (instruction_unit >> 8) & 0xFF;
                let operand_a = Operand::Register(v_aa);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 1).with_operands(&[operand_a]),
                );
                1
            }
            InstructionFormat::Format10t => {
                //op +AA (signed 8-bit offset)
                let offset_raw = ((instruction_unit >> 8) & 0xFF) as i8 as i32;
                let target_address = ((address as i32) + offset_raw * 2) as usize;
                let target_address_str = if target_address < insns.len() * 2 {
                    format!("0x{:04x}", target_address)
                } else {
                    "invalid".into()
                };
                let operand_a = Operand::Offset(offset_raw);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 1).with_operands(&[operand_a]),
                );
                1
            }
            InstructionFormat::Format20t => {
                // op +AAAA (signed 16-bit offset)
                let offset_raw = insns[pc + 1] as i16 as i32;
                let target_address = ((address as i32) + offset_raw * 2) as usize;
                let target_address_str = if target_address < insns.len() * 2 {
                    format!("0x{:04x}", target_address)
                } else {
                    "invalid".into()
                };
                let operand_a = Operand::Offset(offset_raw);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 2).with_operands(&[operand_a]),
                );
                2
            }
            InstructionFormat::Format20bc => {
                // op vAA, kind@BBBB
                // TODO(sfx): Verify the operand types.
                let v_aa = (instruction_unit >> 8) & 0xFF;
                let k_bbbb = insns[pc + 1];
                let operand_a = Operand::Register(v_aa);
                let operand_b = Operand::MethodId(k_bbbb);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 2)
                        .with_operands(&[operand_a, operand_b]),
                );
                2
            }
            InstructionFormat::Format22x => {
                // op vAA, vBBBB
                let v_aa = (instruction_unit >> 8) & 0xFF;
                let v_bbbb = insns[pc + 1];
                let operand_a = Operand::Register(v_aa);
                let operand_b = Operand::Register(v_bbbb);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 2)
                        .with_operands(&[operand_a, operand_b]),
                );
                2
            }
            InstructionFormat::Format21t => {
                // op vAA, +BBBB (signed 16-bit offset)
                let v_aa = (instruction_unit >> 8) & 0xFF;
                let offset_raw = insns[pc + 1] as i16 as i32;
                let target_address = ((address as i32) + offset_raw * 2) as usize;
                let target_address_str = if target_address < insns.len() * 2 {
                    format!("0x{:04x}", target_address)
                } else {
                    "invalid".into()
                };
                let operand_a = Operand::Register(v_aa);
                let operand_b = Operand::Offset(offset_raw);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 2)
                        .with_operands(&[operand_a, operand_b]),
                );
                2
            }
            InstructionFormat::Format21s => {
                // op vAA, #+BBBB
                let v_aa = (instruction_unit >> 8) & 0xFF;
                let imm = insns[pc + 1] as i16 as i32; // Sign-extend 16-bit value
                let operand_a = Operand::Register(v_aa);
                let operand_b = Operand::I32(imm);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 2)
                        .with_operands(&[operand_a, operand_b]),
                );
                2
            }
            InstructionFormat::Format21h => {
                // op vAA, #+BBBB0000 (for const/high16)
                // op vAA, #+BBBB000000000000 (for const-wide/high16)
                let v_aa = (instruction_unit >> 8) & 0xFF;
                let bbbb = insns[pc + 1];
                let operand_a = Operand::Register(v_aa);
                // Check opcode to determine shift amount
                let operand_b = match opcode {
                    Opcode::CONST_HIGH16 => Operand::I32((bbbb as i32) << 16),
                    Opcode::CONST_WIDE_HIGH16 => Operand::I64((bbbb as i64) << 48),
                    _ => Operand::I32(bbbb as i32),
                };
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 2)
                        .with_operands(&[operand_a, operand_b]),
                );
                2
            }
            InstructionFormat::Format21c => {
                let v_aa = (instruction_unit >> 8) & 0xFF;
                let bbbb = insns[pc + 1];

                let operand_a = Operand::Register(v_aa);
                // Determine operand type based on opcode
                let operand_b = match opcode {
                    Opcode::CONST_STRING | Opcode::CONST_STRING_JUMBO => {
                        Operand::StringId(bbbb as u32)
                    }
                    Opcode::CONST_CLASS | Opcode::CHECK_CAST | Opcode::NEW_INSTANCE => {
                        Operand::TypeId(bbbb)
                    }
                    Opcode::CONST_METHOD_HANDLE => Operand::MethodHandle(bbbb as u32),
                    Opcode::CONST_METHOD_TYPE => Operand::ProtoId(bbbb as u32),
                    Opcode::SGET
                    | Opcode::SGET_WIDE
                    | Opcode::SGET_OBJECT
                    | Opcode::SGET_BOOLEAN
                    | Opcode::SGET_BYTE
                    | Opcode::SGET_CHAR
                    | Opcode::SGET_SHORT
                    | Opcode::SPUT
                    | Opcode::SPUT_WIDE
                    | Opcode::SPUT_OBJECT
                    | Opcode::SPUT_BOOLEAN
                    | Opcode::SPUT_BYTE
                    | Opcode::SPUT_CHAR
                    | Opcode::SPUT_SHORT => Operand::FieldId(bbbb),
                    _ => Operand::MethodId(bbbb), // Default fallback
                };
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 2)
                        .with_operands(&[operand_a, operand_b]),
                );
                2
            }
            InstructionFormat::Format23x => {
                // byte 1 AA|op
                // byte 2 CC|BB
                let v_aa = (instruction_unit >> 8) & 0xFF;
                let v_bb = (insns[pc + 1] >> 8) & 0xFF;
                let v_cc = insns[pc + 1] & 0xFF;
                let operand_a = Operand::Register(v_aa);
                let operand_b = Operand::Register(v_bb);
                let operand_c = Operand::Register(v_cc);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 2)
                        .with_operands(&[operand_a, operand_b, operand_c]),
                );
                2
            }
            InstructionFormat::Format22b => {
                // op vAA, vBB, #+CC
                let v_aa = (instruction_unit >> 8) & 0xFF;
                let v_bb = (insns[pc + 1] >> 8) & 0xFF;
                let v_cc = insns[pc + 1] & 0xFF;
                let operand_a = Operand::Register(v_aa);
                let operand_b = Operand::Register(v_bb);
                let operand_c = Operand::I32(v_cc as i8 as i32); // Sign-extend 8-bit value
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 2)
                        .with_operands(&[operand_a, operand_b, operand_c]),
                );
                2
            }
            InstructionFormat::Format22t => {
                // op vA, vB, +CCCC (signed 16-bit offset)
                // B|A|op CCCC
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_b = (instruction_unit >> 12) & 0x0F;
                let offset_raw = insns[pc + 1] as i16 as i32;
                let target_address = ((address as i32) + offset_raw * 2) as usize;
                let target_address_str = if target_address < insns.len() * 2 {
                    format!("0x{:04x}", target_address)
                } else {
                    "invalid".into()
                };
                let operand_a = Operand::Register(v_a);
                let operand_b = Operand::Register(v_b);
                let operand_c = Operand::Offset(offset_raw);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 2)
                        .with_operands(&[operand_a, operand_b, operand_c]),
                );
                2
            }
            InstructionFormat::Format22s => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_b = (instruction_unit >> 12) & 0x0F;
                let imm_cccc = insns[pc + 1] as i16 as i32; // Sign-extend 16-bit value
                let operand_a = Operand::Register(v_a);
                let operand_b = Operand::Register(v_b);
                let operand_c = Operand::I32(imm_cccc);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 2)
                        .with_operands(&[operand_a, operand_b, operand_c]),
                );
                2
            }
            InstructionFormat::Format22c => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_b = (instruction_unit >> 12) & 0x0F;
                let cccc = insns[pc + 1];
                let operand_a = Operand::Register(v_a);
                let operand_b = Operand::Register(v_b);
                // Determine operand type based on opcode
                let operand_c = match opcode {
                    Opcode::INSTANCE_OF | Opcode::NEW_ARRAY => Operand::TypeId(cccc),
                    Opcode::IGET
                    | Opcode::IGET_WIDE
                    | Opcode::IGET_OBJECT
                    | Opcode::IGET_BOOLEAN
                    | Opcode::IGET_BYTE
                    | Opcode::IGET_CHAR
                    | Opcode::IGET_SHORT
                    | Opcode::IPUT
                    | Opcode::IPUT_WIDE
                    | Opcode::IPUT_OBJECT
                    | Opcode::IPUT_BOOLEAN
                    | Opcode::IPUT_BYTE
                    | Opcode::IPUT_CHAR
                    | Opcode::IPUT_SHORT
                    | Opcode::IGET_QUICK
                    | Opcode::IGET_WIDE_QUICK
                    | Opcode::IGET_OBJECT_QUICK
                    | Opcode::IPUT_QUICK
                    | Opcode::IPUT_WIDE_QUICK
                    | Opcode::IPUT_OBJECT_QUICK
                    | Opcode::INVOKE_IPUT_BYTE_QUICK
                    | Opcode::INVOKE_IPUT_SHORT_QUICK
                    | Opcode::INVOKE_IGET_BOOLEAN_QUICK
                    | Opcode::INVOKE_IGET_BYTE_QUICK
                    | Opcode::INVOKE_IGET_CHAR_QUICK
                    | Opcode::INVOKE_IGET_SHORT_QUICK => Operand::FieldId(cccc),
                    _ => Operand::TypeId(cccc), // Default fallback
                };
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 2)
                        .with_operands(&[operand_a, operand_b, operand_c]),
                );
                2
            }
            InstructionFormat::Format22cs => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_b = (instruction_unit >> 12) & 0x0F;
                let cccc = insns[pc + 1];
                let operand_a = Operand::Register(v_a);
                let operand_b = Operand::Register(v_b);
                let operand_c = Operand::FieldOffset(cccc);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 2)
                        .with_operands(&[operand_a, operand_b, operand_c]),
                );
                2
            }
            InstructionFormat::Format30t => {
                // `ØØ|op AAAA_{lo} AAAA_{hi}` (signed 32-bit offset)
                let literal_lo = insns[pc + 1] as u32;
                let literal_hi = insns[pc + 2] as u32;
                let offset_raw = ((literal_hi << 16) | literal_lo) as i32;
                let target_address = ((address as i32) + offset_raw * 2) as usize;
                let target_address_str = if target_address < insns.len() * 2 {
                    format!("0x{:04x}", target_address)
                } else {
                    "invalid".into()
                };
                let operand_a = Operand::Offset(offset_raw);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 3).with_operands(&[operand_a]),
                );
                3
            }
            InstructionFormat::Format32x => {
                let v_aaaa = insns[pc + 1];
                let v_bbbb = insns[pc + 2];
                let operand_a = Operand::Register(v_aaaa);
                let operand_b = Operand::Register(v_bbbb);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 3)
                        .with_operands(&[operand_a, operand_b]),
                );
                3
            }
            InstructionFormat::Format31i => {
                let v_aa = (instruction_unit >> 8) & 0xFF;
                let bb_low = insns[pc + 1];
                let bb_high = insns[pc + 2];
                let bb = ((bb_high as u32) << 16) | (bb_low as u32);
                let operand_a = Operand::Register(v_aa);
                let operand_b = Operand::I32(bb as i32);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 3)
                        .with_operands(&[operand_a, operand_b]),
                );
                3
            }
            InstructionFormat::Format31t => {
                // op vAA, +BBBBBBBB (signed 32-bit offset)
                let v_aa = (instruction_unit >> 8) & 0xFF;
                let bb_low = insns[pc + 1] as u32;
                let bb_high = insns[pc + 2] as u32;
                let offset_raw = ((bb_high << 16) | bb_low) as i32;
                let target_address = ((address as i32) + offset_raw * 2) as usize;
                let target_address_str = if target_address < insns.len() * 2 {
                    format!("0x{:04x}", target_address)
                } else {
                    "invalid".into()
                };
                let operand_a = Operand::Register(v_aa);
                let operand_b = Operand::Offset(offset_raw);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 3)
                        .with_operands(&[operand_a, operand_b]),
                );
                3
            }
            InstructionFormat::Format31c => {
                let v_aa = (instruction_unit >> 8) & 0xFF;
                let bbbb_low = insns[pc + 1];
                let bbbb_high = insns[pc + 2];
                let bbbb = ((bbbb_high as u32) << 16) | (bbbb_low as u32);
                let string_val = string_ids.get(bbbb as usize).cloned().unwrap_or(0xFFFFFFFF);
                let string_repr = string_map
                    .get(&string_val)
                    .cloned()
                    .unwrap_or_else(|| "<invalid_string>".to_string());

                let operand_a = Operand::Register(v_aa);
                let operand_b = Operand::StringId(bbbb);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 3)
                        .with_operands(&[operand_a, operand_b]),
                );
                3
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
                let v_a = (instruction_unit >> 12) & 0x0F;
                let v_g = (instruction_unit >> 8) & 0x0F;
                let bbbb = insns[pc + 1];
                let v_c = (insns[pc + 2] >> 0) & 0x0F;
                let v_d = (insns[pc + 2] >> 4) & 0x0F;
                let v_e = (insns[pc + 2] >> 8) & 0x0F;
                let v_f = (insns[pc + 2] >> 12) & 0x0F;

                let operand_a = Operand::Register(v_a);
                let operand_b = Operand::MethodId(bbbb);
                let operand_c = Operand::Register(v_c);
                let operand_d = Operand::Register(v_d);
                let operand_e = Operand::Register(v_e);
                let operand_f = Operand::Register(v_f);
                let operand_g = Operand::Register(v_g);

                match v_a {
                    5 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3).with_operands(&[
                                operand_c, operand_d, operand_e, operand_f, operand_g,
                            ]),
                        );
                        3
                    }
                    4 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3).with_operands(&[
                                operand_c, operand_d, operand_e, operand_f, operand_b,
                            ]),
                        );
                        3
                    }
                    3 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3)
                                .with_operands(&[operand_c, operand_d, operand_e, operand_b]),
                        );
                        3
                    }
                    2 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3)
                                .with_operands(&[operand_c, operand_d, operand_b]),
                        );
                        3
                    }
                    1 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3)
                                .with_operands(&[operand_c, operand_b]),
                        );
                        3
                    }
                    0 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3)
                                .with_operands(&[operand_b]),
                        );
                        3
                    }
                    _ => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3)
                                .with_operands(&[operand_a]),
                        );
                        3
                    }
                }
            }
            InstructionFormat::Format35ms => {
                // [A=5] op {vC, vD, vE, vF, vG}, vtaboff@BBBB
                // [A=4] op {vC, vD, vE, vF}, vtaboff@BBBB
                // [A=3] op {vC, vD, vE}, vtaboff@BBBB
                // [A=2] op {vC, vD}, vtaboff@BBBB
                // [A=1] op {vC}, vtaboff@BBBB
                let v_a = (instruction_unit >> 12) & 0x0F;
                let v_g = (instruction_unit >> 8) & 0x0F;
                let bbbb = insns[pc + 1];
                let v_c = (insns[pc + 2] >> 0) & 0x0F;
                let v_d = (insns[pc + 2] >> 4) & 0x0F;
                let v_e = (insns[pc + 2] >> 8) & 0x0F;
                let v_f = (insns[pc + 2] >> 12) & 0x0F;

                let operand_a = Operand::Register(v_a);
                // TODO(sfx): Fix the cast
                let operand_b = Operand::Vtaboff(bbbb.into());
                let operand_c = Operand::Register(v_c);
                let operand_d = Operand::Register(v_d);
                let operand_e = Operand::Register(v_e);
                let operand_f = Operand::Register(v_f);
                let operand_g = Operand::Register(v_g);

                match v_a {
                    5 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3).with_operands(&[
                                operand_c, operand_d, operand_e, operand_f, operand_g, operand_b,
                            ]),
                        );
                        3
                    }
                    4 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3).with_operands(&[
                                operand_c, operand_d, operand_e, operand_f, operand_b,
                            ]),
                        );
                        3
                    }
                    3 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3)
                                .with_operands(&[operand_c, operand_d, operand_e, operand_b]),
                        );
                        3
                    }
                    2 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3)
                                .with_operands(&[operand_c, operand_d, operand_b]),
                        );
                        3
                    }
                    1 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3)
                                .with_operands(&[operand_c, operand_b]),
                        );
                        3
                    }
                    _ => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3)
                                .with_operands(&[operand_b]),
                        );
                        3
                    }
                }
            }
            InstructionFormat::Format35mi => {
                // [A=5] op {vC, vD, vE, vF, vG}, inline@BBBB
                // [A=4] op {vC, vD, vE, vF}, inline@BBBB
                // [A=3] op {vC, vD, vE}, inline@BBBB
                // [A=2] op {vC, vD}, inline@BBBB
                // [A=1] op {vC}, inline@BBBB
                let v_a = (instruction_unit >> 12) & 0x0F;
                let v_g = (instruction_unit >> 8) & 0x0F;
                let bbbb = insns[pc + 1];
                let v_c = (insns[pc + 2] >> 0) & 0x0F;
                let v_d = (insns[pc + 2] >> 4) & 0x0F;
                let v_e = (insns[pc + 2] >> 8) & 0x0F;
                let v_f = (insns[pc + 2] >> 12) & 0x0F;

                let operand_a = Operand::Register(v_a);
                let operand_b = Operand::MethodId(bbbb);
                let operand_c = Operand::Register(v_c);
                let operand_d = Operand::Register(v_d);
                let operand_e = Operand::Register(v_e);
                let operand_f = Operand::Register(v_f);
                let operand_g = Operand::Register(v_g);

                match v_a {
                    5 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3).with_operands(&[
                                operand_c, operand_d, operand_e, operand_f, operand_g, operand_b,
                            ]),
                        );
                        3
                    }
                    4 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3).with_operands(&[
                                operand_c, operand_d, operand_e, operand_f, operand_b,
                            ]),
                        );
                        3
                    }
                    3 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3)
                                .with_operands(&[operand_c, operand_d, operand_e, operand_b]),
                        );
                        3
                    }
                    2 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3)
                                .with_operands(&[operand_c, operand_d, operand_b]),
                        );
                        3
                    }
                    1 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3)
                                .with_operands(&[operand_c, operand_b]),
                        );
                        3
                    }
                    _ => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 3)
                                .with_operands(&[operand_a]),
                        );
                        3
                    }
                }
            }
            // TODO(sfx): check for off by ones.
            InstructionFormat::Format3rc => {
                // AA|op BBBB CCCC
                // Format is always 3 units total
                // AA = register count, BBBB = method ref, CCCC = first register
                // Registers are a RANGE: vCCCC through v(CCCC+AA-1)
                let v_a = (instruction_unit >> 8) & 0xFF;
                let bbbb = insns[pc + 1];
                let cccc = insns[pc + 2];

                // Build register range string directly without Vec allocation
                let mut registers_str = String::with_capacity((v_a as usize) * 4);
                for i in 0..v_a {
                    if i > 0 {
                        registers_str.push_str(", ");
                    }
                    registers_str.push_str("v");
                    registers_str.push_str(&(cccc + i).to_string());
                }

                let operand_a = Operand::RegisterRange {
                    start: cccc,
                    end: cccc + v_a - 1,
                };
                let operand_b = Operand::MethodId(bbbb);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 3)
                        .with_operands(&[operand_a, operand_b]),
                );
                3
            }
            InstructionFormat::Format3rms => {
                // AA|op BBBB CCCC
                let v_a = (instruction_unit >> 8) & 0xFF;
                let bbbb = insns[pc + 1];
                let cccc = insns[pc + 2];

                // Build register range string directly without Vec allocation
                let mut registers_str = String::with_capacity((v_a as usize) * 4);
                for i in 0..v_a {
                    if i > 0 {
                        registers_str.push_str(", ");
                    }
                    registers_str.push_str("v");
                    registers_str.push_str(&(cccc + i).to_string());
                }

                let operand_a = Operand::RegisterRange {
                    start: cccc,
                    end: cccc + v_a - 1,
                };
                let operand_b = Operand::Vtaboff(bbbb as u32);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 3)
                        .with_operands(&[operand_a, operand_b]),
                );
                3
            }
            InstructionFormat::Format3rmi => {
                // AA|op BBBB CCCC - same as Format3rc, always 3 units
                let v_a = (instruction_unit >> 8) & 0xFF;
                let bbbb = insns[pc + 1];
                let cccc = insns[pc + 2];

                // Build register range string directly without Vec allocation
                let mut registers_str = String::with_capacity((v_a as usize) * 4);
                for i in 0..v_a {
                    if i > 0 {
                        registers_str.push_str(", ");
                    }
                    registers_str.push_str("v");
                    registers_str.push_str(&(cccc + i).to_string());
                }

                let operand_a = Operand::RegisterRange {
                    start: cccc,
                    end: cccc + v_a - 1,
                };
                let operand_b = Operand::MethodId(bbbb);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 3)
                        .with_operands(&[operand_a, operand_b]),
                );
                3
            }
            InstructionFormat::Format45cc => {
                // A|G|op BBBB F|E|D|C HHHH
                // variadic: [A=5] op {vC..vG}, meth@BBBB, proto@HHHH
                let v_a = (instruction_unit >> 12) & 0x0F;
                let v_g = (instruction_unit >> 8) & 0x0F;
                let bbbb = insns[pc + 1];
                let v_c = (insns[pc + 2] >> 0) & 0x0F;
                let v_d = (insns[pc + 2] >> 4) & 0x0F;
                let v_e = (insns[pc + 2] >> 8) & 0x0F;
                let v_f = (insns[pc + 2] >> 12) & 0x0F;
                let hhhh = insns[pc + 3];

                let operand_a = Operand::Register(v_a);
                let operand_b = Operand::MethodId(bbbb);
                let operand_c = Operand::ProtoId(hhhh as u32);
                let operand_d = Operand::Register(v_c);
                let operand_e = Operand::Register(v_d);
                let operand_f = Operand::Register(v_e);
                let operand_g = Operand::Register(v_f);
                let operand_h = Operand::Register(v_g);

                // Build register list based on v_a
                let mut registers_str = String::with_capacity((v_a as usize) * 4);
                if v_a > 0 {
                    registers_str.push_str("v");
                    registers_str.push_str(&v_c.to_string());
                    if v_a > 1 {
                        registers_str.push_str(", v");
                        registers_str.push_str(&v_d.to_string());
                    }
                    if v_a > 2 {
                        registers_str.push_str(", v");
                        registers_str.push_str(&v_e.to_string());
                    }
                    if v_a > 3 {
                        registers_str.push_str(", v");
                        registers_str.push_str(&v_f.to_string());
                    }
                    if v_a > 4 {
                        registers_str.push_str(", v");
                        registers_str.push_str(&v_g.to_string());
                    }
                }

                match v_a {
                    5 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 4).with_operands(&[
                                operand_d, operand_e, operand_f, operand_g, operand_h, operand_b,
                                operand_c,
                            ]),
                        );
                    }
                    4 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 4).with_operands(&[
                                operand_d, operand_e, operand_f, operand_g, operand_b, operand_c,
                            ]),
                        );
                    }
                    3 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 4).with_operands(&[
                                operand_d, operand_e, operand_f, operand_b, operand_c,
                            ]),
                        );
                    }
                    2 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 4)
                                .with_operands(&[operand_d, operand_e, operand_b, operand_c]),
                        );
                    }
                    1 => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 4)
                                .with_operands(&[operand_d, operand_b, operand_c]),
                        );
                    }
                    _ => {
                        instructions.push(
                            Instruction::new(opcode, format, address as u32, 4)
                                .with_operands(&[operand_b, operand_c]),
                        );
                    }
                }
                4
            }
            InstructionFormat::Format4rcc => {
                // AA|op BBBB CCCC HHHH
                // op> {vCCCC..vNNNN}, meth@BBBB, proto@HHHH
                let v_a = (instruction_unit >> 8) & 0xFF;
                let bbbb = insns[pc + 1];
                let cccc = insns[pc + 2];
                let hhhh = insns[pc + 3];

                let mut registers_str = String::with_capacity((v_a as usize) * 4);
                for i in 0..v_a {
                    if i > 0 {
                        registers_str.push_str(", ");
                    }
                    registers_str.push_str("v");
                    registers_str.push_str(&(cccc + i).to_string());
                }

                let operand_a = Operand::RegisterRange {
                    start: cccc,
                    end: cccc + v_a - 1,
                };
                let operand_b = Operand::MethodId(bbbb);
                let operand_c = Operand::ProtoId(hhhh as u32);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 4)
                        .with_operands(&[operand_a, operand_b, operand_c]),
                );
                4
            }
            InstructionFormat::Format51l => {
                // AA|op BBBBlo BBBB BBBB BBBBhi 5 bytes
                let v_aa = (instruction_unit >> 8) & 0xFF;
                let bbbb_lo1 = insns[pc + 1];
                let bbbb_lo2 = insns[pc + 2];
                let bbbb_hi1 = insns[pc + 3];
                let bbbb_hi2 = insns[pc + 4];
                let bbbb = ((bbbb_hi2 as u64) << 48)
                    | ((bbbb_hi1 as u64) << 32)
                    | ((bbbb_lo2 as u64) << 16)
                    | (bbbb_lo1 as u64);
                let operand_a = Operand::Register(v_aa);
                let operand_b = Operand::I64(bbbb as i64);
                instructions.push(
                    Instruction::new(opcode, format, address as u32, 5)
                        .with_operands(&[operand_a, operand_b]),
                );
                5
            }
        };

        if pc + size_units > insns.len() {
            break; // Stop processing if we hit truncated data
        }

        pc += size_units;
    }
    Ok(instructions)
}

pub fn disassemble_class(
    dex: &Dex,
    dexfile: &Mmap,
    class_def: class_def_item,
    cli: &Cli,
) -> Result<(HashMap<String, Vec<Instruction>>, usize), DisassemblyError> {
    let mut method_idx_counter: u32; // Track method index diff accumulation
    let mut dism: HashMap<String, Vec<Instruction>> = HashMap::new();
    let class_name = dex.type_map.get(class_def.class_idx as usize).unwrap();
    let mut num_bytes: usize = 0;

    if class_def.class_data_off == 0 {
        return Ok((dism, 0));
    }

    if (class_def.class_data_off as usize) >= dexfile.len() {
        // Error: Class data offset out of bounds"
        debug!("Class data offset out of file bounds");
        return Err(DisassemblyError::OutOfBounds);
    }

    let (class_data, _bytes_read) =
        parse_class_data_item(dexfile, class_def.class_data_off as usize);

    // --- Process Direct Methods ---
    method_idx_counter = 0; // Reset for direct methods
    for encoded_method in &class_data.direct_methods {
        method_idx_counter = method_idx_counter.wrapping_add(encoded_method.method_idx_diff); // Accumulate diff
        let method_id_index = method_idx_counter as usize;

        if let Some(method_id) = dex.method_ids.get(method_id_index) {
            // Get the actual proto_id_item needed by the utils function
            let proto_item = dex.proto_ids.get(method_id.proto_idx as usize).ok_or(
                DisassemblyError::ProtoIndexOutOfBounds {
                    proto_idx: method_id.proto_idx,
                    method_idx: method_id_index,
                },
            )?;

            // Call the function from utils
            let method_sig =
                get_method_signature(dexfile, proto_item, dex.string_ids, dex.type_ids).map_err(
                    |e| DisassemblyError::MethodSignatureError {
                        method_idx: method_id_index,
                        error: e,
                    },
                )?;

            // Get method name from string_ids
            let method_name_offset = dex.string_ids.get(method_id.name_idx as usize).unwrap();

            let method_name = dex
                .string_map
                .get(&method_name_offset)
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());

            // Combine method name with signature: methodName(Signature)
            let method_full_name = format!("{}{}", method_name, method_sig);

            let should_disassemble =
                cli.method.is_none() || cli.method.as_deref() == Some(&method_sig);

            if should_disassemble && encoded_method.code_off != 0 {
                // Ensure code offset is within bounds
                if (encoded_method.code_off as usize) < dexfile.len() {
                    let (code_item, code_bytes_read) =
                        parse_code_item(dexfile, encoded_method.code_off as usize);
                    let instructions = disassemble_method(
                        &code_item,
                        dex.string_ids, // Pass the slice of string offsets
                        &dex.string_map,
                        &dex.type_map,
                        Some(&class_name),
                        Some(&method_full_name),
                    )?;
                    dism.insert(method_full_name, instructions);
                    num_bytes += code_bytes_read;
                } else {
                    warn!(
                        "Method code_off 0x{:x} is out of bounds for {}",
                        encoded_method.code_off, method_full_name
                    );
                }
            } else if should_disassemble {
            }
        } else {
            warn!(
                "Invalid method_id_index {} derived for class {}",
                method_id_index, class_name
            );
        }
    }

    // --- Process Virtual Methods ---
    method_idx_counter = 0; // Reset for virtual methods
    for encoded_method in &class_data.virtual_methods {
        method_idx_counter = method_idx_counter.wrapping_add(encoded_method.method_idx_diff); // Accumulate diff
        let method_id_index = method_idx_counter as usize;

        if let Some(method_id) = dex.method_ids.get(method_id_index) {
            // Get the actual proto_id_item needed by the utils function
            let proto_item = dex.proto_ids.get(method_id.proto_idx as usize).ok_or(
                DisassemblyError::ProtoIndexOutOfBounds {
                    proto_idx: method_id.proto_idx,
                    method_idx: method_id_index,
                },
            )?;

            // Call the function from utils
            let method_sig =
                get_method_signature(dexfile, proto_item, dex.string_ids, dex.type_ids).map_err(
                    |e| DisassemblyError::MethodSignatureError {
                        method_idx: method_id_index,
                        error: e,
                    },
                )?;

            // Get method name from string_ids
            let method_name_offset = dex.string_ids.get(method_id.name_idx as usize).unwrap();

            let method_name = dex
                .string_map
                .get(&method_name_offset)
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());

            // Combine method name with signature: methodName(Signature)
            let method_full_name = format!("{}{}", method_name, method_sig);

            let should_disassemble =
                cli.method.is_none() || cli.method.as_deref() == Some(&method_sig);

            if should_disassemble && encoded_method.code_off != 0 {
                // Ensure code offset is within bounds
                if (encoded_method.code_off as usize) < dexfile.len() {
                    let (code_item, code_bytes_read) =
                        parse_code_item(dexfile, encoded_method.code_off as usize);
                    let instructions = disassemble_method(
                        &code_item,
                        dex.string_ids, // Pass the slice of string offsets
                        &dex.string_map,
                        &dex.type_map,
                        Some(&class_name),
                        Some(&method_full_name),
                    )?;
                    dism.insert(method_full_name, instructions);
                    num_bytes += code_bytes_read;
                } else {
                    warn!(
                        "Method code_off 0x{:x} is out of bounds for {}",
                        encoded_method.code_off, method_full_name
                    );
                }
            } else if should_disassemble {
            }
        } else {
            warn!(
                "Invalid method_id_index {} derived for class {}",
                method_id_index, class_name
            );
        }
    }

    Ok((dism, num_bytes))
}
