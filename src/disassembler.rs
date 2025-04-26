use lazy_static::lazy_static;
use log::debug;

use crate::types::CodeItem; // Removed DecodedString for now
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
// | `22b`                                  | 22b       | `op vAA, vBB, #+CC`                                                                            |
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
    /// op vA, vB, +CCCC
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

// --- Opcode Constants (Subset) ---
// Refer to: https://source.android.com/docs/core/dalvik/dalvik-bytecode
#[derive(Debug, Copy, Clone, Ord, PartialEq, PartialOrd, Eq)]
enum Opcode {
    NOP = 0x00,
    MOVE = 0x01,                   // Format 12x (move vA, vB)
    MOVE_FROM16 = 0x02,            // Format 22x (move/from16 vAA, vBBBB)
    MOVE_16 = 0x03,                // Format 32x (move/16 vAAAA, vBBBB)
    MOVE_WIDE = 0x04,              // Format 12x (move-wide vA, vB)
    MOVE_WIDE_FROM16 = 0x05,       // Format 22x (move-wide/from16 vAA, vBBBB)
    MOVE_WIDE_16 = 0x06,           // Format 32x (move-wide/16 vAAAA, vBBBB)
    MOVE_OBJECT = 0x07,            // Format 12x (move-object vA, vB)
    MOVE_OBJECT_FROM16 = 0x08,     // Format 22x (move-object/from16 vAA, vBBBB)
    MOVE_OBJECT_16 = 0x09,         // Format 32x (move-object/16 vAAAA, vBBBB)
    MOVE_RESULT = 0x0a,            // Format 11x (move-result vAA)
    MOVE_RESULT_WIDE = 0x0b,       // Format 11x (move-result-wide vAA)
    MOVE_RESULT_OBJECT = 0x0c,     // Format 11x (move-result-object vAA)
    MOVE_EXCEPTION = 0x0d,         // Format 11x (move-exception vAA)
    RETURN_VOID = 0x0e,            // Format 10x
    RETURN = 0x0f,                 // Format 11x (return vAA)
    RETURN_WIDE = 0x10,            // Format 11x (return-wide vAA)
    RETURN_OBJECT = 0x11,          // Format 11x (return-object vAA)
    CONST_4 = 0x12,                // Format 11n (const/4 vA, #+B)
    CONST_16 = 0x13,               // Format 21s (const/16 vAA, #+BBBB)
    CONST = 0x14,                  // Format 31i (const vAA, #+BBBBBBBB)
    CONST_HIGH16 = 0x15,           // Format 21h (const/high16 vAA, #+BBBB0000)
    CONST_WIDE_16 = 0x16,          // Format 21s (const-wide/16 vAA, #+BBBB)
    CONST_WIDE_32 = 0x17,          // Format 31i (const-wide/32 vAA, #+BBBBBBBB)
    CONST_WIDE = 0x18,             // Format 51l (const-wide vAA, #+BBBBBBBBBBBBBBBB)
    CONST_WIDE_HIGH16 = 0x19,      // Format 21h (const-wide/high16 vAA, #+BBBB000000000000)
    CONST_STRING = 0x1a,           // Format 21c (const-string vAA, string@BBBB)
    CONST_STRING_JUMBO = 0x1b,     // Format 31c (const-string/jumbo vAA, string@BBBBBBBB)
    CONST_CLASS = 0x1c,            // Format 21c (const-class vAA, type@BBBB)
    MONITOR_ENTER = 0x1d,          // Format 11x (monitor-enter vAA)
    MONITOR_EXIT = 0x1e,           // Format 11x (monitor-exit vAA)
    CHECK_CAST = 0x1f,             // Format 21c (check-cast vAA, type@BBBB)
    INSTANCE_OF = 0x20,            // Format 22c (instance-of vA, vB, type@CCCC)
    ARRAY_LENGTH = 0x21,           // Format 12x (array-length vA, vB)
    NEW_INSTANCE = 0x22,           // Format 21c (new-instance vAA, type@BBBB)
    NEW_ARRAY = 0x23,              // Format 22c (new-array vA, vB, type@CCCC)
    FILLED_NEW_ARRAY = 0x24,       // Format 35c (filled-new-array {vC..vG}, type@BBBB)
    FILLED_NEW_ARRAY_RANGE = 0x25, // Format 3rc (filled-new-array/range {vCCCC..vNNNN}, type@BBBB)
    FILL_ARRAY_DATA = 0x26,        // Format 31t (fill-array-data vAA, +BBBBBBBB)
    THROW = 0x27,                  // Format 11x (throw vAA)
    GOTO = 0x28,                   // Format 10t (goto +AA)
    GOTO_16 = 0x29,                // Format 20t (goto/16 +AAAA)
    GOTO_32 = 0x2a,                // Format 30t (goto/32 +AAAAAAAA)
    PACKED_SWITCH = 0x2b,          // Format 31t (packed-switch vAA, +BBBBBBBB)
    SPARSE_SWITCH = 0x2c,          // Format 31t (sparse-switch vAA, +BBBBBBBB)

    // cmpkind
    CMPL_FLOAT = 0x2d,  // Format 23x (cmpl-float vAA, vBB, vCC)
    CMPG_FLOAT = 0x2e,  // Format 23x (cmpg-float vAA, vBB, vCC)
    CMPL_DOUBLE = 0x2f, // Format 23x (cmp-double vAA, vBB, vCC)
    CMPG_DOUBLE = 0x30, // Format 23x (cmpg-double vAA, vBB, vCC)
    CMP_LONG = 0x31,    // Format 23x (cmp-long vAA, vBB, vCC)

    // if-test
    IF_EQ = 0x32, // Format 22t (if-eq vA, vB, +CCCC)
    IF_NE = 0x33, // Format 22t (if-ne vA, vB, +CCCC)
    IF_LT = 0x34, // Format 22t (if-lt vA, vB, +CCCC)
    IF_GE = 0x35, // Format 22t (if-ge vA, vB, +CCCC)
    IF_GT = 0x36, // Format 22t (if-gt vA, vB, +CCCC)
    IF_LE = 0x37, // Format 22t (if-le vA, vB, +CCCC)

    // if-testz
    IF_EQZ = 0x38, // Format 21t (if-eqz vA, +BBBB)
    IF_NEZ = 0x39, // Format 21t (if-nez vA, +BBBB)
    IF_LTZ = 0x3a, // Format 21t (if-ltz vA, +BBBB)
    IF_GEZ = 0x3b, // Format 21t (if-gez vA, +BBBB)
    IF_GTZ = 0x3c, // Format 21t (if-gtz vA, +BBBB)
    IF_LEZ = 0x3d, // Format 21t (if-lex vA, +BBBB)

    // Format 23x arrayop vAA, vBB, vCC
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

    // instanceop vA, vB, field@CCCC
    IGET = 0x52,         // Format 22c (iget vA, vB, field@CCCC)
    IGET_WIDE = 0x53,    // Format 22c (iget-wide vA, vB, field@CCCC)
    IGET_OBJECT = 0x54,  // Format 22c (iget-object vA, vB, field@CCCC)
    IGET_BOOLEAN = 0x55, // Format 22c (iget-boolean vA, vB, field@CCCC)
    IGET_BYTE = 0x56,    // Format 22c (iget-byte vA, vB, field@CCCC)
    IGET_CHAR = 0x57,    // Format 22c (iget-char vA, vB, field@CCCC)
    IGET_SHORT = 0x58,   // Format 22c (iget-short vA, vB, field@CCCC)
    IPUT = 0x59,         // Format 22c (iput vA, vB, field@CCCC)
    IPUT_WIDE = 0x5A,    // Format 22c (iput-wide vA, vB, field@CCCC)
    IPUT_OBJECT = 0x5B,  // Format 22c (iput-object vA, vB, field@CCCC)
    IPUT_BOOLEAN = 0x5C, // Format 22c (iput-boolean vA, vB, field@CCCC)
    IPUT_BYTE = 0x5D,    // Format 22c (iput-byte vA, vB, field@CCCC)
    IPUT_CHAR = 0x5E,    // Format 22c (iput-char vA, vB, field@CCCC)
    IPUT_SHORT = 0x5F,   // Format 22c (iput-short vA, vB, field@CCCC)

    // sttaticop vAA, field@BBBB
    SGET = 0x60,         // Format 21c (sget vAA, field@BBBB)
    SGET_WIDE = 0x61,    // Format 21c (sget-wide vAA, field@BBBB)
    SGET_OBJECT = 0x62,  // Format 21c (sget-object vAA, field@BBBB)
    SGET_BOOLEAN = 0x63, // Format 21c (sget-boolean vAA, field@BBBB)
    SGET_BYTE = 0x64,    // Format 21c (sget-byte vAA, field@BBBB)
    SGET_CHAR = 0x65,    // Format 21c (sget-char vAA, field@BBBB)
    SGET_SHORT = 0x66,   // Format 21c (sget-short vAA, field@BBBB)
    SPUT = 0x67,         // Format 21c (sput vAA, field@BBBB)
    SPUT_WIDE = 0x68,    // Format 21c (sput-wide vAA, field@BBBB)
    SPUT_OBJECT = 0x69,  // Format 21c (sput-object vAA, field@BBBB)
    SPUT_BOOLEAN = 0x6A, // Format 21c (sput-boolean vAA, field@BBBB)
    SPUT_BYTE = 0x6B,    // Format 21c (sput-byte vAA, field@BBBB)
    SPUT_CHAR = 0x6C,    // Format 21c (sput-char vAA, field@BBBB)
    SPUT_SHORT = 0x6D,   // Format 21c (sput-short vAA, field@BBBB)

    // invokekind {vC..vG}, meth@BBBB
    INVOKE_VIRTUAL = 0x6E,   // Format 35c (invoke-virtual {vC..vG}, meth@BBBB)
    INVOKE_SUPER = 0x6F,     // Format 35c (invoke-super {vC..vG}, meth@BBBB)
    INVOKE_DIRECT = 0x70,    // Format 35c (invoke-direct {vC..vG}, meth@BBBB)
    INVOKE_STATIC = 0x71,    // Format 35c (invoke-static {vC..vG}, meth@BBBB)
    INVOKE_INTERFACE = 0x72, // Format 35c (invoke-interface {vC..vG}, meth@BBBB)

    // invoke-kind/range {vCCCC..vNNNN}, meth@BBBB
    INVOKE_VIRTUAL_RANGE = 0x74, // Format 3rc (invoke-virtual/range {vCCCC..vNNNN}, meth@BBBB)
    INVOKE_SUPER_RANGE = 0x75,   // Format 3rc (invoke-super/range {vCCCC..vNNNN}, meth@BBBB)
    INVOKE_DIRECT_RANGE = 0x76,  // Format 3rc (invoke-direct/range {vCCCC..vNNNN}, meth@BBBB)
    INVOKE_STATIC_RANGE = 0x77,  // Format 3rc (invoke-static/range {vCCCC..vNNNN}, meth@BBBB)
    INVOKE_INTERFACE_RANGE = 0x78, // Format 3rc (invoke-interface/range {vCCCC..vNNNN}, meth@BBBB)

    /// Unary operation: neg-int
    NEG_INT = 0x7b, // Format 12x (neg-int vA, vB)
    NOT_INT = 0x7c,         // Format 12x (not-int vA, vB)
    NEG_LONG = 0x7d,        // Format 12x (neg-long vA, vB)
    NOT_LONG = 0x7e,        // Format 12x (not-long vA, vB)
    NEG_FLOAT = 0x7f,       // Format 12x (neg-float vA, vB)
    NEG_DOUBLE = 0x80,      // Format 12x (neg-double vA, vB)
    INT_TO_LONG = 0x81,     // Format 12x (int-to-long vA, vB)
    INT_TO_FLOAT = 0x82,    // Format 12x (int-to-float vA, vB)
    INT_TO_DOUBLE = 0x83,   // Format 12x (int-to-double vA, vB)
    LONG_TO_INT = 0x84,     // Format 12x (long-to-int vA, vB)
    LONG_TO_FLOAT = 0x85,   // Format 12x (long-to-float vA, vB)
    LONG_TO_DOUBLE = 0x86,  // Format 12x (long-to-double vA, vB)
    FLOAT_TO_INT = 0x87,    // Format 12x (float-to-int vA, vB)
    FLOAT_TO_LONG = 0x88,   // Format 12x (float-to-long vA, vB)
    FLOAT_TO_DOUBLE = 0x89, // Format 12x (float-to-double vA, vB)
    DOUBLE_TO_INT = 0x8a,   // Format 12x (double-to-int vA, vB)
    DOUBLE_TO_LONG = 0x8b,  // Format 12x (double-to-long vA, vB)
    DOUBLE_TO_FLOAT = 0x8c, // Format 12x (double-to-float vA, vB)
    INT_TO_BYTE = 0x8d,     // Format 12x (int-to-byte vA, vB)
    INT_TO_CHAR = 0x8e,     // Format 12x (int-to-char vA, vB)
    INT_TO_SHORT = 0x8f,    // Format 12x (int-to-short vA, vB)

    // binop vAA, vBB, vCC
    ADD_INT = 0x90,    // Format 23x (add-int vAA, vBB, vCC)
    SUB_INT = 0x91,    // Format 23x (sub-int vAA, vBB, vCC)
    MUL_INT = 0x92,    // Format 23x (mul-int vAA, vBB, vCC)
    DIV_INT = 0x93,    // Format 23x (div-int vAA, vBB, vCC)
    REM_INT = 0x94,    // Format 23x (rem-int vAA, vBB, vCC)
    AND_INT = 0x95,    // Format 23x (and-int vAA, vBB, vCC)
    OR_INT = 0x96,     // Format 23x (or-int vAA, vBB, vCC)
    XOR_INT = 0x97,    // Format 23x (xor-int vAA, vBB, vCC)
    SHL_INT = 0x98,    // Format 23x (shl-int vAA, vBB, vCC)
    SHR_INT = 0x99,    // Format 23x (shr-int vAA, vBB, vCC)
    USHR_INT = 0x9A,   // Format 23x (ushr-int vAA, vBB, vCC)
    ADD_LONG = 0x9B,   // Format 23x (add-long vAA, vBB, vCC)
    SUB_LONG = 0x9C,   // Format 23x (sub-long vAA, vBB, vCC)
    MUL_LONG = 0x9D,   // Format 23x (mul-long vAA, vBB, vCC)
    DIV_LONG = 0x9E,   // Format 23x (div-long vAA, vBB, vCC)
    REM_LONG = 0x9F,   // Format 23x (rem-long vAA, vBB, vCC)
    AND_LONG = 0xA0,   // Format 23x (and-long vAA, vBB, vCC)
    OR_LONG = 0xA1,    // Format 23x (or-long vAA, vBB, vCC)
    XOR_LONG = 0xA2,   // Format 23x (xor-long vAA, vBB, vCC)
    SHL_LONG = 0xA3,   // Format 23x (shl-long vAA, vBB, vCC)
    SHR_LONG = 0xA4,   // Format 23x (shr-long vAA, vBB, vCC)
    USHR_LONG = 0xA5,  // Format 23x (ushr-long vAA, vBB, vCC)
    ADD_FLOAT = 0xA6,  // Format 23x (add-float vAA, vBB, vCC)
    SUB_FLOAT = 0xA7,  // Format 23x (sub-float vAA, vBB, vCC)
    MUL_FLOAT = 0xA8,  // Format 23x (mul-float vAA, vBB, vCC)
    DIV_FLOAT = 0xA9,  // Format 23x (div-float vAA, vBB, vCC)
    REM_FLOAT = 0xAA,  // Format 23x (rem-float vAA, vBB, vCC)
    ADD_DOUBLE = 0xAB, // Format 23x (add-double vAA, vBB, vCC)
    SUB_DOUBLE = 0xAC, // Format 23x (sub-double vAA, vBB, vCC)
    MUL_DOUBLE = 0xAD, // Format 23x (mul-double vAA, vBB, vCC)
    DIV_DOUBLE = 0xAE, // Format 23x (div-double vAA, vBB, vCC)
    REM_DOUBLE = 0xAF, // Format 23x (rem-double vAA, vBB, vCC)

    // binop/2addr vAA, vBB, vCC
    ADD_INT_2ADDR = 0xb0,    // Format 12x (add-int/2addr vA, vB)
    SUB_INT_2ADDR = 0xb1,    // Format 12x (sub-int/2addr vA, vB)
    MUL_INT_2ADDR = 0xb2,    // Format 12x (mul-int/2addr vA, vB)
    DIV_INT_2ADDR = 0xb3,    // Format 12x (div-int/2addr vA, vB)
    REM_INT_2ADDR = 0xb4,    // Format 12x (rem-int/2addr vA, vB)
    AND_INT_2ADDR = 0xb5,    // Format 12x (and-int/2addr vA, vB)
    OR_INT_2ADDR = 0xb6,     // Format 12x (or-int/2addr vA, vB)
    XOR_INT_2ADDR = 0xb7,    // Format 12x (xor-int/2addr vA, vB)
    SHL_INT_2ADDR = 0xb8,    // Format 12x (shl-int/2addr vA, vB)
    SHR_INT_2ADDR = 0xb9,    // Format 12x (shr-int/2addr vA, vB)
    USHR_INT_2ADDR = 0xba,   // Format 12x (ushr-int/2addr vA, vB)
    ADD_LONG_2ADDR = 0xbb,   // Format 12x (add-long/2addr vA, vB)
    SUB_LONG_2ADDR = 0xbc,   // Format 12x (sub-long/2addr vA, vB)
    MUL_LONG_2ADDR = 0xbd,   // Format 12x (mul-long/2addr vA, vB)
    DIV_LONG_2ADDR = 0xbe,   // Format 12x (div-long/2addr vA, vB)
    REM_LONG_2ADDR = 0xbf,   // Format 12x (rem-long/2addr vA, vB)
    AND_LONG_2ADDR = 0xc0,   // Format 12x (and-long/2addr vA, vB)
    OR_LONG_2ADDR = 0xc1,    // Format 12x (or-long/2addr vA, vB)
    XOR_LONG_2ADDR = 0xc2,   // Format 12x (xor-long/2addr vA, vB)
    SHL_LONG_2ADDR = 0xc3,   // Format 12x (shl-long/2addr vA, vB)
    SHR_LONG_2ADDR = 0xc4,   // Format 12x (shr-long/2addr vA, vB)
    USHR_LONG_2ADDR = 0xc5,  // Format 12x (ushr-long/2addr vA, vB)
    ADD_FLOAT_2ADDR = 0xc6,  // Format 12x (add-float/2addr vA, vB)
    SUB_FLOAT_2ADDR = 0xc7,  // Format 12x (sub-float/2addr vA, vB)
    MUL_FLOAT_2ADDR = 0xc8,  // Format 12x (mul-float/2addr vA, vB)
    DIV_FLOAT_2ADDR = 0xc9,  // Format 12x (div-float/2addr vA, vB)
    REM_FLOAT_2ADDR = 0xca,  // Format 12x (rem-float/2addr vA, vB)
    ADD_DOUBLE_2ADDR = 0xcb, // Format 12x (add-double/2addr vA, vB)
    SUB_DOUBLE_2ADDR = 0xcc, // Format 12x (sub-double/2addr vA, vB)
    MUL_DOUBLE_2ADDR = 0xcd, // Format 12x (mul-double/2addr vA, vB)
    DIV_DOUBLE_2ADDR = 0xce, // Format 12x (div-double/2addr vA, vB)
    REM_DOUBLE_2ADDR = 0xcf, // Format 12x (rem-double/2addr vA, vB)

    // binop/lit16 vAA, vBB, #+CCCC
    ADD_INT_LIT16 = 0xd0, // Format 22s (add-int/lit16 vA, vB, #+CCCC)
    RSUB_INT = 0xd1,      // Format 22s (rsub-int vA, vB, #+CCCC)
    MUL_INT_LIT16 = 0xd2, // Format 22s (mul-int/lit16 vA, vB, #+CCCC)
    DIV_INT_LIT16 = 0xd3, // Format 22s (div-int/lit16 vA, vB, #+CCCC)
    REM_INT_LIT16 = 0xd4, // Format 22s (rem-int/lit16 vA, vB, #+CCCC)
    AND_INT_LIT16 = 0xd5, // Format 22s (and-int/lit16 vA, vB, #+CCCC)
    OR_INT_LIT16 = 0xd6,  // Format 22s (or-int/lit16 vA, vB, #+CCCC)
    XOR_INT_LIT16 = 0xd7, // Format 22s (xor-int/lit16 vA, vB, #+CCCC)

    // binop/lit8 vAA, vBB, #+CC
    ADD_INT_LIT8 = 0xd8,  // Format 22b (add-int/lit8 vAA, vBB, #+CC)
    RSUB_INT_LIT8 = 0xd9, // Format 22b (rsub-int/lit8 vAA, vBB, #+CC)
    MUL_INT_LIT8 = 0xda,  // Format 22b (mul-int/lit8 vAA, vBB, #+CC)
    DIV_INT_LIT8 = 0xdb,  // Format 22b (div-int/lit8 vAA, vBB, #+CC)
    REM_INT_LIT8 = 0xdc,  // Format 22b (rem-int/lit8 vAA, vBB, #+CC)
    AND_INT_LIT8 = 0xdd,  // Format 22b (and-int/lit8 vAA, vBB, #+CC)
    OR_INT_LIT8 = 0xde,   // Format 22b (or-int/lit8 vAA, vBB, #+CC)
    XOR_INT_LIT8 = 0xdf,  // Format 22b (xor-int/lit8 vAA, vBB, #+CC)
    SHL_INT_LIT8 = 0xe0,  // Format 22b (shl-int/lit8 vAA, vBB, #+CC)
    SHR_INT_LIT8 = 0xe1,  // Format 22b (shr-int/lit8 vAA, vBB, #+CC)
    USHR_INT_LIT8 = 0xe2, // Format 22b (ushr-int/lit8 vAA, vBB, #+CC)

    INVOKE_POLYMORPHIC = 0xfa, // Format 45cc (invoke-polymorphic {vC,.. vG}, meth@BBBB, proto@HHHH)
    INVOKE_POLYMORPHIC_RANGE = 0xfb, // Format 4rcc (invoke-polymorphic/range {vCCCC..vNNNN}, meth@BBBB, proto@HHHH)
    INVOKE_CUSTOM = 0xfc,            // Format 45c (invoke-custom {vC,.. vG}, callsite@BBBB)
    INVOKE_CUSTOM_RANGE = 0xfd, // Format 4rc (invoke-custom/range {vCCCC..vNNNN}, callsite@BBBB)

    CONST_METHOD_HANDLE = 0xfe, // Format 21c (const-method-handle vAA, method_handle@BBBB)
    CONST_METHOD_TYPE = 0xff,   // Format 21c (const-method-type vAA, method_type@BBBB)
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

// TODO(sfx): Instruction to Format and Format to decoder map should make things easy to work with in this scenario.

/// DecoderMap: Maps opcode to a tuple of (Instruction Name, InstructionFormat)
/// This makes it easy to decode instructions and identify the appropriate format
type OpcodeInfo = (&'static str, InstructionFormat);
pub fn get_decoder_map() -> BTreeMap<Opcode, OpcodeInfo> {
    let mut map = BTreeMap::new();

    // Basic instructions
    map.insert(Opcode::NOP, ("nop", InstructionFormat::Format10x));
    map.insert(Opcode::MOVE, ("move", InstructionFormat::Format12x));
    map.insert(
        Opcode::MOVE_FROM16,
        ("move/from16", InstructionFormat::Format22x),
    );
    map.insert(Opcode::MOVE_16, ("move/16", InstructionFormat::Format32x));
    map.insert(
        Opcode::MOVE_WIDE,
        ("move-wide", InstructionFormat::Format12x),
    );
    map.insert(
        Opcode::MOVE_WIDE_FROM16,
        ("move-wide/from16", InstructionFormat::Format22x),
    );
    map.insert(
        Opcode::MOVE_WIDE_16,
        ("move-wide/16", InstructionFormat::Format32x),
    );
    map.insert(
        Opcode::MOVE_OBJECT,
        ("move-object", InstructionFormat::Format12x),
    );
    map.insert(
        Opcode::MOVE_OBJECT_FROM16,
        ("move-object/from16", InstructionFormat::Format22x),
    );
    map.insert(
        Opcode::MOVE_OBJECT_16,
        ("move-object/16", InstructionFormat::Format32x),
    );
    map.insert(
        Opcode::MOVE_RESULT,
        ("move-result", InstructionFormat::Format11x),
    );
    map.insert(
        Opcode::MOVE_RESULT_WIDE,
        ("move-result-wide", InstructionFormat::Format11x),
    );
    map.insert(
        Opcode::MOVE_RESULT_OBJECT,
        ("move-result-object", InstructionFormat::Format11x),
    );
    map.insert(
        Opcode::MOVE_EXCEPTION,
        ("move-exception", InstructionFormat::Format11x),
    );

    // Return instructions
    map.insert(
        Opcode::RETURN_VOID,
        ("return-void", InstructionFormat::Format10x),
    );
    map.insert(Opcode::RETURN, ("return", InstructionFormat::Format11x));
    map.insert(
        Opcode::RETURN_WIDE,
        ("return-wide", InstructionFormat::Format11x),
    );
    map.insert(
        Opcode::RETURN_OBJECT,
        ("return-object", InstructionFormat::Format11x),
    );

    // Const instructions
    map.insert(Opcode::CONST_4, ("const/4", InstructionFormat::Format11n));
    map.insert(Opcode::CONST_16, ("const/16", InstructionFormat::Format21s));
    map.insert(Opcode::CONST, ("const", InstructionFormat::Format31i));
    map.insert(
        Opcode::CONST_HIGH16,
        ("const/high16", InstructionFormat::Format21h),
    );
    map.insert(
        Opcode::CONST_WIDE_16,
        ("const-wide/16", InstructionFormat::Format21s),
    );
    map.insert(
        Opcode::CONST_WIDE_32,
        ("const-wide/32", InstructionFormat::Format31i),
    );
    map.insert(
        Opcode::CONST_WIDE,
        ("const-wide", InstructionFormat::Format51l),
    );
    map.insert(
        Opcode::CONST_WIDE_HIGH16,
        ("const-wide/high16", InstructionFormat::Format21h),
    );
    map.insert(
        Opcode::CONST_STRING,
        ("const-string", InstructionFormat::Format21c),
    );
    map.insert(
        Opcode::CONST_STRING_JUMBO,
        ("const-string/jumbo", InstructionFormat::Format31c),
    );
    map.insert(
        Opcode::CONST_CLASS,
        ("const-class", InstructionFormat::Format21c),
    );

    // Monitor instructions
    map.insert(
        Opcode::MONITOR_ENTER,
        ("monitor-enter", InstructionFormat::Format11x),
    );
    map.insert(
        Opcode::MONITOR_EXIT,
        ("monitor-exit", InstructionFormat::Format11x),
    );

    // Type check and cast instructions
    map.insert(
        Opcode::CHECK_CAST,
        ("check-cast", InstructionFormat::Format21c),
    );
    map.insert(
        Opcode::INSTANCE_OF,
        ("instance-of", InstructionFormat::Format22c),
    );

    // Array instructions
    map.insert(
        Opcode::ARRAY_LENGTH,
        ("array-length", InstructionFormat::Format12x),
    );
    map.insert(
        Opcode::NEW_ARRAY,
        ("new-array", InstructionFormat::Format22c),
    );
    map.insert(
        Opcode::FILLED_NEW_ARRAY,
        ("filled-new-array", InstructionFormat::Format35c),
    );
    map.insert(
        Opcode::FILLED_NEW_ARRAY_RANGE,
        ("filled-new-array/range", InstructionFormat::Format3rc),
    );
    map.insert(
        Opcode::FILL_ARRAY_DATA,
        ("fill-array-data", InstructionFormat::Format31t),
    );

    // Instance field instructions
    map.insert(Opcode::IGET, ("iget", InstructionFormat::Format22c));
    map.insert(
        Opcode::IGET_WIDE,
        ("iget-wide", InstructionFormat::Format22c),
    );
    map.insert(
        Opcode::IGET_OBJECT,
        ("iget-object", InstructionFormat::Format22c),
    );
    map.insert(
        Opcode::IGET_BOOLEAN,
        ("iget-boolean", InstructionFormat::Format22c),
    );
    map.insert(
        Opcode::IGET_BYTE,
        ("iget-byte", InstructionFormat::Format22c),
    );
    map.insert(
        Opcode::IGET_CHAR,
        ("iget-char", InstructionFormat::Format22c),
    );
    map.insert(
        Opcode::IGET_SHORT,
        ("iget-short", InstructionFormat::Format22c),
    );
    map.insert(Opcode::IPUT, ("iput", InstructionFormat::Format22c));
    map.insert(
        Opcode::IPUT_WIDE,
        ("iput-wide", InstructionFormat::Format22c),
    );
    map.insert(
        Opcode::IPUT_OBJECT,
        ("iput-object", InstructionFormat::Format22c),
    );
    map.insert(
        Opcode::IPUT_BOOLEAN,
        ("iput-boolean", InstructionFormat::Format22c),
    );
    map.insert(
        Opcode::IPUT_BYTE,
        ("iput-byte", InstructionFormat::Format22c),
    );
    map.insert(
        Opcode::IPUT_CHAR,
        ("iput-char", InstructionFormat::Format22c),
    );
    map.insert(
        Opcode::IPUT_SHORT,
        ("iput-short", InstructionFormat::Format22c),
    );

    // Method invoke instructions
    map.insert(
        Opcode::INVOKE_VIRTUAL,
        ("invoke-virtual", InstructionFormat::Format35c),
    );
    map.insert(
        Opcode::INVOKE_SUPER,
        ("invoke-super", InstructionFormat::Format35c),
    );
    map.insert(
        Opcode::INVOKE_DIRECT,
        ("invoke-direct", InstructionFormat::Format35c),
    );
    map.insert(
        Opcode::INVOKE_STATIC,
        ("invoke-static", InstructionFormat::Format35c),
    );
    map.insert(
        Opcode::INVOKE_INTERFACE,
        ("invoke-interface", InstructionFormat::Format35c),
    );
    map.insert(
        Opcode::INVOKE_VIRTUAL_RANGE,
        ("invoke-virtual/range", InstructionFormat::Format3rc),
    );
    map.insert(
        Opcode::INVOKE_SUPER_RANGE,
        ("invoke-super/range", InstructionFormat::Format3rc),
    );
    map.insert(
        Opcode::INVOKE_DIRECT_RANGE,
        ("invoke-direct/range", InstructionFormat::Format3rc),
    );
    map.insert(
        Opcode::INVOKE_STATIC_RANGE,
        ("invoke-static/range", InstructionFormat::Format3rc),
    );
    map.insert(
        Opcode::INVOKE_INTERFACE_RANGE,
        ("invoke-interface/range", InstructionFormat::Format3rc),
    );

    // Arithmetic instructions
    map.insert(Opcode::ADD_INT, ("add-int", InstructionFormat::Format23x));
    map.insert(Opcode::SUB_INT, ("sub-int", InstructionFormat::Format23x));
    map.insert(Opcode::MUL_INT, ("mul-int", InstructionFormat::Format23x));
    map.insert(Opcode::DIV_INT, ("div-int", InstructionFormat::Format23x));
    map.insert(Opcode::REM_INT, ("rem-int", InstructionFormat::Format23x));
    map.insert(Opcode::AND_INT, ("and-int", InstructionFormat::Format23x));
    map.insert(Opcode::OR_INT, ("or-int", InstructionFormat::Format23x));
    map.insert(Opcode::XOR_INT, ("xor-int", InstructionFormat::Format23x));

    // Control flow instructions
    map.insert(Opcode::GOTO, ("goto", InstructionFormat::Format10t));
    map.insert(Opcode::GOTO_16, ("goto/16", InstructionFormat::Format20t));
    map.insert(Opcode::GOTO_32, ("goto/32", InstructionFormat::Format30t));
    map.insert(Opcode::IF_EQ, ("if-eq", InstructionFormat::Format22t));
    map.insert(Opcode::IF_NE, ("if-ne", InstructionFormat::Format22t));
    map.insert(Opcode::IF_LT, ("if-lt", InstructionFormat::Format22t));
    map.insert(Opcode::IF_GE, ("if-ge", InstructionFormat::Format22t));
    map.insert(Opcode::IF_GT, ("if-gt", InstructionFormat::Format22t));
    map.insert(Opcode::IF_LE, ("if-le", InstructionFormat::Format22t));

    map
}

lazy_static! {
    static ref FMAP: BTreeMap<Opcode, OpcodeInfo> = get_decoder_map();
}

// Function for disassembling a method's code
pub fn disassemble_method(
    code_item: &CodeItem,
    string_ids: &[u32],                // Added: Slice of string ID offsets
    string_map: &HashMap<u32, String>, // Map<string_id_offset, String>
    type_map: &HashMap<u32, String>,   // Map<type_id, String>
                                       // TODO: Add method_map, field_map if needed
) -> Vec<String> {
    let mut disassembled_instructions = Vec::new();
    let insns = &code_item.insns; // Vec<u16>
    let mut pc: usize = 0; // Program counter in 16-bit code units

    while pc < insns.len() {
        let address = pc * 2; // Byte address for display
        let instruction_unit = insns[pc];
        let opcode = Opcode::from(instruction_unit as u8); // Low byte is the primary opcode

        let (name, format) = match FMAP.get(&opcode) {
            Some(&(name, format)) => {
                // Decode the instruction based on its format
                (name, format)
            }
            None => ("unknown", InstructionFormat::Format00x),
        };

        let (disassembly, size_units) = match format {
            InstructionFormat::Format00x => (name.to_string(), 1),
            InstructionFormat::Format10x => {
                (name.to_string(), 1)
            },
            InstructionFormat::Format12x => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                let v_b = (instruction_unit >> 12) & 0x0F;
                (format!("{} v{}, v{}",name , v_a, v_b), 1)
            }
            InstructionFormat::Format11n => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                let imm_b = (instruction_unit >> 12) & 0x0F;
                (format!("{} v{}, #+{}", name, v_a, imm_b), 1)
            },
            InstructionFormat::Format11x => {
                let v_a = (instruction_unit >> 8) & 0x0F;
                (format!("{} v{}", name, v_a), 1)
            },
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
            },
            InstructionFormat::Format20t => {
                // op +AAAA
                let literal = insns[pc+1];
                (format!("{} {}", name, literal),2)

            },
            InstructionFormat::Format20bc => {
                (format!("{}", name, ), 2)
            },
            InstructionFormat::Format22x => {
                (format!("{}", name, ), 2)
            },
            InstructionFormat::Format21t => {
                (format!("{}", name, ), 2)
            },
            InstructionFormat::Format21s => (format!("{}", name, ), 2),
            InstructionFormat::Format21h => (format!("{}", name, ), 2),
            InstructionFormat::Format21c => (format!("{}", name, ), 2),
            InstructionFormat::Format23x => (format!("{}", name, ), 2),
            InstructionFormat::Format22b => (format!("{}", name, ), 2),
            InstructionFormat::Format22t => (format!("{}", name, ), 2),
            InstructionFormat::Format22s => (format!("{}", name, ), 2),
            InstructionFormat::Format22c => (format!("{}", name, ), 2),
            InstructionFormat::Format22cs => (format!("{}", name, ), 2),
            InstructionFormat::Format30t => (format!("{}", name, ), 3),
            InstructionFormat::Format32x => (format!("{}", name, ), 3),
            InstructionFormat::Format31i => (format!("{}", name, ), 3),
            InstructionFormat::Format31t => (format!("{}", name, ), 3),
            InstructionFormat::Format31c => (format!("{}", name, ), 3),
            InstructionFormat::Format35c => (format!("{}", name, ), 3),
            InstructionFormat::Format35ms => (format!("{}", name, ), 3),
            InstructionFormat::Format35mi => (format!("{}", name, ), 3),
            InstructionFormat::Format3rc => (format!("{}", name, ), 3),
            InstructionFormat::Format3rms => (format!("{}", name, ), 3),
            InstructionFormat::Format3rmi => (format!("{}", name, ), 3),
            InstructionFormat::Format45cc => (format!("{}", name, ), 4),
            InstructionFormat::Format4rcc => (format!("{}", name, ), 4),
            InstructionFormat::Format51l => (format!("{}", name, ), 5),
        };
        // let (disassembly, size_units) = match opcode{
        //     Opcode::NOP => ("nop".to_string(), 1), // Format 10x
        //     Opcode::MOVE => { // Format 12x: move vA, vB
        //         let v_a = (instruction_unit >> 8) & 0x0F;
        //         let v_b = (instruction_unit >> 12) & 0x0F;
        //         (format!("move v{}, v{}", v_a, v_b), 1)
        //     }
        //     Opcode::CONST_4 => { // Format 11n: const/4 vA, #+B
        //         let v_a = (instruction_unit >> 8) & 0x0F;
        //         let imm_b = (instruction_unit >> 12) & 0x0F; // This is u16
        //         // Sign extend the 4-bit value correctly using an intermediate u32
        //         let imm_b_u32: u32 = if (imm_b & 0x8) != 0 {
        //             (imm_b as u32) | 0xFFFFFFF0 // Cast imm_b to u32 before OR
        //         } else {
        //             imm_b as u32 // Cast the non-negative case too
        //         };
        //         let imm_b_signed = imm_b_u32 as i32; // Final cast to i32
        //         (format!("const/4 v{}, #{}", v_a, imm_b_signed), 1)
        //     }
        //     Opcode::CONST_16 => { // Format 21s: const/16 vAA, #+BBBB
        //         if pc + 1 >= insns.len() { ("invalid const/16".to_string(), 1) } else {
        //             let v_aa = (instruction_unit >> 8) & 0xFF;
        //             let imm_bbbb = insns[pc + 1] as i16; // Read next unit as signed 16-bit literal
        //             (format!("const/16 v{}, #{}", v_aa, imm_bbbb), 2)
        //         }
        //     }
        //     Opcode::CONST_STRING => { // Format 21c: const-string vAA, string@BBBB
        //          if pc + 1 >= insns.len() { ("invalid const-string".to_string(), 1) } else {
        //             let v_aa = (instruction_unit >> 8) & 0xFF;
        //             let string_table_idx = insns[pc + 1] as usize; // Index into string_ids table
        //
        //             // Look up the string offset from string_ids, then the string from string_map
        //             let string_val = if string_table_idx < string_ids.len() {
        //                 let string_offset = string_ids[string_table_idx];
        //                 string_map.get(&string_offset)
        //                     .map(|s| format!("\"{}\"", s.escape_debug())) // Format string literal
        //                     .unwrap_or_else(|| format!("string@(invalid_offset:0x{:x})", string_offset))
        //             } else {
        //                 format!("string@(invalid_index:{})", string_table_idx)
        //             };
        //
        //             (format!("const-string v{}, {}", v_aa, string_val), 2)
        //          }
        //     }
        //     Opcode::CONST_CLASS => { // Format 21c: const-class vAA, type@BBBB
        //          if pc + 1 >= insns.len() { ("invalid const-class".to_string(), 1) } else {
        //             let v_aa = (instruction_unit >> 8) & 0xFF;
        //             let type_idx = insns[pc + 1] as u16; // Type index is in the next unit
        //
        //             let type_name = type_map.get(&(type_idx as u32))
        //                 .map(|s| s.clone())
        //                 .unwrap_or_else(|| format!("type@{}", type_idx));
        //
        //             (format!("const-class v{}, {}", v_aa, type_name), 2)
        //          }
        //     }
        //     Opcode::RETURN_VOID => ("return-void".to_string(), 1), // Format 10x
        //     Opcode::NEW_INSTANCE => { // Format21c
        //         let v_aa = (instruction_unit >> 8) & 0xff;
        //         let type_idx = insns[pc + 1] as u32;
        //
        //         let type_name = type_map.get(&type_idx)
        //             .map(|s| s.clone()) // Clone the string for display
        //             .unwrap_or_else(|| format!("type@{}", type_idx));
        //
        //         (format!("new-instance v{}, {}",v_aa, type_name), 2)
        //     }
        //     _ => {
        //         // For now, just dump the first unit and assume size 1
        //         let hex_dump = format!("0x{:04x}", instruction_unit);
        //         (format!("??? (opcode 0x{:02x}) {}", opcode as u8, hex_dump), 1)
        //
        //
        //     }
        //};

        // Ensure PC doesn't advance beyond the instruction buffer if an instruction claimed
        // more units than available (e.g., due to truncated data)
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

        // Advance PC by the size of the instruction in 16-bit units
        pc += size_units;
    }

    disassembled_instructions
}

// TODO: Add opcode handlers
// TODO: Add helper functions for parsing different instruction formats (21c, 35c, etc.)
// TODO: Implement index resolution (strings, types, fields, methods)
