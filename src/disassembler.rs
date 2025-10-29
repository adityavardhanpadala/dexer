use crate::types::CodeItem;
use lazy_static::lazy_static;
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
#[allow(non_camel_case_types)] // This convention looks better for opcodes.
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

impl Opcode {
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
            Opcode::IF_LEZ => "if-lex",
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
            Opcode::INVOKE_VIRTUAL => "invoke-virtual",
            Opcode::INVOKE_SUPER => "invoke-super",
            Opcode::INVOKE_DIRECT => "invoke-direct",
            Opcode::INVOKE_STATIC => "invoke-static",
            Opcode::INVOKE_INTERFACE => "invoke-interface",
            Opcode::INVOKE_VIRTUAL_RANGE => "invoke-virtual/range",
            Opcode::INVOKE_SUPER_RANGE => "invoke-super/range",
            Opcode::INVOKE_DIRECT_RANGE => "invoke-direct/range",
            Opcode::INVOKE_STATIC_RANGE => "invoke-static/range",
            Opcode::INVOKE_INTERFACE_RANGE => "invoke-interface/range",
            Opcode::NEG_INT => "neg-int",
            Opcode::NOT_INT => "not-int",
            Opcode::NEG_LONG => "neg-long",
            Opcode::NOT_LONG => "not-long",
            Opcode::NEG_FLOAT => "neg-float",
            Opcode::NEG_DOUBLE => "neg-double",
            Opcode::INT_TO_LONG => "int-to-long",
            Opcode::INT_TO_FLOAT => "int-to-float",
            Opcode::INT_TO_DOUBLE => "int-to-double",
            Opcode::LONG_TO_INT => "long-to-int",
            Opcode::LONG_TO_FLOAT => "long-to-float",
            Opcode::LONG_TO_DOUBLE => "long-to-double",
            Opcode::FLOAT_TO_INT => "float-to-int",
            Opcode::FLOAT_TO_LONG => "float-to-long",
            Opcode::FLOAT_TO_DOUBLE => "float-to-double",
            Opcode::DOUBLE_TO_INT => "double-to-int",
            Opcode::DOUBLE_TO_LONG => "double-to-long",
            Opcode::DOUBLE_TO_FLOAT => "double-to-float",
            Opcode::INT_TO_BYTE => "int-to-byte",
            Opcode::INT_TO_CHAR => "int-to-char",
            Opcode::INT_TO_SHORT => "int-to-short",
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
            Opcode::ADD_LONG => "add-long",
            Opcode::SUB_LONG => "sub-long",
            Opcode::MUL_LONG => "mul-long",
            Opcode::DIV_LONG => "div-long",
            Opcode::REM_LONG => "rem-long",
            Opcode::AND_LONG => "and-long",
            Opcode::OR_LONG => "or-long",
            Opcode::XOR_LONG => "xor-long",
            Opcode::SHL_LONG => "shl-long",
            Opcode::SHR_LONG => "shr-long",
            Opcode::USHR_LONG => "ushr-long",
            Opcode::ADD_FLOAT => "add-float",
            Opcode::SUB_FLOAT => "sub-float",
            Opcode::MUL_FLOAT => "mul-float",
            Opcode::DIV_FLOAT => "div-float",
            Opcode::REM_FLOAT => "rem-float",
            Opcode::ADD_DOUBLE => "add-double",
            Opcode::SUB_DOUBLE => "sub-double",
            Opcode::MUL_DOUBLE => "mul-double",
            Opcode::DIV_DOUBLE => "div-double",
            Opcode::REM_DOUBLE => "rem-double",
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
            Opcode::ADD_LONG_2ADDR => "add-long/2addr",
            Opcode::SUB_LONG_2ADDR => "sub-long/2addr",
            Opcode::MUL_LONG_2ADDR => "mul-long/2addr",
            Opcode::DIV_LONG_2ADDR => "div-long/2addr",
            Opcode::REM_LONG_2ADDR => "rem-long/2addr",
            Opcode::AND_LONG_2ADDR => "and-long/2addr",
            Opcode::OR_LONG_2ADDR => "or-long/2addr",
            Opcode::XOR_LONG_2ADDR => "xor-long/2addr",
            Opcode::SHL_LONG_2ADDR => "shl-long/2addr",
            Opcode::SHR_LONG_2ADDR => "shr-long/2addr",
            Opcode::USHR_LONG_2ADDR => "ushr-long/2addr",
            Opcode::ADD_FLOAT_2ADDR => "add-float/2addr",
            Opcode::SUB_FLOAT_2ADDR => "sub-float/2addr",
            Opcode::MUL_FLOAT_2ADDR => "mul-float/2addr",
            Opcode::DIV_FLOAT_2ADDR => "div-float/2addr",
            Opcode::REM_FLOAT_2ADDR => "rem-float/2addr",
            Opcode::ADD_DOUBLE_2ADDR => "add-double/2addr",
            Opcode::SUB_DOUBLE_2ADDR => "sub-double/2addr",
            Opcode::MUL_DOUBLE_2ADDR => "mul-double/2addr",
            Opcode::DIV_DOUBLE_2ADDR => "div-double/2addr",
            Opcode::REM_DOUBLE_2ADDR => "rem-double/2addr",
            Opcode::ADD_INT_LIT16 => "add-int/lit16",
            Opcode::RSUB_INT => "rsub-int",
            Opcode::MUL_INT_LIT16 => "mul-int/lit16",
            Opcode::DIV_INT_LIT16 => "div-int/lit16",
            Opcode::REM_INT_LIT16 => "rem-int/lit16",
            Opcode::AND_INT_LIT16 => "and-int/lit16",
            Opcode::OR_INT_LIT16 => "or-int/lit16",
            Opcode::XOR_INT_LIT16 => "xor-int/lit16",
            Opcode::ADD_INT_LIT8 => "add-int/lit8",
            Opcode::RSUB_INT_LIT8 => "rsub-int/lit8",
            Opcode::MUL_INT_LIT8 => "mul-int/lit8",
            Opcode::DIV_INT_LIT8 => "div-int/lit8",
            Opcode::REM_INT_LIT8 => "rem-int/lit8",
            Opcode::AND_INT_LIT8 => "and-int/lit8",
            Opcode::OR_INT_LIT8 => "or-int/lit8",
            Opcode::XOR_INT_LIT8 => "xor-int/lit8",
            Opcode::SHL_INT_LIT8 => "shl-int/lit8",
            Opcode::SHR_INT_LIT8 => "shr-int/lit8",
            Opcode::USHR_INT_LIT8 => "ushr-int/lit8",
            Opcode::INVOKE_POLYMORPHIC => "invoke-polymorphic",
            Opcode::INVOKE_POLYMORPHIC_RANGE => "invoke-polymorphic/range",
            Opcode::INVOKE_CUSTOM => "invoke-custom",
            Opcode::INVOKE_CUSTOM_RANGE => "invoke-custom/range",
            Opcode::CONST_METHOD_HANDLE => "const-method-handle",
            Opcode::CONST_METHOD_TYPE => "const-method-type",
            _ => "unknown", // Placeholder for brevity
        }
    }

    pub fn format(&self) -> InstructionFormat {
        match self {
            Opcode::NOP => InstructionFormat::Format10x,
            Opcode::MOVE => InstructionFormat::Format12x,
            Opcode::MOVE_FROM16 => InstructionFormat::Format22x,
            Opcode::MOVE_16 => InstructionFormat::Format32x,
            Opcode::MOVE_WIDE => InstructionFormat::Format12x,
            Opcode::MOVE_WIDE_FROM16 => InstructionFormat::Format22x,
            Opcode::MOVE_WIDE_16 => InstructionFormat::Format32x,
            Opcode::MOVE_OBJECT => InstructionFormat::Format12x,
            Opcode::MOVE_OBJECT_FROM16 => InstructionFormat::Format22x,
            Opcode::MOVE_OBJECT_16 => InstructionFormat::Format32x,
            Opcode::MOVE_RESULT => InstructionFormat::Format11x,
            Opcode::MOVE_RESULT_WIDE => InstructionFormat::Format11x,
            Opcode::MOVE_RESULT_OBJECT => InstructionFormat::Format11x,
            Opcode::MOVE_EXCEPTION => InstructionFormat::Format11x,
            Opcode::RETURN_VOID => InstructionFormat::Format10x,
            Opcode::RETURN => InstructionFormat::Format11x,
            Opcode::RETURN_WIDE => InstructionFormat::Format11x,
            Opcode::RETURN_OBJECT => InstructionFormat::Format11x,
            Opcode::CONST_4 => InstructionFormat::Format11n,
            Opcode::CONST_16 => InstructionFormat::Format21s,
            Opcode::CONST => InstructionFormat::Format31i,
            Opcode::CONST_HIGH16 => InstructionFormat::Format21h,
            Opcode::CONST_WIDE_16 => InstructionFormat::Format21s,
            Opcode::CONST_WIDE_32 => InstructionFormat::Format31i,
            Opcode::CONST_WIDE => InstructionFormat::Format51l,
            Opcode::CONST_WIDE_HIGH16 => InstructionFormat::Format21h,
            Opcode::CONST_STRING => InstructionFormat::Format21c,
            Opcode::CONST_STRING_JUMBO => InstructionFormat::Format31c,
            Opcode::CONST_CLASS => InstructionFormat::Format21c,
            Opcode::MONITOR_ENTER => InstructionFormat::Format11x,
            Opcode::MONITOR_EXIT => InstructionFormat::Format11x,
            Opcode::CHECK_CAST => InstructionFormat::Format21c,
            Opcode::INSTANCE_OF => InstructionFormat::Format22c,
            Opcode::ARRAY_LENGTH => InstructionFormat::Format12x,
            Opcode::NEW_INSTANCE => InstructionFormat::Format21c,
            Opcode::NEW_ARRAY => InstructionFormat::Format22c,
            Opcode::FILLED_NEW_ARRAY => InstructionFormat::Format35c,
            Opcode::FILLED_NEW_ARRAY_RANGE => InstructionFormat::Format3rc,
            Opcode::FILL_ARRAY_DATA => InstructionFormat::Format31t,
            Opcode::THROW => InstructionFormat::Format11x,
            Opcode::GOTO => InstructionFormat::Format10t,
            Opcode::GOTO_16 => InstructionFormat::Format20t,
            Opcode::GOTO_32 => InstructionFormat::Format30t,
            Opcode::PACKED_SWITCH => InstructionFormat::Format31t,
            Opcode::SPARSE_SWITCH => InstructionFormat::Format31t,
            Opcode::CMPL_FLOAT => InstructionFormat::Format23x,
            Opcode::CMPG_FLOAT => InstructionFormat::Format23x,
            Opcode::CMPL_DOUBLE => InstructionFormat::Format23x,
            Opcode::CMPG_DOUBLE => InstructionFormat::Format23x,
            Opcode::CMP_LONG => InstructionFormat::Format23x,
            Opcode::IF_EQ => InstructionFormat::Format22t,
            Opcode::IF_NE => InstructionFormat::Format22t,
            Opcode::IF_LT => InstructionFormat::Format22t,
            Opcode::IF_GE => InstructionFormat::Format22t,
            Opcode::IF_GT => InstructionFormat::Format22t,
            Opcode::IF_LE => InstructionFormat::Format22t,
            Opcode::IF_EQZ => InstructionFormat::Format21t,
            Opcode::IF_NEZ => InstructionFormat::Format21t,
            Opcode::IF_LTZ => InstructionFormat::Format21t,
            Opcode::IF_GEZ => InstructionFormat::Format21t,
            Opcode::IF_GTZ => InstructionFormat::Format21t,
            Opcode::IF_LEZ => InstructionFormat::Format21t,
            Opcode::AGET => InstructionFormat::Format23x,
            Opcode::AGET_WIDE => InstructionFormat::Format23x,
            Opcode::AGET_OBJECT => InstructionFormat::Format23x,
            Opcode::AGET_BOOLEAN => InstructionFormat::Format23x,
            Opcode::AGET_BYTE => InstructionFormat::Format23x,
            Opcode::AGET_CHAR => InstructionFormat::Format23x,
            Opcode::AGET_SHORT => InstructionFormat::Format23x,
            Opcode::APUT => InstructionFormat::Format23x,
            Opcode::APUT_WIDE => InstructionFormat::Format23x,
            Opcode::APUT_OBJECT => InstructionFormat::Format23x,
            Opcode::APUT_BOOLEAN => InstructionFormat::Format23x,
            Opcode::APUT_BYTE => InstructionFormat::Format23x,
            Opcode::APUT_CHAR => InstructionFormat::Format23x,
            Opcode::APUT_SHORT => InstructionFormat::Format23x,
            Opcode::IGET => InstructionFormat::Format22c,
            Opcode::IGET_WIDE => InstructionFormat::Format22c,
            Opcode::IGET_OBJECT => InstructionFormat::Format22c,
            Opcode::IGET_BOOLEAN => InstructionFormat::Format22c,
            Opcode::IGET_BYTE => InstructionFormat::Format22c,
            Opcode::IGET_CHAR => InstructionFormat::Format22c,
            Opcode::IGET_SHORT => InstructionFormat::Format22c,
            Opcode::IPUT => InstructionFormat::Format22c,
            Opcode::IPUT_WIDE => InstructionFormat::Format22c,
            Opcode::IPUT_OBJECT => InstructionFormat::Format22c,
            Opcode::IPUT_BOOLEAN => InstructionFormat::Format22c,
            Opcode::IPUT_BYTE => InstructionFormat::Format22c,
            Opcode::IPUT_CHAR => InstructionFormat::Format22c,
            Opcode::IPUT_SHORT => InstructionFormat::Format22c,
            Opcode::SGET => InstructionFormat::Format21c,
            Opcode::SGET_WIDE => InstructionFormat::Format21c,
            Opcode::SGET_OBJECT => InstructionFormat::Format21c,
            Opcode::SGET_BOOLEAN => InstructionFormat::Format21c,
            Opcode::SGET_BYTE => InstructionFormat::Format21c,
            Opcode::SGET_CHAR => InstructionFormat::Format21c,
            Opcode::SGET_SHORT => InstructionFormat::Format21c,
            Opcode::SPUT => InstructionFormat::Format21c,
            Opcode::SPUT_WIDE => InstructionFormat::Format21c,
            Opcode::SPUT_OBJECT => InstructionFormat::Format21c,
            Opcode::SPUT_BOOLEAN => InstructionFormat::Format21c,
            Opcode::SPUT_BYTE => InstructionFormat::Format21c,
            Opcode::SPUT_CHAR => InstructionFormat::Format21c,
            Opcode::SPUT_SHORT => InstructionFormat::Format21c,
            Opcode::INVOKE_VIRTUAL => InstructionFormat::Format35c,
            Opcode::INVOKE_SUPER => InstructionFormat::Format35c,
            Opcode::INVOKE_DIRECT => InstructionFormat::Format35c,
            Opcode::INVOKE_STATIC => InstructionFormat::Format35c,
            Opcode::INVOKE_INTERFACE => InstructionFormat::Format35c,
            Opcode::INVOKE_VIRTUAL_RANGE => InstructionFormat::Format3rc,
            Opcode::INVOKE_SUPER_RANGE => InstructionFormat::Format3rc,
            Opcode::INVOKE_DIRECT_RANGE => InstructionFormat::Format3rc,
            Opcode::INVOKE_STATIC_RANGE => InstructionFormat::Format3rc,
            Opcode::INVOKE_INTERFACE_RANGE => InstructionFormat::Format3rc,
            Opcode::NEG_INT => InstructionFormat::Format12x,
            Opcode::NOT_INT => InstructionFormat::Format12x,
            Opcode::NEG_LONG => InstructionFormat::Format12x,
            Opcode::NOT_LONG => InstructionFormat::Format12x,
            Opcode::NEG_FLOAT => InstructionFormat::Format12x,
            Opcode::NEG_DOUBLE => InstructionFormat::Format12x,
            Opcode::INT_TO_LONG => InstructionFormat::Format12x,
            Opcode::INT_TO_FLOAT => InstructionFormat::Format12x,
            Opcode::INT_TO_DOUBLE => InstructionFormat::Format12x,
            Opcode::LONG_TO_INT => InstructionFormat::Format12x,
            Opcode::LONG_TO_FLOAT => InstructionFormat::Format12x,
            Opcode::LONG_TO_DOUBLE => InstructionFormat::Format12x,
            Opcode::FLOAT_TO_INT => InstructionFormat::Format12x,
            Opcode::FLOAT_TO_LONG => InstructionFormat::Format12x,
            Opcode::FLOAT_TO_DOUBLE => InstructionFormat::Format12x,
            Opcode::DOUBLE_TO_INT => InstructionFormat::Format12x,
            Opcode::DOUBLE_TO_LONG => InstructionFormat::Format12x,
            Opcode::DOUBLE_TO_FLOAT => InstructionFormat::Format12x,
            Opcode::INT_TO_BYTE => InstructionFormat::Format12x,
            Opcode::INT_TO_CHAR => InstructionFormat::Format12x,
            Opcode::INT_TO_SHORT => InstructionFormat::Format12x,
            Opcode::ADD_INT => InstructionFormat::Format23x,
            Opcode::SUB_INT => InstructionFormat::Format23x,
            Opcode::MUL_INT => InstructionFormat::Format23x,
            Opcode::DIV_INT => InstructionFormat::Format23x,
            Opcode::REM_INT => InstructionFormat::Format23x,
            Opcode::AND_INT => InstructionFormat::Format23x,
            Opcode::OR_INT => InstructionFormat::Format23x,
            Opcode::XOR_INT => InstructionFormat::Format23x,
            Opcode::SHL_INT => InstructionFormat::Format23x,
            Opcode::SHR_INT => InstructionFormat::Format23x,
            Opcode::USHR_INT => InstructionFormat::Format23x,
            Opcode::ADD_LONG => InstructionFormat::Format23x,
            Opcode::SUB_LONG => InstructionFormat::Format23x,
            Opcode::MUL_LONG => InstructionFormat::Format23x,
            Opcode::DIV_LONG => InstructionFormat::Format23x,
            Opcode::REM_LONG => InstructionFormat::Format23x,
            Opcode::AND_LONG => InstructionFormat::Format23x,
            Opcode::OR_LONG => InstructionFormat::Format23x,
            Opcode::XOR_LONG => InstructionFormat::Format23x,
            Opcode::SHL_LONG => InstructionFormat::Format23x,
            Opcode::SHR_LONG => InstructionFormat::Format23x,
            Opcode::USHR_LONG => InstructionFormat::Format23x,
            Opcode::ADD_FLOAT => InstructionFormat::Format23x,
            Opcode::SUB_FLOAT => InstructionFormat::Format23x,
            Opcode::MUL_FLOAT => InstructionFormat::Format23x,
            Opcode::DIV_FLOAT => InstructionFormat::Format23x,
            Opcode::REM_FLOAT => InstructionFormat::Format23x,
            Opcode::ADD_DOUBLE => InstructionFormat::Format23x,
            Opcode::SUB_DOUBLE => InstructionFormat::Format23x,
            Opcode::MUL_DOUBLE => InstructionFormat::Format23x,
            Opcode::DIV_DOUBLE => InstructionFormat::Format23x,
            Opcode::REM_DOUBLE => InstructionFormat::Format23x,
            Opcode::ADD_INT_2ADDR => InstructionFormat::Format12x,
            Opcode::SUB_INT_2ADDR => InstructionFormat::Format12x,
            Opcode::MUL_INT_2ADDR => InstructionFormat::Format12x,
            Opcode::DIV_INT_2ADDR => InstructionFormat::Format12x,
            Opcode::REM_INT_2ADDR => InstructionFormat::Format12x,
            Opcode::AND_INT_2ADDR => InstructionFormat::Format12x,
            Opcode::OR_INT_2ADDR => InstructionFormat::Format12x,
            Opcode::XOR_INT_2ADDR => InstructionFormat::Format12x,
            Opcode::SHL_INT_2ADDR => InstructionFormat::Format12x,
            Opcode::SHR_INT_2ADDR => InstructionFormat::Format12x,
            Opcode::USHR_INT_2ADDR => InstructionFormat::Format12x,
            Opcode::ADD_LONG_2ADDR => InstructionFormat::Format12x,
            Opcode::SUB_LONG_2ADDR => InstructionFormat::Format12x,
            Opcode::MUL_LONG_2ADDR => InstructionFormat::Format12x,
            Opcode::DIV_LONG_2ADDR => InstructionFormat::Format12x,
            Opcode::REM_LONG_2ADDR => InstructionFormat::Format12x,
            Opcode::AND_LONG_2ADDR => InstructionFormat::Format12x,
            Opcode::OR_LONG_2ADDR => InstructionFormat::Format12x,
            Opcode::XOR_LONG_2ADDR => InstructionFormat::Format12x,
            Opcode::SHL_LONG_2ADDR => InstructionFormat::Format12x,
            Opcode::SHR_LONG_2ADDR => InstructionFormat::Format12x,
            Opcode::USHR_LONG_2ADDR => InstructionFormat::Format12x,
            Opcode::ADD_FLOAT_2ADDR => InstructionFormat::Format12x,
            Opcode::SUB_FLOAT_2ADDR => InstructionFormat::Format12x,
            Opcode::MUL_FLOAT_2ADDR => InstructionFormat::Format12x,
            Opcode::DIV_FLOAT_2ADDR => InstructionFormat::Format12x,
            Opcode::REM_FLOAT_2ADDR => InstructionFormat::Format12x,
            Opcode::ADD_DOUBLE_2ADDR => InstructionFormat::Format12x,
            Opcode::SUB_DOUBLE_2ADDR => InstructionFormat::Format12x,
            Opcode::MUL_DOUBLE_2ADDR => InstructionFormat::Format12x,
            Opcode::DIV_DOUBLE_2ADDR => InstructionFormat::Format12x,
            Opcode::REM_DOUBLE_2ADDR => InstructionFormat::Format12x,
            Opcode::ADD_INT_LIT16 => InstructionFormat::Format22s,
            Opcode::RSUB_INT => InstructionFormat::Format22s,
            Opcode::MUL_INT_LIT16 => InstructionFormat::Format22s,
            Opcode::DIV_INT_LIT16 => InstructionFormat::Format22s,
            Opcode::REM_INT_LIT16 => InstructionFormat::Format22s,
            Opcode::AND_INT_LIT16 => InstructionFormat::Format22s,
            Opcode::OR_INT_LIT16 => InstructionFormat::Format22s,
            Opcode::XOR_INT_LIT16 => InstructionFormat::Format22s,
            Opcode::ADD_INT_LIT8 => InstructionFormat::Format22b,
            Opcode::RSUB_INT_LIT8 => InstructionFormat::Format22b,
            Opcode::MUL_INT_LIT8 => InstructionFormat::Format22b,
            Opcode::DIV_INT_LIT8 => InstructionFormat::Format22b,
            Opcode::REM_INT_LIT8 => InstructionFormat::Format22b,
            Opcode::AND_INT_LIT8 => InstructionFormat::Format22b,
            Opcode::OR_INT_LIT8 => InstructionFormat::Format22b,
            Opcode::XOR_INT_LIT8 => InstructionFormat::Format22b,
            Opcode::SHL_INT_LIT8 => InstructionFormat::Format22b,
            Opcode::SHR_INT_LIT8 => InstructionFormat::Format22b,
            Opcode::USHR_INT_LIT8 => InstructionFormat::Format22b,
            Opcode::INVOKE_POLYMORPHIC => InstructionFormat::Format45cc,
            Opcode::INVOKE_POLYMORPHIC_RANGE => InstructionFormat::Format4rcc,
            Opcode::INVOKE_CUSTOM => InstructionFormat::Format35c,
            Opcode::INVOKE_CUSTOM_RANGE => InstructionFormat::Format3rc,
            Opcode::CONST_METHOD_HANDLE => InstructionFormat::Format21c,
            Opcode::CONST_METHOD_TYPE => InstructionFormat::Format21c,
        }
    }
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        unsafe { std::mem::transmute(value) }
    }
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
        let opcode = Opcode::from(instruction_unit as u8); // Low byte is the primary opcode

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
            },
            InstructionFormat::Format21s => {
                // op vAA, #+BBBB
                let v_aa = (instruction_unit >> 8) & 0x0F;
                let imm = insns[pc + 1];
                (format!("{} v{}, #+{}", name, v_aa, imm), 2)
            },
            InstructionFormat::Format21h => {
                // op vAA, #+BBBB0000
                // op vAA, #+BBBB000000000000
                let v_aa = (instruction_unit >> 8) & 0x0F;
                let imm = insns[pc + 1];
                (format!("{} v{}, #+{}", name, v_aa, imm), 2)
            },
            InstructionFormat::Format21c => {
                let v_aa = (instruction_unit >> 8) & 0x0F;
                let bbbb = insns[pc + 1];

                (format!("{} v{}, <type,field,met,proto,string>@{}", name, v_aa, bbbb), 2)
            },
            InstructionFormat::Format23x => {
                // byte 1 AA|op
                // byte 2 CC|BB
                let v_aa = (instruction_unit >> 8) & 0x0F;
                let v_bb = insns[pc + 1] >> 8;
                let v_cc = insns[pc + 1] & 0xFF;

                (format!("{} v{}, v{}, v{}", name, v_aa, v_bb, v_cc), 2)

            },
            InstructionFormat::Format22b => (format!("{}", name,), 2),
            InstructionFormat::Format22t => (format!("{}", name,), 2),
            InstructionFormat::Format22s => (format!("{}", name,), 2),
            InstructionFormat::Format22c => (format!("{}", name,), 2),
            InstructionFormat::Format22cs => (format!("{}", name,), 2),
            InstructionFormat::Format30t => (format!("{}", name,), 3),
            InstructionFormat::Format32x => (format!("{}", name,), 3),
            InstructionFormat::Format31i => (format!("{}", name,), 3),
            InstructionFormat::Format31t => (format!("{}", name,), 3),
            InstructionFormat::Format31c => (format!("{}", name,), 3),
            InstructionFormat::Format35c => (format!("{}", name,), 3),
            InstructionFormat::Format35ms => (format!("{}", name,), 3),
            InstructionFormat::Format35mi => (format!("{}", name,), 3),
            InstructionFormat::Format3rc => (format!("{}", name,), 3),
            InstructionFormat::Format3rms => (format!("{}", name,), 3),
            InstructionFormat::Format3rmi => (format!("{}", name,), 3),
            InstructionFormat::Format45cc => (format!("{}", name,), 4),
            InstructionFormat::Format4rcc => (format!("{}", name,), 4),
            InstructionFormat::Format51l => (format!("{}", name,), 5),
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
