// 8-bit integers
type byte = i8;    // 8-bit signed int
type ubyte = u8;   // 8-bit unsigned int

// 16-bit integers (little-endian)
type short = i16;  // 16-bit signed int
type ushort = u16; // 16-bit unsigned int

// 32-bit integers (little-endian)
type int = i32;    // 32-bit signed int
type uint = u32;   // 32-bit unsigned int

// 64-bit integers (little-endian)
type long = i64;   // 64-bit signed int
type ulong = u64;  // 64-bit unsigned int


#[repr(C)]
pub struct StringDataItem<'a> {
    pub size: u16,
    pub data: &'a [u8]
}
