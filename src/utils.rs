use chrono::{DateTime, Local};
use libc::timeval;
use std::mem;

pub fn struct_to_bytes<T>(s: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(
            (s as *const T) as *const u8,
            mem::size_of::<T>(),
            // It is fine to use size_of because the length of u8 array is also the number of bytes
        )
    }
}

pub fn timeval_to_datetime(tv: timeval) -> DateTime<Local> {
    let seconds = tv.tv_sec as i64;
    let nanoseconds = (tv.tv_usec * 1000) as u32; // microseconds to nanoseconds
    DateTime::from_timestamp(seconds, nanoseconds)
        .unwrap()
        .with_timezone(&Local)
}
