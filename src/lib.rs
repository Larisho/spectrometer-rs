use winapi::um::processthreadsapi::GetSystemTimes;
use winapi::um::sysinfoapi::{GetNativeSystemInfo, GlobalMemoryStatusEx, GetTickCount64, MEMORYSTATUSEX, SYSTEM_INFO /*, GetVersion */};
use winapi::um::fileapi::{GetDiskFreeSpaceExW, GetLogicalDriveStringsW};
use winapi::um::winnt::{ULARGE_INTEGER, WCHAR};
use winapi::um::winbase::{GetComputerNameW, GetUserNameW};
use winapi::shared::minwindef::{FILETIME /*, HIWORD, LOWORD, HIBYTE, LOBYTE */};
use winapi::shared::lmcons::UNLEN;
use std::{time, thread, mem, env};
use std::io::{Error, ErrorKind};

#[derive(Debug, Clone)]
/// A `struct` containing relevant CPU values
pub struct CPU {
    pub user: f32,
    pub system: f32,
    pub idle: f32,
    pub percent: f32
}

#[derive(Debug, Clone)]
/// A `struct` containing relevant FileSystem values
pub struct FS {
    pub mount: String,
    pub free: u64,
    pub avail: u64,
    pub total: u64
}

#[derive(Debug, Clone)]
/// A `struct` containing relevant Memory values
pub struct Mem {
    pub load: f32,
    pub total: u64,
    pub used: u64,
    pub free: u64
}

/// Gets the CPU load. Currently, on Windows, this requires sleeping for a particular duration
/// (default is 250 millis--use `cpu_load_with_duration` to specify sleep time) to get an estimate
/// on the CPU load.
///
/// Ideally, this will change in the future to not require sleeping like in Linux
pub fn cpu_load() -> Result<CPU, Error> {
    cpu_load_with_duration(time::Duration::from_millis(250))
}

// TODO(gab): Contemplate changing to use Performance Counters
/// Gets the CPU load. Currently, on Windows, this requires sleeping for `duration` amount of time to
/// get an estimate on the CPU load.
pub fn cpu_load_with_duration(duration: time::Duration) -> Result<CPU, Error> { 
    let mut base_idle_time = FILETIME { dwHighDateTime: 0, dwLowDateTime: 0 };
    let mut base_kernel_time = FILETIME { dwHighDateTime: 0, dwLowDateTime: 0 };
    let mut base_user_time = FILETIME { dwHighDateTime: 0, dwLowDateTime: 0 };

    let mut idle_time = FILETIME { dwHighDateTime: 0, dwLowDateTime: 0 };
    let mut kernel_time = FILETIME { dwHighDateTime: 0, dwLowDateTime: 0 };
    let mut user_time = FILETIME { dwHighDateTime: 0, dwLowDateTime: 0 };

    if unsafe { GetSystemTimes(&mut base_idle_time, &mut base_kernel_time, &mut base_user_time) } == 0 {
        return Err(Error::last_os_error())
    }
    thread::sleep(duration);

    if unsafe { GetSystemTimes(&mut idle_time, &mut kernel_time, &mut user_time) } == 0 {
        return Err(Error::last_os_error())
    }

    let idle_time = filetime2u64(&idle_time) - filetime2u64(&base_idle_time);
    let kernel_time = filetime2u64(&kernel_time) - filetime2u64(&base_kernel_time);
    let user_time = filetime2u64(&user_time) - filetime2u64(&base_user_time);
    let total = kernel_time + user_time;
    
    let mut percent = ((kernel_time - idle_time) + user_time) as f32 / (kernel_time + user_time) as f32;

    if percent <= 0.5 {
        percent = percent * 2.0;
    }

    Ok(CPU {
        user: user_time as f32 / total as f32,
        system: (kernel_time - idle_time) as f32 / total as f32,
        idle: idle_time as f32 / total as f32,
        percent: percent
    })
}

fn filetime2u64(filetime: &FILETIME) -> u64 {
    ((filetime.dwHighDateTime as u64) << 32) | filetime.dwLowDateTime as u64
}

/// Gets a `Vec<String>` of drive names.
///
/// This function's name will most likely change in the future to use a more generic term
/// for `drive` (mostly because the term `mount` is more widely used).
pub fn get_drives() -> Result<Vec<String>, Error> {
    let buffer_size = 512;
    let mut buffer: Vec<WCHAR> = Vec::with_capacity(buffer_size);

    match unsafe { GetLogicalDriveStringsW((buffer_size - 1) as u32, buffer.as_mut_ptr()) } {
        0 => Err(Error::last_os_error()),
        bytes_read @ _ if bytes_read <= (buffer_size - 1) as u32 => {
            unsafe { buffer.set_len(bytes_read as usize) };
            
            let mut vecs: Vec<Vec<u16>> = Vec::new();
            let mut tmp: Vec<u16> = Vec::new();

            for char in buffer.iter() {
                if *char == 0 {
                    if tmp.len() == 0 {
                        break;
                    }

                    vecs.push(tmp.clone());
                    tmp.clear();
                } else {
                    tmp.push(*char);
                }
            }

            if !tmp.is_empty() {
                vecs.push(tmp.clone());
            }

            Ok(vecs
               .iter()
               .map(|val| String::from_utf16(val).unwrap())
               .collect())
        },
        _ => Err(
            Error::new(
                ErrorKind::Other,
                "Too many drives found. This error is technically impossible to hit. Please report"
            )
        )
    }
}

/// Gets File System information based on the drive provided
pub fn drive_details(drive: String) -> Result<FS, Error> {
    let u16_drive = str2u16(&drive).as_ptr();
    let mut avail: ULARGE_INTEGER = unsafe { mem::zeroed() };
    let mut free: ULARGE_INTEGER = unsafe { mem::zeroed() };
    let mut total: ULARGE_INTEGER = unsafe { mem::zeroed() };
    
    if unsafe { GetDiskFreeSpaceExW(u16_drive, &mut avail, &mut total, &mut free) } == 0 {
        return Err(Error::last_os_error())
    }

    Ok(FS {
        mount: drive,
        avail: unsafe { *avail.QuadPart() },
        free: unsafe { *free.QuadPart() },
        total: unsafe { *total.QuadPart() }
    })
}

fn str2u16(string: &String) -> Vec<u16> {
    let mut v: Vec<u16> = string.encode_utf16().collect();
    v.push(0);
    v
}
/// Gets the machine's current Memory statistics.
pub fn memory_details() -> Result<Mem, Error> {
    let mut memory: MEMORYSTATUSEX = MEMORYSTATUSEX {
        dwLength: mem::size_of::<MEMORYSTATUSEX>() as u32,
        dwMemoryLoad: 0,
        ullTotalPhys: 0,
        ullAvailPhys: 0,
        ullTotalPageFile: 0,
        ullAvailPageFile: 0,
        ullTotalVirtual: 0,
        ullAvailVirtual: 0,
        ullAvailExtendedVirtual: 0
    };

    if unsafe { GlobalMemoryStatusEx(&mut memory) } == 0 {
        return Err(Error::last_os_error())
    }

    Ok(Mem {
        load: memory.dwMemoryLoad as f32 / 100.0,
        total: memory.ullTotalPhys,
        used: memory.ullTotalPhys - memory.ullAvailPhys,
        free: memory.ullAvailPhys
    })
}

/// Gets the uptime in seconds
pub fn uptime() -> u64 {
    let ticks = unsafe { GetTickCount64() };
    
    ticks / 1000
}

/// Gets the number of logical CPUs the machine has
pub fn logical_cpus() -> u32 {
    let mut system_info = SYSTEM_INFO {
        u: unsafe { mem::zeroed() },
        dwPageSize: 0,
        lpMinimumApplicationAddress: std::ptr::null_mut(),
        lpMaximumApplicationAddress: std::ptr::null_mut(),
        dwActiveProcessorMask: 0,
        dwNumberOfProcessors: 0,
        dwProcessorType: 0,
        dwAllocationGranularity: 0,
        wProcessorLevel: 0,
        wProcessorRevision: 0
    };

    unsafe { GetNativeSystemInfo(&mut system_info) };

    system_info.dwNumberOfProcessors
}

/// Gets the machine's architecture
pub fn arch() -> String {
    let mut system_info = SYSTEM_INFO {
        u: unsafe { mem::zeroed() },
        dwPageSize: 0,
        lpMinimumApplicationAddress: std::ptr::null_mut(),
        lpMaximumApplicationAddress: std::ptr::null_mut(),
        dwActiveProcessorMask: 0,
        dwNumberOfProcessors: 0,
        dwProcessorType: 0,
        dwAllocationGranularity: 0,
        wProcessorLevel: 0,
        wProcessorRevision: 0
    };

    unsafe { GetNativeSystemInfo(&mut system_info) };

    match unsafe { system_info.u.s().wProcessorArchitecture } {
        0 => String::from("x86"),
        5 => String::from("ARM"),
        6 => String::from("Intel Itanium-based"),
        9 => String::from("x64"),
        12 => String::from("ARM64"),
        _ => String::from("Uknown architecture")
    }
}

/// Gets the machine's hostname
pub fn hostname() -> Result<String, Error> {
    let mut buffer_size = 62;
    let mut buffer = Vec::with_capacity(buffer_size);

    if unsafe { GetComputerNameW(buffer.as_mut_ptr(), &mut (buffer_size as u32)) } == 0 {
        return Err(Error::last_os_error())
    }

    unsafe { buffer.set_len(buffer_size) };
    
    for (i, val) in buffer.iter().enumerate() {
        if *val == 0 {
            buffer_size = i;
            break;
        }
    }

    unsafe { buffer.set_len(buffer_size) };
    
    Ok(String::from_utf16(&buffer).unwrap())
}

/// Gets the current user's username without relying on environment variables
pub fn username() -> Result<String, Error> {
    let mut buffer_size = (UNLEN + 1) as usize;
    let mut buffer = Vec::with_capacity(buffer_size);
    
    if unsafe { GetUserNameW(buffer.as_mut_ptr(), &mut (buffer_size as u32)) } == 0 {
        return Err(Error::last_os_error())
    }

    unsafe { buffer.set_len(buffer_size) };
    
    for (i, val) in buffer.iter().enumerate() {
        if *val == 0 {
            buffer_size = i;
            break;
        }
    }

    unsafe { buffer.set_len(buffer_size) };
    
    Ok(String::from_utf16(&buffer).unwrap())
}

/// Gets the OS name. Currently just returning a `String::from("Windows")` because this library only
/// works on Windows for the time being.
pub fn os_name() -> String {
    String::from("Windows")
}

// fn os_version() -> String {
//     let version;
//     let major;
//     let minor;
//     let mut build = 0;

//     version = unsafe { GetVersion() };
//     major = LOBYTE(LOWORD(version)) as u32;
//     minor = HIBYTE(LOWORD(version)) as u32;

//     if version > 0x80000000 {
//         build = HIWORD(version) as u32;
//     }
// }

#[cfg(test)]
mod windows_tests {
    use super::*;

    #[test]
    fn test_cpu_ok() {
        let load = cpu_load();
        assert!(load.is_ok(), format!("Load returned exception {}", load.err().unwrap()));
    }

    #[test]
    fn test_cpu_sum_100() {
        let load = cpu_load().unwrap();
        assert_eq!((load.user + load.system + load.idle), 1.0, "Load doesn't add up to 100%");
    }

    #[test]
    fn test_sleeps_duration() {
        let duration = time::Duration::from_millis(500);
        let inst = time::Instant::now();
        let _ = cpu_load_with_duration(duration);
        let stamp = inst.elapsed();
        assert!(stamp >= duration && stamp <= (duration + time::Duration::from_millis(2)));
    }

    #[test]
    fn test_drive_info_ok() {
        let drive = drive_details(String::from("C:\\"));
        assert!(drive.is_ok(), format!("GetDriveDetails return exception {}", drive.err().unwrap()));
    }

    #[test]
    fn test_get_all_drives_ok() {
        let drives = get_drives();
        assert!(drives.is_ok(), format!("GetDrives return expection {}", drives.err().unwrap()));
    }

    #[test]
    fn test_get_all_drive_info() {
        let drives = get_drives().ok().unwrap();
        let res: Vec<FS> = drives
            .iter()
            .map(|val| drive_details(val.to_string()).ok().unwrap())
            .collect();

        assert_eq!(drives.len(), res.len());
        drives
            .iter()
            .zip(res.iter())
            .for_each(|(drive, fs)| assert_eq!(*drive, fs.mount));
    }

    #[test]
    fn test_memory_details_ok() {
        let mem = memory_details();
        assert!(mem.is_ok());
        
        let mem = mem.ok().unwrap();
        assert_eq!(mem.free + mem.used, mem.total);

        // NOTE(gab): Attempted rounding through casting
        assert_eq!(
            (((mem.used as f32 / mem.total as f32) * 100.0) as i32) as f32 / 100.0,
            mem.load
        );
    }

    #[test]
    fn test_uptime_ok() {
        let res = uptime();
        assert_ne!(res, 0);
    }

    #[test]
    fn test_logical_cpus() {
        let res = logical_cpus();
        assert_ne!(res, 0);
        assert_eq!(res.to_string(), env::var("NUMBER_OF_PROCESSORS").unwrap());
    }

    #[test]
    fn test_hostname() {
        let res = hostname();
        assert!(res.is_ok(), format!("Hostname returned exception {}", res.err().unwrap()));
        
        let res = res.ok().unwrap();
        assert_ne!(res.len(), 0, "Hostname empty");
        assert_eq!(env::var("COMPUTERNAME").unwrap(), res);
    }

    #[test]
    fn test_username() {
        let res = username();
        assert!(res.is_ok(), format!("Username returned exception {}", res.err().unwrap()));
        
        let res = res.ok().unwrap();
        assert_ne!(res.len(), 0, "Username empty");
        assert_eq!(env::var("USERNAME").unwrap(), res);
    }

    #[test]
    fn test_os_name() {
        assert_eq!(os_name(), "Windows");
    }

    // #[test]
    // fn test_os_version() {
    //     let res = os_version();

    //     println!("osver: {}", res);

    //     assert_ne!(res, "0");
    // }

    #[test]
    fn test_arch() {
        println!("Arch {}", arch());
    }
}
