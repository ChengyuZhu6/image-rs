use anyhow::{bail, Result};
use std::fs::File;
use std::os::linux::fs::MetadataExt;
use std::os::unix::io::AsRawFd;

const DEFAULT_MEM_ALIGNMENT: usize = 4096;

enum LockType {
    DEVLOCKREAD = 0,
    DEVLOCKWRITE,
}

enum LockMode {
    DEVLOCKFILE = 0,
    DEVLOCKBDEV,
    DEVLOCKNAME,
}
enum LockHandleUnion {
    BDEV(u32),
    NAME(String),
}

struct CryptLockHandle {
    refcnt: u32,
    flock_fd: i32,
    type_: LockType,
    mode: LockMode,
    u: LockHandleUnion,
}

struct VolumeKey {
    id: i32,
    keylength: usize,
    key_description: String,
    key: String, // Flexible array member
}

#[derive(Default)]
struct Device {
    path: String,
    file_path: String,
    loop_fd: i32,
    ro_dev_fd: i32,
    dev_fd: i32,
    dev_fd_excl: i32,
    lh: Option<CryptLockHandle>,
    o_direct: u32,
    init_done: u32,
    alignment: usize,
    block_size: usize,
    loop_block_size: usize,
}

/**
 *
 * Structure used as parameter for dm-verity device type.
 *
 */
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct CryptParamsVerity {
    pub hash_name: String,
    pub data_device: String,
    pub hash_device: String,
    pub fec_device: String,
    pub salt: String,
    pub salt_size: u32,
    pub hash_type: u32,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_size: u64,
    pub hash_area_offset: u64,
    pub fec_area_offset: u64,
    pub fec_roots: u32,
    pub flags: u32,
}

struct CryptDevice {
    type_: String,
    device: Option<Device>,
    metadata_device: Option<Device>,
    volume_key: Vec<VolumeKey>,
    rng_type: i32,
    compatibility: u32,
    key_in_keyring: u32,
    data_offset: u64,
    metadata_size: u64,
    keyslots_size: u64,
    verity: Option<CryptVerity>,
}

struct CryptVerity {
    hdr: Option<CryptParamsVerity>,
    root_hash: String,
    root_hash_size: u32,
    uuid: String,
    fec_device: Option<Device>,
}

fn device_init(device_path: &str) -> Result<Device> {
    if device_path.is_empty() {
        bail!("Cannot init device for null device path")
    }
    let mut device = Device {
        path: device_path.to_string(),
        loop_fd: -1,
        ro_dev_fd: -1,
        dev_fd: -1,
        dev_fd_excl: -1,
        o_direct: 1,
        ..Default::default()
    };
    let devfd = match File::open(device_path) {
        Ok(file) => file.as_raw_fd(), // File exists, no need to create
        Err(e) => bail!("Cannot create device{}. error = {:?}", device_path, e),
    };

    if devfd < 0 {
        bail!("Device {} does not exist or access denied.", device_path);
    }

    match std::fs::metadata(device_path) {
        Ok(st) => {
            if !st.st_mode() & libc::S_IFBLK == libc::S_IFBLK {
                bail!("Device {} is not compatible.", device_path);
            }
        }
        Err(e) => {
            bail!("Error getting device metadata: {}", e);
        }
    }

    device.alignment = DEFAULT_MEM_ALIGNMENT;

    Ok(device)
}
