#![allow(non_snake_case)]

use appcontainer::{Profile};
use super::{add_sid_profile_entry, remove_sid_acl_entry};

use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::shared::ntdef::{NULL};
use winapi::um::fileapi::{ReadFile};
use winapi::um::handleapi::{INVALID_HANDLE_VALUE};
use winapi::um::minwinbase::{LPOVERLAPPED, SECURITY_ATTRIBUTES};
use winapi::um::namedpipeapi::{CreatePipe};
use winapi::um::processthreadsapi::{GetExitCodeProcess, TerminateProcess};
use winapi::um::synchapi::{WaitForSingleObject};
use winapi::um::winbase::{INFINITE, WAIT_OBJECT_0};
use winapi::um::winnt::{GENERIC_EXECUTE, GENERIC_READ, HANDLE};

use std::env;
use std::mem;
use std::path::{PathBuf};

#[cfg(test)]
const KEY_READ_MASK: u32 = 0x00000020;

#[cfg(test)]
fn get_unittest_support_path() -> Option<PathBuf> {
    let mut dir_path = match env::current_exe() {
        Ok(x) => x,
        Err(_) => return None,
    };

    while dir_path.pop() {
        dir_path.push("unittest_support");
        if dir_path.exists() && dir_path.is_dir() {
            return Some(dir_path);
        }
        dir_path.pop();
    }

    None
}

#[cfg(test)]
struct ProfileWrapper {
    name: String,
}

#[cfg(test)]
impl Drop for ProfileWrapper {
    fn drop(&mut self) {
        Profile::remove(&self.name);
    }
}

#[cfg(test)]
struct AclOp {
    path: PathBuf,
    sid: String,
}

#[cfg(test)]
impl AclOp {
    fn add(path: &PathBuf, sid: &str, mask: u32) -> Option<AclOp> {
        if !add_sid_profile_entry(&path, sid, mask) {
            return None;
        }

        Some(AclOp {
                 path: PathBuf::from(path),
                 sid: sid.to_string(),
             })
    }
}

#[cfg(test)]
impl Drop for AclOp {
    fn drop(&mut self) {
        remove_sid_acl_entry(&self.path, &self.sid);
    }
}

// FIXME(andy): This test has some issues
#[allow(unused_variables)]
#[allow(non_snake_case)]
#[ignore]
#[test]
fn test_sandbox_key_read() {
    let result = get_unittest_support_path();
    assert!(!result.is_none());

    let profile_name = String::from("test_default_appjail1");

    let mut child_path = result.unwrap();
    let mut dir_path = child_path.clone();
    child_path.push("sandbox-test.exe");

    dir_path.push("pub");

    let mut key_path = dir_path.clone();
    key_path.push("key2.txt");

    println!("dir_path = {:?}", dir_path);
    println!("key_path = {:?}", key_path);
    println!("Attempting to create AppContainer profile...");

    if let Ok(profile) = Profile::new(&profile_name, child_path.to_str().unwrap()) {
        let wrapper = ProfileWrapper { name: profile_name };

        println!("Setting ACLs for {:} on {:?}", &profile.sid, dir_path);
        let dirAclOp = AclOp::add(&dir_path, &profile.sid, GENERIC_READ | GENERIC_EXECUTE);
        assert!(dirAclOp.is_some());

        println!("Setting ACLs for {:} on {:?}", &profile.sid, key_path);
        let fileAclOp = AclOp::add(&key_path, &profile.sid, GENERIC_READ);
        assert!(fileAclOp.is_some());

        println!("Testing with default privileges");
        let launch_result = profile.launch(INVALID_HANDLE_VALUE,
                                           INVALID_HANDLE_VALUE,
                                           dir_path.to_str().unwrap());
        assert!(launch_result.is_ok());

        let hProcess = launch_result.unwrap();
        assert_eq!(unsafe { WaitForSingleObject(hProcess.raw, INFINITE) },
                   WAIT_OBJECT_0);

        let mut dwExitCode: DWORD = 0 as DWORD;
        assert!(unsafe { GetExitCodeProcess(hProcess.raw, &mut dwExitCode) } != 0);
        println!("ExitCode = {:08x}", dwExitCode);

        assert!((dwExitCode & KEY_READ_MASK) == 0)
    } else {
        println!("Failed to create AppContainer profile");
        assert!(false);
    }
}

#[test]
fn test_profile_sid() {
    {
        let result = Profile::new("default_profile", "INVALID_FILE");
        assert!(result.is_err());
    }

    {
        let mut result = Profile::new("cmd_profile", "\\Windows\\System32\\cmd.exe");
        assert!(result.is_ok());

        let profile = result.unwrap();

        result = Profile::new("cmd_profile", "\\Windows\\System32\\cmd.exe");
        assert!(result.is_ok());

        let same_profile = result.unwrap();
        assert_eq!(profile.sid, same_profile.sid);

        assert!(Profile::remove("cmd_profile"));

        result = Profile::new("cmd_profile1", "\\Windows\\System32\\cmd.exe");
        assert!(result.is_ok());

        let new_profile = result.unwrap();
        assert!(profile.sid != new_profile.sid);
    }
}

#[cfg(test)]
const OUTBOUND_CONNECT_MASK: u32 = 0x00000001;
#[cfg(test)]
const FILE_READ_MASK: u32 = 0x00000002;
#[cfg(test)]
const FILE_WRITE_MASK: u32 = 0x00000004;
#[cfg(test)]
const REGISTRY_READ_MASK: u32 = 0x00000008;
#[cfg(test)]
const REGISTRY_WRITE_MASK: u32 = 0x00000010;

#[allow(unused_variables)]
#[test]
fn test_appcontainer() {
    let result = get_unittest_support_path();
    assert!(!result.is_none());

    let profile_name = String::from("test_default_appjail");

    let mut child_path = result.unwrap();
    let dir_path = child_path.clone();
    child_path.push("sandbox-test.exe");

    println!("dir_path = {:?}", dir_path);
    println!("Attempting to create AppContainer profile...");

    if let Ok(mut profile) = Profile::new(&profile_name, child_path.to_str().unwrap()) {
        let wrapper = ProfileWrapper { name: profile_name };

        {
            println!("Testing with default privileges");
            let launch_result = profile.launch(INVALID_HANDLE_VALUE,
                                               INVALID_HANDLE_VALUE,
                                               dir_path.to_str().unwrap());
            assert!(launch_result.is_ok());

            let hProcess = launch_result.unwrap();
            assert_eq!(unsafe { WaitForSingleObject(hProcess.raw, INFINITE) },
                       WAIT_OBJECT_0);

            let mut dwExitCode: DWORD = 0 as DWORD;
            assert!(unsafe { GetExitCodeProcess(hProcess.raw, &mut dwExitCode) } != 0);

            assert!((dwExitCode & OUTBOUND_CONNECT_MASK) == 0);
            assert!((dwExitCode & FILE_READ_MASK) != 0);
            assert!((dwExitCode & FILE_WRITE_MASK) != 0);
            assert!((dwExitCode & REGISTRY_READ_MASK) == 0);
            assert!((dwExitCode & REGISTRY_WRITE_MASK) != 0);
        }

        println!("Disabling outbound network connections");
        profile.enable_outbound_network(false);

        {
            println!("Testing without outbound network connections");
            let launch_result = profile.launch(INVALID_HANDLE_VALUE,
                                               INVALID_HANDLE_VALUE,
                                               dir_path.to_str().unwrap());
            assert!(launch_result.is_ok());

            let hProcess = launch_result.unwrap();
            assert_eq!(unsafe { WaitForSingleObject(hProcess.raw, INFINITE) },
                       WAIT_OBJECT_0);

            let mut dwExitCode: DWORD = 0 as DWORD;
            assert!(unsafe { GetExitCodeProcess(hProcess.raw, &mut dwExitCode) } != 0);

            assert!((dwExitCode & OUTBOUND_CONNECT_MASK) != 0);
            assert!((dwExitCode & FILE_READ_MASK) != 0);
            assert!((dwExitCode & FILE_WRITE_MASK) != 0);
            assert!((dwExitCode & REGISTRY_READ_MASK) == 0);
            assert!((dwExitCode & REGISTRY_WRITE_MASK) != 0);
        }

        println!("Enabling outbound network connections");
        profile.enable_outbound_network(true);

        println!("Disabling AppContainer");
        profile.enable_debug(true);

        {
            println!("Testing debug mode");
            let launch_result = profile.launch(INVALID_HANDLE_VALUE,
                                               INVALID_HANDLE_VALUE,
                                               dir_path.to_str().unwrap());
            assert!(launch_result.is_ok());

            let hProcess = launch_result.unwrap();
            assert_eq!(unsafe { WaitForSingleObject(hProcess.raw, INFINITE) },
                       WAIT_OBJECT_0);

            let mut dwExitCode: DWORD = 0 as DWORD;
            assert!(unsafe { GetExitCodeProcess(hProcess.raw, &mut dwExitCode) } != 0);

            assert!((dwExitCode & OUTBOUND_CONNECT_MASK) == 0);
            assert!((dwExitCode & FILE_READ_MASK) == 0);
            assert!((dwExitCode & FILE_WRITE_MASK) == 0);
            assert!((dwExitCode & REGISTRY_READ_MASK) == 0);
            assert!((dwExitCode & REGISTRY_WRITE_MASK) == 0);
        }
    } else {
        println!("Failed to create AppContainer profile");
        assert!(false);
    }
}

#[allow(unused_variables)]
#[test]
fn test_stdout_redirect() {
    let result = get_unittest_support_path();
    assert!(!result.is_none());

    let profile_name = String::from("test_default_appjail2");

    let mut child_path = result.unwrap();
    let dir_path = child_path.clone();
    child_path.push("greenhornd.exe");

    let raw_profile = Profile::new(&profile_name, child_path.to_str().unwrap());
    if let Err(x) = raw_profile {
        println!("GLE={:}", x);
    }
    assert!(raw_profile.is_ok());

    let wrapper = ProfileWrapper { name: profile_name };
    let profile = raw_profile.unwrap();

    let mut rChildStdin: HANDLE = 0 as HANDLE;
    let mut wChildStdin: HANDLE = 0 as HANDLE;
    let mut rChildStdout: HANDLE = 0 as HANDLE;
    let mut wChildStdout: HANDLE = 0 as HANDLE;

    let mut saAttr = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: NULL as LPVOID,
        bInheritHandle: 0,
    };

    println!("Creating stdin/stdout anonymous pipes");
    assert!(unsafe {
                CreatePipe(&mut rChildStdout, &mut wChildStdout, &mut saAttr, 0)
            } != 0);
    assert!(unsafe {
                CreatePipe(&mut rChildStdin, &mut wChildStdin, &mut saAttr, 0)
            } != 0);

    {
        println!("Launching AppContainer with redirected stdin/stdout/stderr");
        let launch_result = profile.launch(rChildStdin, wChildStdout, dir_path.to_str().unwrap());
        assert!(launch_result.is_ok());

        let hProcess = launch_result.unwrap();

        let mut dwRead: DWORD = 0 as DWORD;
        let mut buffer: Vec<u8> = Vec::with_capacity(37);

        println!("Reading 37 bytes for testing");
        assert!(unsafe {
                    ReadFile(rChildStdout,
                             buffer.as_mut_ptr() as LPVOID,
                             37,
                             &mut dwRead,
                             mem::transmute::<usize, LPOVERLAPPED>(0))
                } != 0);

        let data;
        unsafe {
            let p = buffer.as_mut_ptr();
            mem::forget(buffer);

            data = Vec::from_raw_parts(p, dwRead as usize, 37);
        }

        let result = String::from_utf8(data);
        assert!(result.is_ok());

        let read_data = result.unwrap();

        println!("Read bytes: {:?}", &read_data);
        assert_eq!(read_data, "Wecome to the Greenhorn CSAW service!");
        assert!(unsafe { TerminateProcess(hProcess.raw, 0xffffffff) } != 0);
    }
}