#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![cfg(windows)]

#[allow(unused_imports)]
use log::*;

use winapi::shared::basetsd::{SIZE_T, PSIZE_T};
use winapi::shared::minwindef::{DWORD, LPBYTE, LPVOID, WORD};
use winapi::shared::ntdef::{PVOID, NULL};
use winapi::shared::winerror::{ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, HRESULT_FROM_WIN32};
use winapi::um::errhandlingapi::{GetLastError};
use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle, SetHandleInformation};
use winapi::um::minwinbase::{LPSECURITY_ATTRIBUTES};
use winapi::um::processthreadsapi::{LPPROC_THREAD_ATTRIBUTE_LIST, LPSTARTUPINFOW, PPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, STARTUPINFOW, CreateProcessW, InitializeProcThreadAttributeList, UpdateProcThreadAttribute};
use winapi::um::securitybaseapi::{FreeSid};
use winapi::um::userenv::{CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName};
use winapi::um::winbase::{EXTENDED_STARTUPINFO_PRESENT, HANDLE_FLAG_INHERIT, LPSTARTUPINFOEXW, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOEXW};
use winapi::um::winnt::{HANDLE, HRESULT, LPWSTR, PSECURITY_CAPABILITIES, PSID, PSID_AND_ATTRIBUTES, SE_GROUP_ENABLED, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES};
use winapi::um::winuser::{SW_HIDE};

use windows_acl::helper::{string_to_sid, sid_to_string};

use utils::{HandlePtr};

use std::path::Path;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::iter::once;
use std::mem;

#[allow(dead_code)]
pub struct Profile {
    profile: String,
    childPath: String,
    outboundNetwork: bool,
    debug: bool,
    pub sid: String,
}

#[allow(dead_code)]
impl Profile {
    pub fn new(profile: &str, path: &str) -> Result<Profile, HRESULT> {
        let mut pSid: PSID = NULL as PSID;
        let profile_name: Vec<u16> = OsStr::new(profile)
            .encode_wide()
            .chain(once(0))
            .collect();

        let path_obj = Path::new(path);
        if !path_obj.exists() || !path_obj.is_file() {
            return Err(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND));
        }

        let mut hr = unsafe {
            CreateAppContainerProfile(profile_name.as_ptr(),
                                      profile_name.as_ptr(),
                                      profile_name.as_ptr(),
                                      NULL as PSID_AND_ATTRIBUTES,
                                      0 as DWORD,
                                      &mut pSid)
        };

        if hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) {
            hr = unsafe {
                DeriveAppContainerSidFromAppContainerName(profile_name.as_ptr(), &mut pSid)
            };
            if hr != (ERROR_SUCCESS as HRESULT) {
                return Err(hr);
            }
        }

        let string_sid = match sid_to_string(pSid) {
            Ok(x) => x,
            Err(x) => return Err(x as HRESULT),
        };

        unsafe { FreeSid(pSid) };

        Ok(Profile {
               profile: profile.to_string(),
               childPath: path.to_string(),
               outboundNetwork: true,
               debug: false,
               sid: string_sid,
           })
    }

    pub fn remove(profile: &str) -> bool {
        let profile_name: Vec<u16> = OsStr::new(profile)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut pSid: PSID = 0 as PSID;

        let mut hr = unsafe {
            DeriveAppContainerSidFromAppContainerName(profile_name.as_ptr(), &mut pSid)
        };

        if hr == (ERROR_SUCCESS as HRESULT) {
            hr = unsafe { DeleteAppContainerProfile(profile_name.as_ptr()) };
            return hr == (ERROR_SUCCESS as HRESULT);
        }

        false
    }

    pub fn enable_outbound_network(&mut self, has_outbound_network: bool) {
        self.outboundNetwork = has_outbound_network;
    }

    pub fn enable_debug(&mut self, is_debug: bool) {
        self.debug = is_debug;
    }

    pub fn launch(&self, stdin: HANDLE, stdout: HANDLE, dirPath: &str) -> Result<HandlePtr, DWORD> {
        let network_allow_sid = string_to_sid("S-1-15-3-1")?;
        let sid = string_to_sid(&self.sid)?;
        let mut capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: sid.as_ptr() as PSID,
            Capabilities: NULL as PSID_AND_ATTRIBUTES,
            CapabilityCount: 0,
            Reserved: 0,
        };
        let mut attrs;
        let mut si = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: 0 as DWORD,
                lpReserved: NULL as LPWSTR,
                lpDesktop: NULL as LPWSTR,
                lpTitle: NULL as LPWSTR,
                dwX: 0 as DWORD,
                dwY: 0 as DWORD,
                dwXSize: 0 as DWORD,
                dwYSize: 0 as DWORD,
                dwXCountChars: 0 as DWORD,
                dwYCountChars: 0 as DWORD,
                dwFillAttribute: 0 as DWORD,
                dwFlags: 0 as DWORD,
                wShowWindow: 0 as WORD,
                cbReserved2: 0 as WORD,
                lpReserved2: NULL as LPBYTE,
                hStdInput: 0 as HANDLE,
                hStdOutput: 0 as HANDLE,
                hStdError: 0 as HANDLE,
            },
            lpAttributeList: 0 as PPROC_THREAD_ATTRIBUTE_LIST,
        };
        let mut dwCreationFlags: DWORD = 0 as DWORD;
        let mut attrBuf: Vec<u8>;

        if !self.debug {
            debug!("Setting up AppContainer");

            if self.outboundNetwork {
                debug!("Setting up SID_AND_ATTRIBUTES for outbound network permissions");

                attrs = SID_AND_ATTRIBUTES {
                    Sid: network_allow_sid.as_ptr() as PSID,
                    Attributes: SE_GROUP_ENABLED,
                };

                capabilities.CapabilityCount = 1;
                capabilities.Capabilities = &mut attrs;
            }

            let mut listSize: SIZE_T = 0;
            if unsafe {
                   InitializeProcThreadAttributeList(NULL as LPPROC_THREAD_ATTRIBUTE_LIST,
                                                     1,
                                                     0,
                                                     &mut listSize)
               } !=
               0 {
                debug!("InitializeProcThreadAttributeList failed: GLE={:}",
                       unsafe { GetLastError() });
                return Err(unsafe { GetLastError() });
            }

            attrBuf = Vec::with_capacity(listSize as usize);
            if unsafe {
                   InitializeProcThreadAttributeList(attrBuf.as_mut_ptr() as
                                                     LPPROC_THREAD_ATTRIBUTE_LIST,
                                                     1,
                                                     0,
                                                     &mut listSize)
               } ==
               0 {
                debug!("InitializeProcThreadAttributeList failed: GLE={:}",
                       unsafe { GetLastError() });
                return Err(unsafe { GetLastError() });
            }

            if unsafe {
                UpdateProcThreadAttribute(attrBuf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST, 
                                          0, 
                                          PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, 
                                          mem::transmute::<PSECURITY_CAPABILITIES, LPVOID>(&mut capabilities), 
                                          mem::size_of::<SECURITY_CAPABILITIES>() as SIZE_T, 
                                          NULL as PVOID, 
                                          NULL as PSIZE_T) } == 0 {
                debug!("UpdateProcThreadAttribute failed: GLE={:}", unsafe { GetLastError() });
                return Err(unsafe { GetLastError() })
            }

            si.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as DWORD;
            si.lpAttributeList = attrBuf.as_mut_ptr() as PPROC_THREAD_ATTRIBUTE_LIST;

            dwCreationFlags |= EXTENDED_STARTUPINFO_PRESENT;
        } else {
            debug!("Debug mode -- no extended STARTUPINFO");
            si.StartupInfo.cb = mem::size_of::<STARTUPINFOW>() as DWORD;
        }

        si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;

        if stdout != INVALID_HANDLE_VALUE && stdin != INVALID_HANDLE_VALUE {
            si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = stdin as HANDLE;
            si.StartupInfo.hStdOutput = stdout as HANDLE;
            si.StartupInfo.hStdError = stdout as HANDLE;

            // Ensure the handle is inheritable
            if unsafe { SetHandleInformation(stdin, HANDLE_FLAG_INHERIT, 1) } == 0 {
                return Err(unsafe { GetLastError() });
            }

            if stdin != stdout {
                if unsafe { SetHandleInformation(stdout, HANDLE_FLAG_INHERIT, 1) } == 0 {
                    return Err(unsafe { GetLastError() });
                }
            }
        }

        si.StartupInfo.wShowWindow = SW_HIDE as WORD;

        let currentDir: Vec<u16> = OsStr::new(dirPath)
            .encode_wide()
            .chain(once(0))
            .collect();
        let cmdLine: Vec<u16> = OsStr::new(&self.childPath)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut pi = PROCESS_INFORMATION {
            hProcess: 0 as HANDLE,
            hThread: 0 as HANDLE,
            dwProcessId: 0 as DWORD,
            dwThreadId: 0 as DWORD,
        };

        if unsafe {
               CreateProcessW(cmdLine.as_ptr(),
                              NULL as LPWSTR,
                              NULL as LPSECURITY_ATTRIBUTES,
                              NULL as LPSECURITY_ATTRIBUTES,
                              1,
                              dwCreationFlags,
                              NULL as LPVOID,
                              currentDir.as_ptr(),
                              mem::transmute::<LPSTARTUPINFOEXW, LPSTARTUPINFOW>(&mut si),
                              &mut pi)
           } == 0 {
            println!("CreateProcess failed: GLE={:}",
                     unsafe { GetLastError() });
            return Err(unsafe { GetLastError() });
        }

        debug!("  Child PID = {:}", pi.dwProcessId);

        unsafe { CloseHandle(pi.hThread) };

        Ok(HandlePtr::new(pi.hProcess))
    }
}