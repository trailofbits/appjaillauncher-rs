#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![cfg(windows)]

extern crate libc;
extern crate winapi;
extern crate ws2_32;
extern crate kernel32;
extern crate widestring;

#[allow(unused_imports)]
use log::*;

use self::widestring::WideString;
use std::mem;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::iter::once;
use winapi::*;
use super::winffi::{HANDLE_FLAG_INHERIT, WSA_INVALID_EVENT, FD_ACCEPT};

pub enum TcpServerEvent {
    Accept,
    Error,
    Token(usize),
}

pub struct TcpClient {
    socket: SOCKET,
}

pub trait HasRawHandle {
    fn raw_handle(&self) -> HANDLE;
}

impl TcpClient {
    fn from_accept(socket: SOCKET) -> TcpClient {
        TcpClient { socket: socket }
    }
}

impl HasRawHandle for TcpClient {
    fn raw_handle(&self) -> HANDLE {
        self.socket as HANDLE
    }
}

impl Drop for TcpClient {
    fn drop(&mut self) {
        unsafe {
            ws2_32::closesocket(self.socket);
        }
    }
}

pub struct TcpServer {
    socket: SOCKET,
    eventList: Vec<HANDLE>,
    hAccept: HANDLE,
}

impl TcpServer {
    pub fn bind(port: &str) -> Result<TcpServer, DWORD> {
        let mut data: WSADATA = unsafe { mem::zeroed() };
        let mut ret = unsafe { ws2_32::WSAStartup(0x202, &mut data) };
        if ret != 0 {
            return Err(ret as DWORD);
        }

        let wszPort: Vec<u16> = OsStr::new(port).encode_wide().chain(once(0)).collect();

        let mut hints: ADDRINFOW = unsafe { mem::zeroed() };
        let mut servinfo: *mut ADDRINFOW = 0 as *mut ADDRINFOW;

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = 1; // AI_PASSIVE

        ret = unsafe { ws2_32::GetAddrInfoW(0 as PCWSTR, wszPort.as_ptr(), &hints, &mut servinfo) };
        if ret != 0 {
            debug!("GetAddrInfoW failed: GLE={:}",
                   unsafe { ws2_32::WSAGetLastError() });
            return Err(ret as DWORD);
        }

        let socket = unsafe {
            ws2_32::WSASocketW((*servinfo).ai_family,
                               (*servinfo).ai_socktype,
                               (*servinfo).ai_protocol,
                               mem::transmute::<usize, *mut WSAPROTOCOL_INFOW>(0),
                               0,
                               0)
        };
        if socket == INVALID_SOCKET {
            debug!("WSASocketW failed: GLE={:}",
                   unsafe { ws2_32::WSAGetLastError() });
            return Err(unsafe { ws2_32::WSAGetLastError() as DWORD });
        }

        let mut server = TcpServer {
            socket: socket,
            eventList: Vec::new(),
            hAccept: unsafe {
                kernel32::CreateEventW(0 as LPSECURITY_ATTRIBUTES, 0, 0, 0 as LPCWSTR)
            },
        };
        if server.hAccept == WSA_INVALID_EVENT {
            debug!("CreateEventW failed: GLE={:}",
                   unsafe { kernel32::GetLastError() });
            return Err(unsafe { ws2_32::WSAGetLastError() } as DWORD);
        }

        server.eventList.push(server.hAccept);

        let yes: DWORD = 1;
        ret = unsafe {
            ws2_32::setsockopt(socket,
                               SOL_SOCKET,
                               SO_REUSEADDR,
                               mem::transmute::<&DWORD, *const i8>(&yes),
                               mem::size_of::<DWORD>() as i32)
        };
        if ret != 0 {
            debug!("setsockopt SO_REUSEADDR failed: GLE={:}",
                   unsafe { ws2_32::WSAGetLastError() });
            return Err(ret as DWORD);
        }

        ret = unsafe { ws2_32::bind(socket, (*servinfo).ai_addr, (*servinfo).ai_addrlen as i32) };
        if ret == -1 {
            debug!("bind failed: GLE={:}", unsafe { ws2_32::WSAGetLastError() });
            return Err(ret as DWORD);
        }

        ret = unsafe { ws2_32::listen(socket, 5) };
        if ret != 0 {
            debug!("listen failed: GLE={:}",
                   unsafe { ws2_32::WSAGetLastError() });
            return Err(ret as DWORD);
        }

        ret = unsafe { ws2_32::WSAEventSelect(socket, server.hAccept, FD_ACCEPT) };
        if ret == SOCKET_ERROR {
            debug!("WSAEventSelect failed: GLE={:}",
                   unsafe { ws2_32::WSAGetLastError() });
            return Err(unsafe { ws2_32::WSAGetLastError() } as DWORD);
        }

        if unsafe { kernel32::SetHandleInformation(socket as HANDLE, HANDLE_FLAG_INHERIT, 0) } ==
           0 {
            debug!("Failed to SetHandleInformation: GLE={:}",
                   unsafe { kernel32::GetLastError() });
            return Err(unsafe { kernel32::GetLastError() });
        }

        Ok(server)
    }

    pub fn register_event(&mut self, event: HANDLE) -> TcpServerEvent {
        self.eventList.push(event);
        TcpServerEvent::Token(self.eventList.len() - 1)
    }

    pub fn accept(&self) -> Option<(TcpClient, String)> {
        let mut clientAddr: SOCKADDR_IN = unsafe { mem::zeroed() };
        let mut sinSize: i32 = mem::size_of::<SOCKADDR_IN>() as i32;
        let clientSocket: SOCKET =
            unsafe {
                ws2_32::accept(self.socket,
                               mem::transmute::<&mut SOCKADDR_IN, *mut SOCKADDR>(&mut clientAddr),
                               &mut sinSize)
            };
        if clientSocket == INVALID_SOCKET {
            debug!("Invalid client socket: GLE={:}",
                   unsafe { ws2_32::WSAGetLastError() });
            return None;
        }

        let mut buffer: Vec<u16> = Vec::with_capacity(16);

        let ret = unsafe {
            ws2_32::InetNtopW(clientAddr.sin_family as INT,
                              mem::transmute::<&mut in_addr, LPVOID>(&mut clientAddr.sin_addr),
                              buffer.as_mut_ptr(),
                              16)
        };
        if ret == 0 as PCWSTR {
            debug!("Failed to convert client IP addr to string: GLE={:}",
                   unsafe { ws2_32::WSAGetLastError() });
            return None;
        }

        let clientAddrPair = unsafe {
            mem::forget(buffer);
            let size = libc::wcslen(ret);
            format!("{}:{}",
                    WideString::from_ptr(ret, size).to_string_lossy(),
                    clientAddr.sin_port)
        };

        Some((TcpClient::from_accept(clientSocket), clientAddrPair))
    }

    pub fn get_event(&self) -> TcpServerEvent {
        let ret = unsafe {
            ws2_32::WSAWaitForMultipleEvents(self.eventList.len() as u32,
                                             self.eventList.as_ptr(),
                                             0,
                                             0xffffffff as DWORD,
                                             0)
        };
        if ret == WAIT_OBJECT_0 {
            return TcpServerEvent::Accept;
        } else if ret > WAIT_OBJECT_0 {
            let item = ret - WAIT_OBJECT_0;
            return TcpServerEvent::Token(item as usize);
        }

        TcpServerEvent::Error
    }
}

impl Drop for TcpServer {
    fn drop(&mut self) {
        unsafe {
            ws2_32::closesocket(self.socket);
            ws2_32::WSACleanup();
        }
    }
}

impl HasRawHandle for TcpServer {
    fn raw_handle(&self) -> HANDLE {
        self.socket as HANDLE
    }
}