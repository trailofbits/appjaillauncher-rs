#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![cfg(windows)]

#[allow(unused_imports)]
use log::*;

use libc;
use widestring::WideString;
use std::mem;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::iter::once;

use winapi::shared::inaddr::{in_addr};
use winapi::shared::minwindef::{DWORD, INT, LPVOID};
use winapi::shared::ntdef::{NULL};
use winapi::shared::ws2def::{
    ADDRINFOW, AF_INET, AI_PASSIVE, SO_REUSEADDR, SOCK_STREAM, SOCKADDR, SOCKADDR_IN, SOL_SOCKET
};
use winapi::um::errhandlingapi::{GetLastError};
use winapi::um::handleapi::{SetHandleInformation};
use winapi::um::minwinbase::{LPSECURITY_ATTRIBUTES};
use winapi::um::synchapi::{CreateEventW};
use winapi::um::winbase::{HANDLE_FLAG_INHERIT, WAIT_OBJECT_0};
use winapi::um::winnt::{HANDLE, LPCWSTR, PCWSTR};
use winapi::um::winsock2::{
    INVALID_SOCKET, SOCKET, SOCKET_ERROR, WSA_INVALID_EVENT, WSADATA, FD_ACCEPT, accept, bind, closesocket, listen, 
    setsockopt, WSACleanup, WSAEventSelect, WSAGetLastError, WSAPROTOCOL_INFOW, WSASocketW, WSAStartup, 
    WSAWaitForMultipleEvents
};
use winapi::um::ws2tcpip::{GetAddrInfoW, InetNtopW};

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
            closesocket(self.socket);
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
        let mut ret = unsafe { WSAStartup(0x202, &mut data) };
        if ret != 0 {
            return Err(ret as DWORD);
        }

        let wszPort: Vec<u16> = OsStr::new(port).encode_wide().chain(once(0)).collect();

        let mut hints: ADDRINFOW = unsafe { mem::zeroed() };
        let mut servinfo: *mut ADDRINFOW = NULL as *mut ADDRINFOW;

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        ret = unsafe { GetAddrInfoW(0 as PCWSTR, wszPort.as_ptr(), &hints, &mut servinfo) };
        if ret != 0 {
            debug!("GetAddrInfoW failed: GLE={:}",
                   unsafe { WSAGetLastError() });
            return Err(ret as DWORD);
        }

        let socket = unsafe {
            WSASocketW((*servinfo).ai_family,
                       (*servinfo).ai_socktype,
                       (*servinfo).ai_protocol,
                       mem::transmute::<usize, *mut WSAPROTOCOL_INFOW>(0),
                       0,
                       0)
        };
        if socket == INVALID_SOCKET {
            debug!("WSASocketW failed: GLE={:}",
                   unsafe { WSAGetLastError() });
            return Err(unsafe { WSAGetLastError() as DWORD });
        }

        let mut server = TcpServer {
            socket: socket,
            eventList: Vec::new(),
            hAccept: unsafe {
                CreateEventW(0 as LPSECURITY_ATTRIBUTES, 0, 0, NULL as LPCWSTR)
            },
        };
        if server.hAccept == WSA_INVALID_EVENT {
            debug!("CreateEventW failed: GLE={:}",
                   unsafe { GetLastError() });
            return Err(unsafe { WSAGetLastError() } as DWORD);
        }

        server.eventList.push(server.hAccept);

        let yes: DWORD = 1;
        ret = unsafe {
            setsockopt(socket,
                       SOL_SOCKET,
                       SO_REUSEADDR,
                       mem::transmute::<&DWORD, *const i8>(&yes),
                       mem::size_of::<DWORD>() as i32)
        };
        if ret != 0 {
            debug!("setsockopt SO_REUSEADDR failed: GLE={:}",
                   unsafe { WSAGetLastError() });
            return Err(ret as DWORD);
        }

        ret = unsafe { bind(socket, (*servinfo).ai_addr, (*servinfo).ai_addrlen as i32) };
        if ret == -1 {
            debug!("bind failed: GLE={:}", unsafe { WSAGetLastError() });
            return Err(ret as DWORD);
        }

        ret = unsafe { listen(socket, 5) };
        if ret != 0 {
            debug!("listen failed: GLE={:}",
                   unsafe { WSAGetLastError() });
            return Err(ret as DWORD);
        }

        ret = unsafe { WSAEventSelect(socket, server.hAccept, FD_ACCEPT) };
        if ret == SOCKET_ERROR {
            debug!("WSAEventSelect failed: GLE={:}",
                   unsafe { WSAGetLastError() });
            return Err(unsafe { WSAGetLastError() } as DWORD);
        }

        if unsafe { SetHandleInformation(socket as HANDLE, HANDLE_FLAG_INHERIT, 0) } ==
           0 {
            debug!("Failed to SetHandleInformation: GLE={:}",
                   unsafe { GetLastError() });
            return Err(unsafe { GetLastError() });
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
                accept(self.socket,
                       mem::transmute::<&mut SOCKADDR_IN, *mut SOCKADDR>(&mut clientAddr),
                       &mut sinSize)
            };
        if clientSocket == INVALID_SOCKET {
            debug!("Invalid client socket: GLE={:}",
                   unsafe { WSAGetLastError() });
            return None;
        }

        let mut buffer: Vec<u16> = Vec::with_capacity(16);

        let ret = unsafe {
            InetNtopW(clientAddr.sin_family as INT,
                      mem::transmute::<&mut in_addr, LPVOID>(&mut clientAddr.sin_addr),
                      buffer.as_mut_ptr(),
                      16)
        };
        if ret == 0 as PCWSTR {
            debug!("Failed to convert client IP addr to string: GLE={:}",
                   unsafe { WSAGetLastError() });
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
            WSAWaitForMultipleEvents(self.eventList.len() as u32,
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
            closesocket(self.socket);
            WSACleanup();
        }
    }
}

impl HasRawHandle for TcpServer {
    fn raw_handle(&self) -> HANDLE {
        self.socket as HANDLE
    }
}