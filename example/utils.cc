#include "utils.h"
#include <stdio.h>

DWORD WINAPI AlarmThread(LPVOID lpParameter) {
  DWORD sleepMs = (DWORD) lpParameter;

  ::Sleep(sleepMs);
  ::TerminateProcess(::GetCurrentProcess(), 1);
  
  return 1;
}

bool InitChallenge(DWORD sleepMs) {
  HANDLE hThread = ::CreateThread(NULL, 0, &AlarmThread, (LPVOID) sleepMs, 0, NULL);
  if (hThread == NULL) {
    return false;
  }

  ::setvbuf(stdout, NULL, _IONBF, 0);

  return true;
}