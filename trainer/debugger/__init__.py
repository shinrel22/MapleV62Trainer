import binascii

from .constants import *

kernel32 = windll.kernel32
ntdll = windll.ntdll


class Debugger(object):
    def __init__(self, process_name=None):
        if not process_name:
            self.pid = None
            self.h_process = None
        else:
            self.pid = self.get_pid(process_name)
            self.h_process = self.open_process()

        self.h_thread = None
        self.debugger_active = False

    def get_pid(self, process_name):
        process_list = self.enumerate_processes()
        for procID in process_list:
            if process_list[procID] == process_name:
                return procID

        print("Couldn't find", process_name)
        return None

    def open_process(self, pid=None):
        if self.pid:
            pid = self.pid
        try:
            h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            return h_process
        except Exception as e:
            print(e)
            return None

    def attach(self, pid=None):
        if self.pid:
            pid = self.pid
        # We attempt to attach to the process
        # if this fails we exit the call
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            print("[*] Attached!")
            return True
        print("[*] Unable to attach to the process.")
        return False

    def suspend_thread(self, thread_id):
        h_thread = self.open_thread(thread_id)

        if kernel32.SuspendThread(h_thread) == -1:
            print("Suspending has failed!")
            kernel32.CloseHandle(h_thread)
            return False

        kernel32.CloseHandle(h_thread)
        return True

    def suspend_all_threads(self, pid=None):
        if self.pid:
            pid = self.pid
        for thread_id in self.enumerate_threads(pid=pid):
            self.suspend_thread(thread_id)

    def resume_thread(self, thread_id):
        '''
        Resume the specified thread.

        @type  thread_id: DWORD
        @param thread_id: ID of thread to resume.

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''
        h_thread = self.open_thread(thread_id)

        if kernel32.ResumeThread(h_thread) == -1:
            print("Resuming has failed!")
            kernel32.CloseHandle(h_thread)
            return False

        kernel32.CloseHandle(h_thread)
        return True

    def resume_all_threads(self, pid=None):
        if self.pid:
            pid = self.pid

        for thread_id in self.enumerate_threads(pid=pid):
            self.resume_thread(thread_id)

    def allocate_mem(self, h_process=None, address=None, size=None):
        """
        LPVOID WINAPI VirtualAllocEx(
          _In_     HANDLE hProcess,
          _In_opt_ LPVOID lpAddress,
          _In_     SIZE_T dwSize,
          _In_     DWORD  flAllocationType,
          _In_     DWORD  flProtect
        );
        """
        if self.h_process:
            h_process = self.h_process

        size = c_size_t(size)

        allocate = kernel32.VirtualAllocEx(h_process, address, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        if not allocate:
            print("[*] Allocate memory failed!")
            return False
        if not address:
            return allocate
        return True

    def free_mem(self, h_process=None, address=None, size=None, free_type=None):
        """
        BOOL WINAPI VirtualFreeEx(
              _In_ HANDLE hProcess,
              _In_ LPVOID lpAddress,
              _In_ SIZE_T dwSize,
              _In_ DWORD  dwFreeType
            );
        """
        if self.h_process:
            h_process = self.h_process

        if address is None:
            print("[*] You have to enter an address")
            return False

        if not free_type:
            free_type = MEM_RELEASE
            size = 0

        freeing = kernel32.VirtualFreeEx(h_process, address, size, free_type)
        if not freeing:
            print("[*] Freeing memory failed!")
            return False

        return True

    def read_process_memory(self, address, length, h_process=None):
        if self.h_process:
            h_process = self.h_process
        raw_data = b''
        read_buf = create_string_buffer(length)
        count = c_ulong(0)
        if not kernel32.ReadProcessMemory(h_process,
                                          address,
                                          read_buf,
                                          length,
                                          byref(count)):
            return False

        raw_data += read_buf.raw
        raw_data = binascii.b2a_hex(raw_data).decode("utf-8")
        data = []
        for i in range(len(raw_data)):
            if i * 2 < len(raw_data):
                data.append(raw_data[i * 2:i * 2 + 2])

        return " ".join(data)

    def reverse_code(self, codes):
        new_codes = []
        if codes:
            codes = codes.strip().replace(" ", "")
            if len(codes) % 2 != 0:
                codes = "0" + codes
            for num in range(len(codes)):
                if len(codes) - num * 2 > 0:
                    new_codes.append(codes[-2 * num - 2: len(codes) - num * 2])
            return " ".join(new_codes)
        return False

    def write_process_memory(self, address, data, h_process=None):
        if self.h_process:
            h_process = self.h_process
        count = c_ulong(0)
        data = binascii.a2b_hex(data.replace(" ", ""))
        length = len(data)
        c_data = c_char_p(data[count.value:])
        if not kernel32.WriteProcessMemory(h_process,
                                           address,
                                           c_data,
                                           length,
                                           byref(count)):
            return False
        return True

    def terminate_process(self, h_process=None):
        if self.h_process:
            h_process = self.h_process

        exit_code = c_ulong(0)
        terminating = kernel32.TerminateProcess(h_process, exit_code)

        if terminating:
            print("[*] Process terminated successfully!")
            return True
        print("[*] Terminating process failed!")
        return False

    def enumerate_processes(self):
        '''
        Using the CreateToolhelp32Snapshot() API enumerate all system processes returning a list of pid / process name
        tuples.

        @see: iterate_processes()

        @rtype:  List
        @return: List of pid / process name tuples.

        Example::

            for (pid, name) in pydbg.enumerate_processes():
                if name == "test.exe":
                    break

            pydbg.attach(pid)
        '''
        pe = PROCESSENTRY32()
        process_list = {}
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        if snapshot == INVALID_HANDLE_VALUE:
            raise Exception("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0, True)")

        # we *must* set the size of the structure prior to using it, otherwise Process32First() will fail.
        pe.dwSize = sizeof(PROCESSENTRY32)

        found_proc = kernel32.Process32First(snapshot, byref(pe))

        while found_proc:
            process_list[int(pe.th32ProcessID)] = pe.szExeFile
            found_proc = kernel32.Process32Next(snapshot, byref(pe))

        kernel32.CloseHandle(snapshot)
        return process_list

    def enumerate_modules(self, pid=None):

        '''
        Using the CreateToolhelp32Snapshot() API enumerate and return the list of module name / base address tuples that
        belong to the debuggee

        @see: iterate_modules()

        @rtype:  List
        @return: List of module name / base address tuples.
        '''

        if self.pid:
            pid = self.pid

        module = MODULEENTRY32()
        module_list = []
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise Exception("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, %d)" % pid)

        # we *must* set the size of the structure prior to using it, otherwise Module32First() will fail.
        module.dwSize = sizeof(module)

        found_mod = kernel32.Module32First(snapshot, byref(module))

        while found_mod:
            module_list.append((module.szModule, module.modBaseAddr))
            found_mod = kernel32.Module32Next(snapshot, byref(module))

        kernel32.CloseHandle(snapshot)
        return module_list

    def detach(self, pid=None):
        if self.pid:
            pid = self.pid

        if kernel32.DebugActiveProcessStop(pid):
            print("[*] Detached!")
            return True
        print("There was an error")
        return False

    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, thread_id)
        if h_thread is not None:
            return h_thread
        print("[*] Could not obtain a valid thread handle.")
        return False

    def enumerate_threads(self, pid=None):
        if self.pid:
            pid = self.pid

        thread_entry = THREADENTRY32()
        thread_list = []
        h_snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid)
        if h_snapshot is not None:
            # You have to set the size of the struct or the call will fail
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(h_snapshot, byref(thread_entry))

            while success:
                if thread_entry.th32OwnerProcessID == pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(h_snapshot, byref(thread_entry))

            kernel32.CloseHandle(h_snapshot)
        return thread_list

    def get_thread_context(self, thread_id):
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        # Obtain a handle to the thread
        h_thread = self.open_thread(thread_id)
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        return False

