from XoanDbg.my_debugger_defines import *
import time, binascii


kernel32 = windll.kernel32
ntdll = windll.ntdll


class Debugger():
    def __init__(self, processs_name=None):
        if not processs_name:
            self.pid = None
            self.h_process = None
        else:
            self.pid = self.getPid(processs_name)
            self.h_process = self.open_process()
        self.debugger_active = False
        self.h_thread = None
        self.context = None
        self.exception = None
        self.exception_address = None
        self.breakpoints = {}
        self.hardware_breakpoints = {}
        self.page_size = self.get_page_size()
        self.guarded_pages = []
        self.memory_breakpoints = {}


    def get_page_size(self):
        # Here let's determine and store
        # the default page size for the system
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        page_size = system_info.dwPageSize
        return page_size


    def bp_set_mem(self, address, size):
        mem_basic_info = MEMORY_BASIC_INFORMATION

        # If our VirtualQueryEx() call doesn't return a full-sized MEMORY_BASIC_INFORMATION then return False
        if kernel32.VirtualQueryEx(self.h_process,
                                   address,
                                   byref(mem_basic_info),
                                   sizeof(mem_basic_info)) < sizeof(mem_basic_info):
            return False
        current_page = mem_basic_info.BaseAddress

        # We will set the permissions on all pages that are affected by our memory breakpoint.
        while current_page <= address + size:
            # Add the page to the list; this will
            # differentiate our guarded pages from those
            # that were set by the OS or the debuggee process
            self.guarded_pages.append(current_page)

            old_protection = c_ulong(0)
            if not kernel32.VirtualProtectEx(self.h_process,
                                             current_page, size,
                                             mem_basic_info.Protect | PAGE_GUARD, byref(old_protection)):
                return False

            # Increase our range by the size of the
            # default system memory page size
            current_page += self.page_size

        # Add the memory breakpoint to our global list
        self.memory_breakpoints[address] = (address, size, mem_basic_info)
        return True


    def load(self, path_to_exe):
        # dwCreation flag determines how to create the process
        # set creation_flags = CREATE_NEW_CONSOLE if you want
        # to see the calculator GUI
        creation_flags = DEBUG_PROCESS
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()

        # The following two options allow the started process
        # to be shown as a separate window. This also illustrates
        # how different settings in the STARTUPINFO struct can affect
        # the debuggee.
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0

        # We then initialize the cb variable in the STARTUPINFO struct
        # which is just the size of the struct itself
        startupinfo.cb = sizeof(startupinfo)

        if kernel32.CreateProcessA(path_to_exe,
                                    None,
                                    None,
                                    None,
                                    None,
                                    creation_flags,
                                    None,
                                    None,
                                    byref(startupinfo),
                                    byref(process_information)):

            print ("[*] We have successfully launched the process!")
            print ("[*] PID: %d" % process_information.dwProcessId)

            # Obtain a valid handle to the newly created process
            # and store it for future access
            self.h_process = self.open_process(process_information.dwProcessId)

        else:
            print ("[*] Error: 0x%08x." % kernel32.GetLastError())



    def getPid(self, process_name):
        process_list = self.enumerate_processes()
        for procID in process_list:
            if process_list[procID] == process_name:
                return procID

        print ("Couldn't find", process_name)
        return None


    def open_process(self, pid=None):
        if self.pid:
            pid = self.pid
        try:
            h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            return h_process
        except:
            return None



    def attach(self, pid=None):
        if self.pid:
            pid = self.pid
        # We attempt to attach to the process
        # if this fails we exit the call
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            print ("[*] Attached!")
            return True
        else:
            print ("[*] Unable to attach to the process.")
            return False

    def run(self):
        # Now we have to poll the debuggee for
        # debugging events
        while self.debugger_active == True:
            self.get_debug_event()
            time.sleep(0.5)


    def suspend_thread(self, thread_id):
        h_thread = self.open_thread(thread_id)

        if kernel32.SuspendThread(h_thread) == -1:
            print ("Suspending has failed!")
            kernel32.CloseHandle(h_thread)
            return False

        kernel32.CloseHandle(h_thread)
        return True


    def suspend_all_threads (self, pid=None):
        if self.pid:
            pid = self.pid
        for thread_id in self.enumerate_threads(pid=pid):
            self.suspend_thread(thread_id)


    def resume_thread (self, thread_id):
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
            print ("Resuming has failed!")
            kernel32.CloseHandle(h_thread)
            return False

        kernel32.CloseHandle(h_thread)
        return True


    def resume_all_threads(self, pid=None):
        if self.pid:
            pid = self.pid

        for thread_id in self.enumerate_threads(pid=pid):
            self.resume_thread(thread_id)


    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            # Let's obtain the thread and context information
            self.context = self.get_thread_context(debug_event.dwThreadId)
            print ("Event Code: %d Thread ID: %d" % (debug_event.dwDebugEventCode, debug_event.dwThreadId))

            # If the event code is an exception, we want to examine it further
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                # Obtain the exception code
                self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                    print  ("Access Violation Detected.")

                # If a breakpoint is detected, we call an internal handler.
                elif self.exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()

                elif self.exception == EXCEPTION_GUARD_PAGE:
                    print ("Guard Page Access Detected.")

                elif self.exception == EXCEPTION_SINGLE_STEP:
                    continue_status = self.exception_handler_single_step()
                else:
                    print ("Unknown exception")

        kernel32.ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                continue_status
        )


    def exception_handler_single_step(self):
        # Comment from PyDbg:
        # determine if this single step event occurred in reaction to a
        # hardware breakpoint and grab the hit breakpoint.
        # according to the Intel docs, we should be able to check for
        # the BS flag in Dr6. but it appears that Windows
        # isn't properly propagating that flag down to us.
        if self.context.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
            slot = 0
        elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
            slot = 1
        elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.has_key(2):
            slot = 2
        elif self.context.Dr6 & 0x8 and self.hardware_breakpoints.has_key(3):
            slot = 3
        else:
            # This wasn't an INT1 generated by a hw breakpoint
            continue_status = DBG_EXCEPTION_NOT_HANDLED
            return continue_status

        # Now let's remove the breakpoint from the list
        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE
            print ("[*] Hardware breakpoint removed.")
            return continue_status



    def bp_del_hw(self, slot):
        # Disable the breakpoint for all active threads
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)

            # Reset the flags to remove the breakpoint
            context.Dr7 &= ~(1 << (slot * 2))

            # Zero out the address
            if slot == 0:
                context.Dr0 = 0x00000000
            elif slot == 1:
                context.Dr1 = 0x00000000
            elif slot == 2:
                context.Dr2 = 0x00000000
            elif slot == 3:
                context.Dr3 = 0x00000000

            # Remove the condition flag
            context.Dr7 &= ~(3 << ((slot * 4) + 16))

            # Remove the length flag
            context.Dr7 &= ~(3 << ((slot * 4) + 18))

            # Reset the thread's context with the breakpoint removed
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))

        # remove the breakpoint from the internal list.
        del self.hardware_breakpoints[slot]
        return True



    def exception_handler_breakpoint(self):
        print ("[*] Exception breakpoint")
        print ("[*] Inside the breakpoint handler.")
        print ("Exception Address: 0x%08x") % self.exception_address
        return DBG_CONTINUE


    def allocate(self, h_process=None, address=None, size=None):
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


    def freeMem(self, h_process=None, address=None, size=None, freeType=None):
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

        if address == None:
            print("[*] You have to enter an address")
            return False

        if not freeType:
            freeType = MEM_RELEASE
            size     = 0

        freeing = kernel32.VirtualFreeEx(h_process, address, size, freeType)
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
            if i*2 < len(raw_data):
                data.append(raw_data[i*2:i*2+2])

        return " ".join(data)


    def reverseCode(sefl, codes):
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


    def bp_set(self, address):
        if not self.breakpoints.has_key(address):
            try:
                # store the original byte
                original_byte = self.read_process_memory(address, 1)

                # write the INT3 opcode
                self.write_process_memory(address, "\xCC")

                # register the breakpoint in our internal list
                self.breakpoints[address] = (address, original_byte)

                print ("Set breakpoint at 0x%08x successfully!") % address

            except:
                return False
        return True


    def terminateProcess(self, h_process=None):
        if self.h_process:
            h_process = self.h_process

        exitCode = c_ulong(0)
        terminating = kernel32.TerminateProcess(h_process, exitCode)

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
        pe           = PROCESSENTRY32()
        process_list = {}
        snapshot     = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0", True)

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

        module      = MODULEENTRY32()
        module_list = []
        snapshot    = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, %d" % pid, True)

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
            print ("[*] Detached!")
            return True
        print ("There was an error")
        return False


    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, thread_id)
        if h_thread is not None:
            return h_thread
        print ("[*] Could not obtain a valid thread handle.")
        return False


    def enumerate_threads(self, pid=None):
        if self.pid:
            pid = self.pid

        thread_entry = THREADENTRY32()
        thread_list = []
        hSnapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid)
        if hSnapshot is not None:
            # You have to set the size of the struct or the call will fail
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(hSnapshot, byref(thread_entry))

            while success:
                if thread_entry.th32OwnerProcessID == pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(hSnapshot, byref(thread_entry))

            kernel32.CloseHandle(hSnapshot)
        return thread_list


    def func_resolve(self, dll, function):
        handle = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle, function)
        kernel32.CloseHandle(handle)
        return address


    def get_thread_context(self, thread_id):
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        # Obtain a handle to the thread
        h_thread = self.open_thread(thread_id)
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        return False


    def bp_set_hw(self, address, length, condition):
        # Check for a valid length value
        if length not in (1, 2, 4):
            return False
        length -= 1

        # Check for a valid condition
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False

        # Check for available slots
        if not self.hardware_breakpoints.has_key(0):
            available = 0
        elif not self.hardware_breakpoints.has_key(1):
            available = 1
        elif not self.hardware_breakpoints.has_key(2):
            available = 2
        elif not self.hardware_breakpoints.has_key(3):
            available = 3
        else:
            return False

        # We want to set the debug register in every thread
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)


            # Enable the appropriate flag in the DR7 register to set the breakpoint
            context.Dr7 |= 1 << (available * 2)

            # Save the address of the breakpoint in the free register that we found
            if available == 0:
                context.Dr0 = address
            elif available == 1:
                context.Dr1 = address
            elif available == 2:
                context.Dr2 = address
            elif available == 3:
                context.Dr3 = address

            # Set the breakpoint condition
            context.Dr7 |= condition << ((available * 4) + 16)

            # Set the length
            context.Dr7 |= length << ((available * 4) + 18)

            # Set thread context with the break set
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))

        # update the internal hardware breakpoint array at the used slot index.
        self.hardware_breakpoints[available] = (address, length, condition)
        print ("Set breakpoint at 0x%08x successfully!") % address
        return True


    # NTSTATUS WINAPI NtQueryInformationThread(
    #   __in       HANDLE ThreadHandle,
    #   __in       THREADINFOCLASS ThreadInformationClass,
    #   __out      PVOID ThreadInformation,
    #   __in       ULONG ThreadInformationLength,
    #   __out_opt  PULONG ReturnLength
    # );
    def getThreadStartAddr(self, thread_id):
        h_thread = self.open_thread(thread_id)

        _NtQueryInformationThread = ntdll.NtQueryInformationThread
        _NtQueryInformationThread.argtypes = [HANDLE, THREADINFOCLASS, PVOID, DWORD, PULONG]
        _NtQueryInformationThread.restype = NTSTATUS
        ThreadInformationClass = ThreadQuerySetWin32StartAddress
        ThreadInformation = PVOID(9)
        ThreadInformationLength = sizeof(ThreadInformation)
        ReturnLength = ULONG(0)
        _NtQueryInformationThread(h_thread, ThreadInformationClass, byref(ThreadInformation),
                                             ThreadInformationLength, byref(ReturnLength))

        retval = ThreadInformation.value
        kernel32.CloseHandle(h_thread)
        return retval

