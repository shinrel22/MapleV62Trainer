from ctypes import *

# Let's map the Microsoft types to ctypes for clarity

BYTE = c_ubyte
WORD = c_ushort
DWORD = c_ulong
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p
PVOID = c_void_p
LPVOID = c_void_p
UINT_PTR = c_ulong
SIZE_T = c_ulong
PULONG = POINTER(DWORD)
NTSTATUS = c_long
SDWORD = c_int32
KAFFINITY = c_size_t
LONGLONG = c_int64
ULONG = c_ulong
CHAR = c_char
LONG = c_long
TCHAR = CHAR  # XXX ANSI by default?

# Constants
DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010
PROCESS_ALL_ACCESS = 0x001F0FFF
INFINITE = 0xFFFFFFFF
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
THREADINFOCLASS = DWORD
MEM_RESERVE = 0x00002000
MEM_COMMIT = 0x00001000
MEM_RELEASE = 0x8000

# Map size_t to SIZE_T
try:
    SIZE_T = c_size_t
except AttributeError:
    # Size of a pointer
    SIZE_T = {1: BYTE, 2: WORD, 4: DWORD, 8: DWORD}[sizeof(LPVOID)]
PSIZE_T = POINTER(SIZE_T)

# Not really pointers but pointer-sized integers
DWORD_PTR = SIZE_T
ULONG_PTR = SIZE_T
LONG_PTR = SIZE_T

# THREAD_INFORMATION_CLASS
ThreadBasicInformation = 0
ThreadTimes = 1
ThreadPriority = 2
ThreadBasePriority = 3
ThreadAffinityMask = 4
ThreadImpersonationToken = 5
ThreadDescriptorTableEntry = 6
ThreadEnableAlignmentFaultFixup = 7
ThreadEventPair = 8
ThreadQuerySetWin32StartAddress = 9
ThreadZeroTlsCell = 10
ThreadPerformanceCount = 11
ThreadAmILastThread = 12
ThreadIdealProcessor = 13
ThreadPriorityBoost = 14
ThreadSetTlsArrayAddress = 15
ThreadIsIoPending = 16
ThreadHideFromDebugger = 17

# Debug event constants
EXCEPTION_DEBUG_EVENT = 0x1
CREATE_THREAD_DEBUG_EVENT = 0x2
CREATE_PROCESS_DEBUG_EVENT = 0x3
EXIT_THREAD_DEBUG_EVENT = 0x4
EXIT_PROCESS_DEBUG_EVENT = 0x5
LOAD_DLL_DEBUG_EVENT = 0x6
UNLOAD_DLL_DEBUG_EVENT = 0x7
OUTPUT_DEBUG_STRING_EVENT = 0x8
RIP_EVENT = 0x9

# debug exception codes.
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_GUARD_PAGE = 0x80000001
EXCEPTION_SINGLE_STEP = 0x80000004

# Thread constants for CreateToolhelp32Snapshot()
TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_INHERIT = 0x80000000
TH32CS_SNAPALL = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
THREAD_ALL_ACCESS = 0x001F03FF

# Context flags for GetThreadContext()
CONTEXT_FULL = 0x00010007
CONTEXT_DEBUG_REGISTERS = 0x00010010

# Memory permissions
PAGE_EXECUTE_READWRITE = 0x00000040

# Hardware breakpoint conditions
HW_ACCESS = 0x00000003
HW_EXECUTE = 0x00000000
HW_WRITE = 0x00000001

# Memory page permissions, used by VirtualProtect()
PAGE_NOACCESS = 0x00000001
PAGE_READONLY = 0x00000002
PAGE_READWRITE = 0x00000004
PAGE_WRITECOPY = 0x00000008
PAGE_EXECUTE = 0x00000010
PAGE_EXECUTE_READ = 0x00000020
PAGE_EXECUTE_WRITECOPY = 0x00000080
PAGE_GUARD = 0x00000100
PAGE_NOCACHE = 0x00000200
PAGE_WRITECOMBINE = 0x00000400

INVALID_HANDLE_VALUE = 0xFFFFFFFF

# Error codes
# To do maybe add more error codes?
# if they're too many they could be pickled instead,
# or at the very least put in a new file
ERROR_SUCCESS = 0
ERROR_INVALID_FUNCTION = 1
ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_NOT_ENOUGH_MEMORY = 8
ERROR_INVALID_DRIVE = 15
ERROR_NO_MORE_FILES = 18
ERROR_BAD_LENGTH = 24
ERROR_HANDLE_EOF = 38
ERROR_HANDLE_DISK_FULL = 39
ERROR_NOT_SUPPORTED = 50
ERROR_FILE_EXISTS = 80
ERROR_INVALID_PARAMETER = 87
ERROR_BUFFER_OVERFLOW = 111
ERROR_DISK_FULL = 112
ERROR_CALL_NOT_IMPLEMENTED = 120
ERROR_SEM_TIMEOUT = 121
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_INVALID_NAME = 123
ERROR_MOD_NOT_FOUND = 126
ERROR_PROC_NOT_FOUND = 127
ERROR_DIR_NOT_EMPTY = 145
ERROR_BAD_THREADID_ADDR = 159
ERROR_BAD_ARGUMENTS = 160
ERROR_BAD_PATHNAME = 161
ERROR_ALREADY_EXISTS = 183
ERROR_INVALID_FLAG_NUMBER = 186
ERROR_FILENAME_EXCED_RANGE = 206
WAIT_TIMEOUT = 258
ERROR_NO_MORE_ITEMS = 259
ERROR_PARTIAL_COPY = 299
ERROR_INVALID_ADDRESS = 487
ERROR_THREAD_NOT_IN_PROCESS = 566
ERROR_CONTROL_C_EXIT = 572
ERROR_UNHANDLED_EXCEPTION = 574
ERROR_ASSERTION_FAILURE = 668
ERROR_WOW_ASSERTION = 670

ERROR_DBG_EXCEPTION_NOT_HANDLED = 688
ERROR_DBG_REPLY_LATER = 689
ERROR_DBG_UNABLE_TO_PROVIDE_HANDLE = 690
ERROR_DBG_TERMINATE_THREAD = 691
ERROR_DBG_TERMINATE_PROCESS = 692
ERROR_DBG_CONTROL_C = 693
ERROR_DBG_PRINTEXCEPTION_C = 694
ERROR_DBG_RIPEXCEPTION = 695
ERROR_DBG_CONTROL_BREAK = 696
ERROR_DBG_COMMAND_EXCEPTION = 697
ERROR_DBG_EXCEPTION_HANDLED = 766
ERROR_DBG_CONTINUE = 767

ERROR_NOACCESS = 998

ERROR_DEBUGGER_INACTIVE = 1284


# Structures for CreateProcessA() function
# STARTUPINFO describes how to spawn the process
class STARTUPINFO(Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPTSTR),
        ("lpDesktop", LPTSTR),
        ("lpTitle", LPTSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]


# PROCESS_INFORMATION receives its information
# after the target process has been successfully
# started.
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]


# When the dwDebugEventCode is evaluated
class EXCEPTION_RECORD(Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", DWORD),
    ("ExceptionFlags", DWORD),
    ("ExceptionRecord", POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", PVOID),
    ("NumberParameters", DWORD),
    ("ExceptionInformation", UINT_PTR * 15),
]


class _EXCEPTION_RECORD(Structure):
    _fields_ = [
        ("ExceptionCode", DWORD),
        ("ExceptionFlags", DWORD),
        ("ExceptionRecord", POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress", PVOID),
        ("NumberParameters", DWORD),
        ("ExceptionInformation", UINT_PTR * 15),
    ]


# Exceptions
class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", DWORD),
    ]


# it populates this union appropriately
class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        #        ("CreateThread",      CREATE_THREAD_DEBUG_INFO),
        #        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        #        ("ExitThread",        EXIT_THREAD_DEBUG_INFO),
        #        ("ExitProcess",       EXIT_PROCESS_DEBUG_INFO),
        #        ("LoadDll",           LOAD_DLL_DEBUG_INFO),
        #        ("UnloadDll",         UNLOAD_DLL_DEBUG_INFO),
        #        ("DebugString",       OUTPUT_DEBUG_STRING_INFO),
        #        ("RipInfo",           RIP_INFO),
    ]

# DEBUG_EVENT describes a debugging event


# that the debugger has trapped
class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", DEBUG_EVENT_UNION),
    ]


# Used by the CONTEXT structure
class FLOATING_SAVE_AREA(Structure):
    _fields_ = [

        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
    ]


# The CONTEXT structure which holds all of the
# register values after a GetThreadContext() call
class CONTEXT(Structure):
    _fields_ = [

        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
    ]


# THREADENTRY32 contains information about a thread
# we use this for enumerating all of the system threads

class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ThreadID", DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri", DWORD),
        ("tpDeltaPri", DWORD),
        ("dwFlags", DWORD),
    ]


# Supporting struct for the SYSTEM_INFO_UNION union
class PROC_STRUCT(Structure):
    _fields_ = [
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
    ]


# Supporting union for the SYSTEM_INFO struct
class SYSTEM_INFO_UNION(Union):
    _fields_ = [
        ("dwOemId", DWORD),
        ("sProcStruc", PROC_STRUCT),
    ]


# SYSTEM_INFO structure is populated when a call to
# kernel32.GetSystemInfo() is made. We use the dwPageSize
# member for size calculations when setting memory breakpoints
class SYSTEM_INFO(Structure):
    _fields_ = [
        ("uSysInfo", SYSTEM_INFO_UNION),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", DWORD),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
    ]


# MEMORY_BASIC_INFORMATION contains information about a
# particular region of memory. A call to kernel32.VirtualQuery()
# populates this structure.
class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]


# --- CLIENT_ID structure ---------------------------------------
#   typedef struct _CLIENT_ID
#   {
#       HANDLE UniqueProcess;
#       HANDLE UniqueThread;
#   } CLIENT_ID;

class CLIENT_ID(Structure):
    _fields_ = [
        ("UniqueProcess", PVOID),
        ("UniqueThread", PVOID)
    ]


# --- THREAD_BASIC_INFORMATION structure ---------------------------------------

# From http://undocumented.ntinternals.net/UserMode/Structures/THREAD_BASIC_INFORMATION.html
#
# typedef struct _THREAD_BASIC_INFORMATION {
#   NTSTATUS ExitStatus;
#   PVOID TebBaseAddress;
#   CLIENT_ID ClientId;
#   KAFFINITY AffinityMask;
#   KPRIORITY Priority;
#   KPRIORITY BasePriority;
# } THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;
class THREAD_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus", NTSTATUS),
        ("TebBaseAddress", PVOID),  # PTEB
        ("ClientId", CLIENT_ID),
        ("AffinityMask", KAFFINITY),
        ("Priority", SDWORD),
        ("BasePriority", SDWORD),
    ]


class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("th32ModuleID", DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage", DWORD),
        ("ProccntUsage", DWORD),
        ("modBaseAddr", DWORD),
        ("modBaseSize", DWORD),
        ("hModule", DWORD),
        ("szModule", CHAR * 256),
        ("szExePath", CHAR * 260),
    ]


# typedef struct tagPROCESSENTRY32 {
#    DWORD dwSize;
#    DWORD cntUsage;
#    DWORD th32ProcessID;
#    ULONG_PTR th32DefaultHeapID;
#    DWORD th32ModuleID;
#    DWORD cntThreads;
#    DWORD th32ParentProcessID;
#    LONG pcPriClassBase;
#    DWORD dwFlags;
#    TCHAR szExeFile[MAX_PATH];
# } PROCESSENTRY32,  *PPROCESSENTRY32;
class PROCESSENTRY32(Structure):
    _fields_ = [
        ('dwSize', DWORD),
        ('cntUsage', DWORD),
        ('th32ProcessID', DWORD),
        ('th32DefaultHeapID', ULONG_PTR),
        ('th32ModuleID', DWORD),
        ('cntThreads', DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase', LONG),
        ('dwFlags', DWORD),
        ('szExeFile', TCHAR * 260),
    ]


LPPROCESSENTRY32 = POINTER(PROCESSENTRY32)
