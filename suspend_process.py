from XoanDbg.my_debugger import Debugger


procName = b"NamLunPhieuLuuKy.exe"
dbg = Debugger(processs_name=procName)

dbg.suspend_all_threads()
input("Pause")
dbg.resume_all_threads()