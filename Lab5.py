print "Hello Lab5\n"

from idaapi import *

ea = 0x401241

def testStandAlone():
	print("testStandAlone")

class MyDbgHook(DBG_Hooks):

	""" Own debug hook class that implementd the callback functions """

	def dbg_process_start(self, pid, tid, ea, name, base, size):
		print "Process started, pid=%d tid=%d name=%s" % (pid, tid, name)
		new_val = 0x75
		patch_ea = 0x401241
		print("Setting instruction to 0x75 (jnz)")
		print("BYTE @ 0x%x before patching is [0x%X]" % (patch_ea, Byte(patch_ea)))
		result = PatchByte(patch_ea, new_val)
		print("Result was %d") % result
		print("BYTE @ 0x%x after patching is [0x%X]\n" % (patch_ea, Byte(patch_ea)))
		return 0

	def dbg_process_exit(self, pid, tid, ea, code):
		print "Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code)
		new_val = 0x74
		patch_ea = 0x401241
		print("")
		print("Resetting instruction back to 0x74 (jz)")
		print("BYTE @ 0x%x before patching is [0x%X]" % (patch_ea, Byte(patch_ea)))
		result = PatchByte(patch_ea, new_val)
		print("Result was %d") % result
		print("BYTE @ 0x%x after patching is [0x%X]\n" % (patch_ea, Byte(patch_ea)))
		return 0

	def dbg_library_load(self, pid, tid, ea, name, base, size):
		print "Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base)

	def dbg_bpt(self, tid, ea):
		print "Break point at 0x%x pid=%d" % (ea, tid)
		return 0

	def dbg_trace(self, tid, ea):
		print tid, ea
		return 0

	def dbg_step_into(self):
		print "Step into"
		return self.dbg_step_over()

	def dbg_step_over(self):
		eip = GetRegValue("EIP")
		print "0x%x %s" % (eip, GetDisasm(eip))

		self.steps += 1
		if self.steps >= 5:
			request_exit_process()
		else:
			request_step_over()
		return 0
		
	def dbg_patchByte(ea, new_val):

		#print("BYTE @ 0x%x before patching is [0x%X]" % (ea, Byte(0x401241)))
		print("Debug: BYTE @ 0x%x before patching is [0x%X]" % (ea, Byte(ea)))
		result = PatchByte(ea, new_val)
		#print("BYTE @ 0x%x after patching is [0x%X]\n" % (ea, Byte(0x401241)))
		print("Debug: Result was %d") % result
		print("Debug: BYTE @ 0x%x after patching is [0x%X]\n" % (ea, Byte(ea)))
		
	def testMe():
		print("Test!")


# Remove an existing debug hook
try:
	if debughook:
		print "Removing previous hook ...\n"
		debughook.unhook()
except:
	pass

#ea = 0x401241

	
# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0

# Stop at the entry point
ep = GetLongPrm(INF_START_IP)
request_run_to(ep)

# Step one instruction
request_step_over()



# Add a breakpoint at address 0x401241 (right at the instruction we want to modify)
# Adding like this enables the breakpoint as well

#AddBpt(0x401241)
#AddBpt(ea)

#debughook.dbg_bpt(self, tid, ea)

# Start debugging
run_requests()
testStandAlone()



AddBpt(ea)

#while not is_debugger_on():
#	print("Debugger is not on")
	
#print("Debugger is on!")

#patchThisByte(ea, 0x74)
#patchThisByte(ea, 0x75)

#patchhisByte(ea, 0x75)

print("End of script")

# Reset to op code 74 (jz) when finished
#patchhisByte(ea, 0x74)