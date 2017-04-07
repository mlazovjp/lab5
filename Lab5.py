# Reverse Engineering
# Lab 5, script 2
# Jeremy Mlazovsky

print "Hello Lab5\n"

from idaapi import *
from idc import *

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
		
		# if at section where user input string is in ESI register ...
		if ea == 0x401370:
		
			esi = GetRegValue("esi")
			print("ea=[0x%x]") % ea
			print("esi=%d 0x%x %s") % (esi, esi,esi)
			
			# try reading data at 0x0019FDD8 ?

			esi_string = ""
			for character_number in range(0, 19):
				print("")
				character = Byte(esi+character_number)
				print("character_number=%d") % character_number
				print("character 0x%x %d %s") % (character, character, character)
				#print("char=%d %x %s") % (character, character, chr(character))
				esi_string = esi_string + chr(character)

			print("user entered the password:%s\n") % esi_string

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


# Remove an existing debug hook
try:
	if debughook:
		print "Removing previous hook ...\n"
		debughook.unhook()
except:
	pass

# memory address at which the BYTE opcode 74 (jz) needs to be patched to 75 (jnz)
ea = 0x401241

	
# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0

# Add a breakpoint at address 0x401241 (right at the instruction we want to modify)
# Adding like this enables the breakpoint as well
AddBpt(ea)

# set breakpoint at location where was can get user-entered password
AddBpt(0x401370)

# Stop at the break point "ea"
request_run_to(ea)

# Start debugging
run_requests()