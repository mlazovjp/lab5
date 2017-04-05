print "Hello Lab5\n"


#need to patch byte 841 from 74 (jz) to 75 (jnz)

## Reset to op code 74 (jz)
PatchByte(0x401241, 0x74)
print("BYTE @ 0x401241 is [0x%X]\n" % (Byte(0x401241)))

#Patch op code to 75 (jnz)
PatchByte(0x401241, 0x75)
print("BYTE @ 0x401241 has been patched to [0x%X]\n" % (Byte(0x401241)))