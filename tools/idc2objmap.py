#!/usr/bin/env python

# radare - LGPL - Copyright 2013 - xvilka
# modified by AxioDL for outputting object/map file pair

import re
import sys

class Func(object):
# FIXME: parse ftype into params and values
	def __init__(self, name="unknown", frame=0, params=[], values=[], address=0, size=0, ftype=""):
		self.name = name
		self.frame = frame
		self.params = params
		self.values = values
		self.address = address
		self.size = size
		self.ftype = ftype

class Llabel(object):
	def __init__(self, name="unknown", address=0):
		self.name = name
		self.address = address

class Comm(object):
	def __init__(self, text="", address=0):
		self.text = text
		self.address = address

class Enum(object):
	def __init__(self, name="unknown", members=[]):
		self.name = name
		self.members = members

class Struct(object):
	def __init__(self, name="unknown", members=[]):
		self.name = name
		self.members = members

class Union(object):
	def __init__(self, name="unknown", members=[]):
		self.name = name
		self.members = members

class Type(object):
	def __init__(self, name="unknown"):
		self.name = name
		self.members = members

class Lvar(object):
	def __init__(self, name="unknown", address=0, bpdisp=0):
		self.name = name
		self.address = address
		self.bpdisp = bpdisp

class CodeObject(object):
	def __init__(self, type="unknown", name="unknown", address=0, arr_count=0):
		self.type = type
		self.name = name
		self.address = address
		self.arr_count = arr_count

# -----------------------------------------------------------------------

functions = []
llabels = []
comments = []
structs = []
enums = []
types = []
objects = []

def functions_parse(idc):
	global objects

	# MakeFunction (0XF3C99,0XF3CA8);
	mkfun_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeFunction[ \t]*\(
		(?P<fstart>0[xX][\dA-Fa-f]{1,8})	# Function start
		[ \t]*\,[ \t]*
		(?P<fend>0[xX][\dA-Fa-f]{1,8})		# Function end
		[ \t]*\);[ \t]*$
		""", re.VERBOSE)
	mkfun_group_name = dict([(v,k) for k,v in mkfun_re.groupindex.items()])
	mkfun = mkfun_re.finditer(idc)
	for match in mkfun :
		fun = Func()
		obj = CodeObject('FUNC')
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkfun_group_name[group_index+1] == "fstart" :
					fun.address = int(group, 16)
					obj.address = int(group, 16)
				if mkfun_group_name[group_index+1] == "fend" :
					fun.size = int(group, 16) - fun.address
		functions.append(fun)
		objects.append(obj)

	# MakeStr (0XF3C99,0XF3CA8);
	mkstr_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeStr[ \t]*\(
		(?P<sstart>0[xX][\dA-Fa-f]{1,8})	# String start
		[ \t]*\,[ \t]*
		(?P<send>0[xX][\dA-Fa-f]{1,8})		# String end
		[ \t]*\);[ \t]*$
		""", re.VERBOSE)
	mkstr_group_name = dict([(v,k) for k,v in mkstr_re.groupindex.items()])
	mkstr = mkstr_re.finditer(idc)
	for match in mkstr :
		obj = CodeObject('STR')
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkstr_group_name[group_index+1] == "sstart" :
					obj.address = int(group, 16)
				if mkstr_group_name[group_index+1] == "send" :
					obj.arr_count = int(group, 16) - obj.address
		objects.append(obj)

	# MakeDword (0XF3C99);
	mkdword_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeDword[ \t]*\(
		(?P<addr>0[xX][\dA-Fa-f]{1,8})		# Address
		[ \t]*\);[ \t]*$
		""", re.VERBOSE)
	mkdword_group_name = dict([(v,k) for k,v in mkdword_re.groupindex.items()])
	mkdword = mkdword_re.finditer(idc)
	for match in mkdword :
		obj = CodeObject('DWORD')
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkdword_group_name[group_index+1] == "addr" :
					obj.address = int(group, 16)
		objects.append(obj)

	# MakeWord (0XF3C99);
	mkword_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeWord[ \t]*\(
		(?P<addr>0[xX][\dA-Fa-f]{1,8})		# Address
		[ \t]*\);[ \t]*$
		""", re.VERBOSE)
	mkword_group_name = dict([(v,k) for k,v in mkword_re.groupindex.items()])
	mkword = mkword_re.finditer(idc)
	for match in mkword :
		obj = CodeObject('WORD')
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkword_group_name[group_index+1] == "addr" :
					obj.address = int(group, 16)
		objects.append(obj)

	# MakeByte (0XF3C99);
	mkbyte_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeByte[ \t]*\(
		(?P<addr>0[xX][\dA-Fa-f]{1,8})		# Address
		[ \t]*\);[ \t]*$
		""", re.VERBOSE)
	mkbyte_group_name = dict([(v,k) for k,v in mkbyte_re.groupindex.items()])
	mkbyte = mkbyte_re.finditer(idc)
	for match in mkbyte :
		obj = CodeObject('BYTE')
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkbyte_group_name[group_index+1] == "addr" :
					obj.address = int(group, 16)
		objects.append(obj)

	# MakeFloat (0XF3C99);
	mkfloat_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeFloat[ \t]*\(
		(?P<addr>0[xX][\dA-Fa-f]{1,8})		# Address
		[ \t]*\);[ \t]*$
		""", re.VERBOSE)
	mkfloat_group_name = dict([(v,k) for k,v in mkfloat_re.groupindex.items()])
	mkfloat = mkfloat_re.finditer(idc)
	for match in mkfloat :
		obj = CodeObject('FLOAT')
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkfloat_group_name[group_index+1] == "addr" :
					obj.address = int(group, 16)
		objects.append(obj)

	# MakeDouble (0XF3C99);
	mkdouble_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeDouble[ \t]*\(
		(?P<addr>0[xX][\dA-Fa-f]{1,8})		# Address
		[ \t]*\);[ \t]*$
		""", re.VERBOSE)
	mkdouble_group_name = dict([(v,k) for k,v in mkdouble_re.groupindex.items()])
	mkdouble = mkdouble_re.finditer(idc)
	for match in mkdouble :
		obj = CodeObject('DOUBLE')
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkdouble_group_name[group_index+1] == "addr" :
					obj.address = int(group, 16)
		objects.append(obj)

	# MakeFrame (0XF3C99, 0, 0, 0);
	mkframe_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeFrame[ \t]*\(
		(?P<fstart>0[xX][\dA-Fa-f]{1,8})	# Function start
		[ \t]*\,[ \t]*
		(?P<fframe>0[xX]?[\dA-Fa-f]{0,8})	# Function frame
		[ \t]*\,[ \t]*
		(?P<dc0>0[xX]?[\dA-Fa-f]{0,8})		# Don't care 0
		[ \t]*\,[ \t]*
		(?P<dc1>0[xX]?[\dA-Fa-f]{0,8})		# Don't care 1
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)
	mkframe_group_name = dict([(v,k) for k,v in mkframe_re.groupindex.items()])
	mkframe = mkframe_re.finditer(idc)
	for match in mkframe :
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkframe_group_name[group_index+1] == "fstart" :
					addr = int(group, 16)
				if mkframe_group_name[group_index+1] == "fframe" :
					for fun in functions :
						if fun.address == addr :
							fun.frame = int(group, 16)

	# MakeLocal (0xF3CA0, 0xF3CA8, "[bp+/-0X38]", "name");
	mklocal_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeLocal[ \t]*\(
		(?P<astart>0[xX][\dA-Fa-f]{1,8})	# Start address
		[ \t]*\,[ \t]*
		(?P<aend>0[xX][\dA-Fa-f]{1,8})		# End address
		[ \t]*\,[ \t]*
		"\[bp(?P<bpdisp>.*)\]"				# Base pointer displacement
		[ \t]*\,[ \t]*
		"(?P<lname>.*)"						# Local name
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)
	mklocal_group_name = dict([(v,k) for k,v in mklocal_re.groupindex.items()])
	mklocal = mklocal_re.finditer(idc)
	for match in mklocal :
		obj = CodeObject('LVAR')
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mklocal_group_name[group_index+1] == "astart" :
					obj.address = int(group, 16)
				if mklocal_group_name[group_index+1] == "bpdisp" :
					for fun in functions :
						if fun.address == obj.address :
							obj.arr_count = fun.frame + int(group, 16)
				if mklocal_group_name[group_index+1] == "lname" :
					obj.name = group
		objects.append(obj)

	objects = sorted(objects, key=lambda x: x.address)

	# MakeArray (0XF3C99,0X3);
	mkarr_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeArray[ \t]*\(
		(?P<aaddr>0[xX][\dA-Fa-f]{1,8})		# Array Address
		[ \t]*\,[ \t]*
		(?P<acount>0[xX][\dA-Fa-f]{1,8})	# Array Count
		[ \t]*\);[ \t]*$
		""", re.VERBOSE)
	mkarr_group_name = dict([(v,k) for k,v in mkarr_re.groupindex.items()])
	mkarr = mkarr_re.finditer(idc)
	for match in mkarr :
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkarr_group_name[group_index+1] == "aaddr" :
					addr = int(group, 16)
				if mkarr_group_name[group_index+1] == "acount" :
					for obj in objects :
						if obj.address == addr :
							obj.arr_count = int(group, 16)

	# SetFunctionFlags (0XF3C99, 0x400);
	mkfunflags_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*SetFunctionFlags[ \t*]\(
		(?P<fstart>0[xX][\dA-Fa-f]{1,8})	# Function start
		[ \t]*\,[ \t]*
		(?P<flags>0[xX][\dA-Fa-f]{1,8})		# Flags
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)
	mkfunflags_group_name = dict([(v,k) for k,v in mkfunflags_re.groupindex.items()])
	mkfunflags = mkfunflags_re.finditer(idc)
	for match in mkfunflags :
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkfunflags_group_name[group_index+1] == "fstart" :
					addr = int(group, 16)
				if mkfunflags_group_name[group_index+1] == "flags" :
					for fun in functions :
						if fun.address == addr :
							pass # TODO: parse flags

	# MakeName (0XF3C99, "SIO_port_setup_S");
	mkname_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeName[ \t]*\(
		(?P<fstart>0[xX][\dA-Fa-f]{1,8})	# Function start
		[ \t]*\,[ \t]*
		"(?P<fname>.*)"						# Function name
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)
	mkname_group_name = dict([(v,k) for k,v in mkname_re.groupindex.items()])
	mkname = mkname_re.finditer(idc)
	for match in mkname :
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkname_group_name[group_index+1] == "fstart" :
					addr = int(group, 16)
				if mkname_group_name[group_index+1] == "fname" :
					for fun in functions :
						if fun.address == addr :
							fun.name = group
					for obj in objects :
						if obj.address == addr and obj.type != 'LVAR' :
							obj.name = group

	# SetType (0XFFF72, "__int32 __cdecl PCI_ByteWrite_SL(__int32 address, __int32 value)");
	mkftype_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*SetType[ \t]*\(
		(?P<fstart>0[xX][\dA-Fa-f]{1,8})	# Function start
		[ \t]*\,[ \t]*
		"(?P<ftype>.*)"						# Function type
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)
	mkftype_group_name = dict([(v,k) for k,v in mkftype_re.groupindex.items()])
	mkftype = mkftype_re.finditer(idc)
	for match in mkftype :
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkftype_group_name[group_index+1] == "fstart" :
					addr = int(group, 16)
				if mkftype_group_name[group_index+1] == "ftype" :
					for fun in functions :
						if fun.address == addr :
							fun.ftype = group

	# MakeNameEx (0xF3CA0, "return", SN_LOCAL);
	mknameex_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeNameEx[ \t]*\(
		(?P<laddr>0[xX][\dA-Fa-f]{1,8})		# Local label address
		[ \t]*\,[ \t]*
		"(?P<lname>.*)"						# Local label name
		[ \t]*\,[ \t]*SN_LOCAL
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)
	mknameex_group_name = dict([(v,k) for k,v in mknameex_re.groupindex.items()])
	mkname = mknameex_re.finditer(idc)
	for match in mkname :
		lab = Llabel()
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mknameex_group_name[group_index+1] == "laddr" :
					lab.address = int(group, 16)
				if mknameex_group_name[group_index+1] == "lname" :
					lab.name = group
		llabels.append(lab)

# ----------------------------------------------------------------------

def enums_parse(idc):
	pass

# ----------------------------------------------------------------------

def structs_parse(idc):
	# id = AddStrucEx (-1, "struct_MTRR", 0);
	mkstruct_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*id[ \t]*=[ \t]*AddStrucEx[ \t]*\(
		[ \t]*-1[ \t]*,[ \t]*
		"(?P<sname>.*)"						# Structure name
		[ \t]*\,[ \t]*0
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)
	mkstruct_group_name = dict([(v,k) for k,v in mkstruct_re.groupindex.items()])
	mkstruct = mkstruct_re.finditer(idc)
	for match in mkstruct :
		s = Struct()
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkstruct_group_name[group_index+1] == "sname" :
					s.name = group
		structs.append(s)

	# Case 1: not nested structures
	# =============================
	# id = GetStrucIdByName ("struct_header");
	# mid = AddStructMember(id,"BCPNV", 0, 0x5000c500, 0, 7);
	# mid = AddStructMember(id,"_", 0X7, 0x00500, -1, 1);
	# mid = AddStructMember(id, "BCPNV_size",0X8, 0x004500, -1, 1);
	mkstruct_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*id[ \t]*=[ \t]*GetStrucIdByName[ \t]*\(
		[ \t]*-1[ \t]*,[ \t]*
		"(?P<sname>.*)"						# Structure name
		[ \t]*\,[ \t]*0
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)

# ----------------------------------------------------------------------

def comments_parse(idc):
	global objects

	regequals_re = re.compile("""r[0-9]+\s*=""", re.VERBOSE)

	# MakeComm (0XFED3D, "PCI class 0x600 - Host/PCI bridge");
	mkcomm_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeComm[ \t]*\(
		(?P<caddr>0[xX][\dA-Fa-f]{1,8})		# Comment address
		[ \t]*\,[ \t]*
		"(?P<ctext>.*)"						# Comment
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)
	mkcomm_group_name = dict([(v,k) for k,v in mkcomm_re.groupindex.items()])
	mkcomm = mkcomm_re.finditer(idc)
	for match in mkcomm :
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkcomm_group_name[group_index+1] == "caddr" :
					address = int(group, 16)
				if mkcomm_group_name[group_index+1] == "ctext" :
					if regequals_re.match(group) :
						break
					com_multi = group.split('\\n')
					for a in com_multi :
						com = Comm()
						com.address = address
						com.text = a
						comments.append(com)
						objects.append(CodeObject('COMM', a, address))

# ----------------------------------------------------------------------

#	print("af+ 0x%08lx %d %s" % (func.address, func.size, func.name))

def generate_r2():
	for f in functions :
		if f.name != "unknown" :
			print("\"af+ {0} {1}\"".format(hex(f.address), f.name))
			print("f+\"{1}\" {2} @ {0}".format(hex(f.address), f.name.replace('@', '_'), f.size))
			#print("\"CCa {0} {1}\"".format(hex(f.address), f.ftype))

	for l in llabels :
		if l.name != "unknown" :
			for f in functions :
				if (l.address > f.address) and (l.address < (f.address + f.size)) :
					print("f. {0} @ {1}".format(l.name, hex(l.address)))

	for c in comments :
		if c.text != "" :
			print("\"CCa {0} {1}\"".format(c.address, c.text))

# ----------------------------------------------------------------------

def generate_files():
	with open('map', 'w') as file :
		file.write('.text\n')
		for f in functions :
			if f.name != "unknown" :
				file.write('%08X %08X %08X 0 %s\n' % (f.address, f.size, f.address, f.name))

	with open('objects', 'w') as file :
		for obj in objects :
			if obj.name != "unknown" :
				file.write('%08X %s %X %s\n' % (obj.address, obj.type, obj.arr_count, obj.name))

# ----------------------------------------------------------------------

def idc_parse(idc):
	enums_parse(idc)
	structs_parse(idc)
	comments_parse(idc)
	functions_parse(idc)
	#generate_r2()
	generate_files()

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("Usage: idc2objmap.py input.idc")
		sys.exit(1)

	#print(sys.argv[1])
	idc_file = open(sys.argv[1], "r")
	idc = idc_file.read()
	idc_parse(idc)
