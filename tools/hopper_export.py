save_loc = Document.askDirectory('Object file save location', None)
if save_loc is not None:
    class CodeObject(object):
	    def __init__(self, type="unknown", name="unknown", address=0, arr_count=0):
		    self.type = type
		    self.name = name
		    self.address = address
		    self.arr_count = arr_count
    
    objects = []
    
    doc = Document.getCurrentDocument()
    for seg in doc.getSegmentsList():
        doc.log('Exporting segment %s' % seg.getName())
        for label_name in seg.labelIterator():
            addr = doc.getAddressForName(label_name)
            type = seg.getTypeAtAddress(addr)
            length = seg.getObjectLength(addr)
            if type == Segment.TYPE_INT8:
                objects.append(CodeObject('BYTE', label_name, addr, length))
            elif type == Segment.TYPE_INT16:
                objects.append(CodeObject('WORD', label_name, addr, length // 2))
            elif type == Segment.TYPE_INT32:
                if doc.getOperandFormat(addr, 0) == Document.FORMAT_FLOAT:
                    objects.append(CodeObject('FLOAT', label_name, addr, length // 4))
                else:
                    objects.append(CodeObject('DWORD', label_name, addr, length // 4))
            elif type == Segment.TYPE_INT64:
                if doc.getOperandFormat(addr, 0) == Document.FORMAT_FLOAT:
                    objects.append(CodeObject('DOUBLE', label_name, addr, length // 8))
                else:
                    objects.append(CodeObject('QWORD', label_name, addr, length // 8))
            elif type == Segment.TYPE_ASCII:
                objects.append(CodeObject('STR', label_name, addr, length))
            elif type == Segment.TYPE_UNICODE:
                objects.append(CodeObject('WSTR', label_name, addr, length))
            elif type == Segment.TYPE_PROCEDURE:
                objects.append(CodeObject('FUNC', label_name, addr, length))
                proc = seg.getProcedureAtAddress(addr)
                for lvar in proc.getLocalVariableList():
                    if not lvar.name().startswith('var_') and not lvar.name().startswith('arg_'):
                        objects.append(CodeObject('LVAR', lvar.name(), addr, lvar.displacement()))
        for addr in range(seg.getStartingAddress(), seg.getStartingAddress() + seg.getLength()):
            comm = seg.getInlineCommentAtAddress(addr)
            if comm is None:
                comm = seg.getCommentAtAddress(addr)
            if comm is not None:
                comm = comm.split('\n')[0]
                if comm:
                    objects.append(CodeObject('COMM', comm, addr))

    doc.log('Sorting objects')
    objects = sorted(objects, key=lambda x: x.address)

    doc.log('Writing objects')
    with open(save_loc + '/map', 'w') as file:
        file.write('.text\n')
        for obj in objects:
            if obj.name != "unknown" and obj.type == 'FUNC':
			    file.write('%08X %08X %08X 0 %s\n' % (obj.address, obj.arr_count, obj.address, obj.name))

    with open(save_loc + '/objects', 'w') as file:
        for obj in objects:
            if obj.name != "unknown":
			    file.write('%08X %s %X %s\n' % (obj.address, obj.type, obj.arr_count, obj.name))
