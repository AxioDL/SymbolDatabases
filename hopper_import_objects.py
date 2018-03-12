doc = Document.getCurrentDocument()
file_path = Document.askFile('Select Objects File', None, False)
if file_path is not None:
    with open(file_path, 'r') as file:
        while True:
            l = file.readline()
            if not l:
                break
            parts = l.split(' ', 3)
            address = int(parts[0], 16)
            segment = doc.getSegmentAtAddress(address)
            if segment is None:
                continue
            arr_count = int(parts[2], 10)
            if parts[1] == 'FUNC':
                if segment.getTypeAtAddress(address) != Segment.TYPE_PROCEDURE:
                    segment.markAsProcedure(address)
            elif parts[1] == 'STR':
                segment.setTypeAtAddress(address, arr_count, Segment.TYPE_ASCII)
            elif parts[1] == 'WSTR':
                segment.setTypeAtAddress(address, arr_count, Segment.TYPE_UNICODE)
            elif parts[1] == 'BYTE':
                if arr_count:
                    segment.setTypeAtAddress(address, arr_count, Segment.TYPE_INT8)
                else:
                    segment.setTypeAtAddress(address, 1, Segment.TYPE_INT8)
            elif parts[1] == 'WORD':
                if arr_count:
                    segment.setTypeAtAddress(address, arr_count, Segment.TYPE_INT16)
                else:
                    segment.setTypeAtAddress(address, 2, Segment.TYPE_INT16)
            elif parts[1] == 'DWORD':
                if arr_count:
                    segment.setTypeAtAddress(address, arr_count, Segment.TYPE_INT32)
                else:
                    segment.setTypeAtAddress(address, 4, Segment.TYPE_INT32)
            elif parts[1] == 'FLOAT':
                if arr_count:
                    segment.setTypeAtAddress(address, arr_count, Segment.TYPE_INT32)
                else:
                    segment.setTypeAtAddress(address, 4, Segment.TYPE_INT32)
                doc.setOperandFormat(address, 0, Document.FORMAT_FLOAT)
            elif parts[1] == 'DOUBLE':
                if arr_count:
                    segment.setTypeAtAddress(address, arr_count, Segment.TYPE_INT64)
                else:
                    segment.setTypeAtAddress(address, 8, Segment.TYPE_INT64)
                doc.setOperandFormat(address, 0, Document.FORMAT_FLOAT)
            segment.setNameAtAddress(address, parts[3])
