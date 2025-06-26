from hbctool.util import *
from .parser import parse, export, INVALID_LENGTH
from .translator import disassemble, assemble
from struct import pack, unpack

NullTag = 0
TrueTag = 1 << 4
FalseTag = 2 << 4
NumberTag = 3 << 4
LongStringTag = 4 << 4
ShortStringTag = 5 << 4
ByteStringTag = 6 << 4
IntegerTag = 7 << 4
TagMask = 0x70

class HBC96:
    def __init__(self, f=None):
        if f:
            self.obj = parse(f)
        else:
            self.obj = None

    def export(self, f):
        export(self.getObj(), f)

    def getObj(self):
        assert self.obj, "Obj is not set."
        return self.obj

    def setObj(self, obj):
        self.obj = obj

    def getVersion(self):
        return 96

    def getHeader(self):
        return self.getObj()["header"]

    def getFunctionCount(self):
        return self.getObj()["header"]["functionCount"]

    def getFunction(self, fid, disasm=True):
        assert fid >= 0 and fid < self.getFunctionCount(), "Invalid function ID"

        functionHeader = self.getObj()["functionHeaders"][fid]
        offset = functionHeader["offset"]
        paramCount = functionHeader["paramCount"]
        registerCount = functionHeader["frameSize"]
        symbolCount = functionHeader["environmentSize"]
        bytecodeSizeInBytes = functionHeader["bytecodeSizeInBytes"]
        functionName = functionHeader["functionName"]

        instOffset = self.getObj()["instOffset"]
        start = offset - instOffset
        end = start + bytecodeSizeInBytes
        bc = self.getObj()["inst"][start:end]
        insts = bc
        if disasm:
            insts = disassemble(bc)
        
        functionNameStr, _ = self.getString(functionName)

        return functionNameStr, paramCount, registerCount, symbolCount, insts, functionHeader
    
    def setFunction(self, fid, func, disasm=True):
        assert fid >= 0 and fid < self.getFunctionCount(), "Invalid function ID"

        functionName, paramCount, registerCount, symbolCount, insts, _ = func

        functionHeader = self.getObj()["functionHeaders"][fid]

        functionHeader["paramCount"] = paramCount
        functionHeader["frameSize"] = registerCount
        functionHeader["environmentSize"] = symbolCount

        # TODO : Make this work
        # functionHeader["functionName"] = functionName

        offset = functionHeader["offset"]
        bytecodeSizeInBytes = functionHeader["bytecodeSizeInBytes"]

        instOffset = self.getObj()["instOffset"]
        start = offset - instOffset
        
        bc = insts

        if disasm:
            bc = assemble(insts)
            
        # assert len(bc) <= bytecodeSizeInBytes, "Overflowed instruction length is not supported yet."
        # functionHeader["bytecodeSizeInBytes"] = len(bc)
        
        # Handle bytecode overflow
        if len(bc) > bytecodeSizeInBytes:
            # Extend the instruction buffer if needed
            if start + len(bc) > len(self.getObj()["inst"]):
                # Extend the instruction buffer
                extension_needed = start + len(bc) - len(self.getObj()["inst"])
                self.getObj()["inst"].extend([0] * extension_needed)
        
        # Check if we need to use the overflow mechanism (when size exceeds 15-bit limit)
        if len(bc) > (1 << 15) - 1:  # 15-bit limit for SmallFuncHeader
            # Set the overflowed flag (bit 5 in flags)
            functionHeader["flags"] = functionHeader.get("flags", 0) | (1 << 5)
            
            # If not already overflowed, create the small header backup
            if "small" not in functionHeader:
                # Save the current header as small header for future export
                functionHeader["small"] = {}
                for key in ["offset", "paramCount", "bytecodeSizeInBytes", "functionName", 
                           "infoOffset", "frameSize", "environmentSize", "highestReadCacheIndex", 
                           "highestWriteCacheIndex", "flags"]:
                    if key in functionHeader:
                        functionHeader["small"][key] = functionHeader[key]
                
                # Ensure the small header has the truncated bytecode size (15-bit max)
                functionHeader["small"]["bytecodeSizeInBytes"] = min(bytecodeSizeInBytes, (1 << 15) - 1)
                functionHeader["small"]["flags"] = functionHeader["flags"]
            
            # Update the full header with new bytecode size (32-bit)
            functionHeader["bytecodeSizeInBytes"] = len(bc)
        else:
            # Can fit in 15 bits, just update the size normally
            functionHeader["bytecodeSizeInBytes"] = len(bc)
            
        memcpy(self.getObj()["inst"], bc, start, len(bc))
        
    def getStringCount(self):
        return self.getObj()["header"]["stringCount"]

    def getString(self, sid):
        assert sid >= 0 and sid < self.getStringCount(), "Invalid string ID"

        stringTableEntry = self.getObj()["stringTableEntries"][sid]
        stringStorage = self.getObj()["stringStorage"]
        stringTableOverflowEntries = self.getObj()["stringTableOverflowEntries"]

        isUTF16 = stringTableEntry["isUTF16"]
        offset = stringTableEntry["offset"]
        length = stringTableEntry["length"]

        if length >= INVALID_LENGTH:
            stringTableOverflowEntry = stringTableOverflowEntries[offset]
            offset = stringTableOverflowEntry["offset"]
            length = stringTableOverflowEntry["length"]

        if isUTF16:
            length*=2

        s = bytes(stringStorage[offset:offset + length])
        return s.hex() if isUTF16 else s.decode("utf-8"), (isUTF16, offset, length)
    
    def setString(self, sid, val):
        assert sid >= 0 and sid < self.getStringCount(), "Invalid string ID"

        stringTableEntry = self.getObj()["stringTableEntries"][sid]
        stringStorage = self.getObj()["stringStorage"]
        stringTableOverflowEntries = self.getObj()["stringTableOverflowEntries"]

        isUTF16 = stringTableEntry["isUTF16"]
        offset = stringTableEntry["offset"]
        length = stringTableEntry["length"]

        if length >= INVALID_LENGTH:
            stringTableOverflowEntry = stringTableOverflowEntries[offset]
            offset = stringTableOverflowEntry["offset"]
            length = stringTableOverflowEntry["length"]
        
        if isUTF16:
            s = list(bytes.fromhex(val))
            l = len(s)//2
        else:
            l = len(val)
            s = val.encode("utf-8")
        
        assert l <= length, "Overflowed string length is not supported yet."

        memcpy(stringStorage, s, offset, len(s))
        
    def _checkBufferTag(self, buf, iid):
        keyTag = buf[iid]
        if keyTag & 0x80:
            return (((keyTag & 0x0f) << 8) | (buf[iid + 1]), keyTag & TagMask)
        else:
            return (keyTag & 0x0f, keyTag & TagMask)

    def _SLPToString(self, tag, buf, iid, ind):
        start = iid + ind
        if tag == ByteStringTag:
            type = "String"
            val = buf[start]
            ind += 1
        elif tag == ShortStringTag:
            type = "String"
            val = unpack("<H", bytes(buf[start:start+2]))[0]
            ind += 2
        elif tag == LongStringTag:
            type = "String"
            val = unpack("<L", bytes(buf[start:start+4]))[0]
            ind += 4
        elif tag == NumberTag:
            type = "Number"
            val = unpack("<d", bytes(buf[start:start+8]))[0]
            ind += 8
        elif tag == IntegerTag:
            type = "Integer"
            val = unpack("<L", bytes(buf[start:start+4]))[0]
            ind += 4
        elif tag == NullTag:
            type = "Null"
            val = None
        elif tag == TrueTag:
            type = "Boolean"
            val = True
        elif tag == FalseTag:
            type = "Boolean"
            val = False
        else:
            type = "Empty"
            val = None
        
        return type, val, ind

    def getArrayBufferSize(self):
        return self.getObj()["header"]["arrayBufferSize"]

    def getArray(self, aid):
        assert aid >= 0 and aid < self.getArrayBufferSize(), "Invalid Array ID"
        tag = self._checkBufferTag(self.getObj()["arrayBuffer"], aid)
        ind = 2 if tag[0] > 0x0f else 1
        arr = []
        t = None
        for _ in range(tag[0]):
            t, val, ind = self._SLPToString(tag[1], self.getObj()["arrayBuffer"], aid, ind)
            arr.append(val)
        
        return t, arr

    def getObjKeyBufferSize(self):
        return self.getObj()["header"]["objKeyBufferSize"]

    def getObjKey(self, kid):
        assert kid >= 0 and kid < self.getObjKeyBufferSize(), "Invalid ObjKey ID"
        tag = self._checkBufferTag(self.getObj()["objKeyBuffer"], kid)
        ind = 2 if tag[0] > 0x0f else 1
        keys = []
        t = None
        for _ in range(tag[0]):
            t, val, ind = self._SLPToString(tag[1], self.getObj()["objKeyBuffer"], kid, ind)
            keys.append(val)
        
        return t, keys

    def getObjValueBufferSize(self):
        return self.getObj()["header"]["objValueBufferSize"]

    def getObjValue(self, vid):
        assert vid >= 0 and vid < self.getObjValueBufferSize(), "Invalid ObjValue ID"
        tag = self._checkBufferTag(self.getObj()["objValueBuffer"], vid)
        ind = 2 if tag[0] > 0x0f else 1
        keys = []
        t = None
        for _ in range(tag[0]):
            t, val, ind = self._SLPToString(tag[1], self.getObj()["objValueBuffer"], vid, ind)
            keys.append(val)
        
        return t, keys
