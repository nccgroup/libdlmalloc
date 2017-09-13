# libdlmalloc_26x.py
#
# This file is part of libdlmalloc.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# Some parts of this code were taken from libheap, a ptmalloc2 GDB
# plugin: https://github.com/cloudburst/libheap
#
# Some gdb argument handling functions were taken and/or inspired from
# https://github.com/0vercl0k/stuffz/blob/master/dps_like_for_gdb.py
#
# The show_last_exception() code was derived from https://github.com/hugsy/gef
#
# Note libdmalloc_26x was primarily tested on 2.6.3i?, which is not the latest
# version.
#
# Note this has been heavily ported from libdlmalloc_28x.py so it may not actually
# be close enough to malloc-2.6.3i.c. It still contains lots of 2.8.x
# references that need to be cleaned up.
#
# See http://gee.cs.oswego.edu/pub/misc/malloc-2.6.7.c
#
# TODO
# - support IS_MMAPPED

from __future__ import print_function

import traceback
import importlib

try:
    import gdb
    is_gdb = True
except ImportError:
    is_gdb = False

from os.path import basename

import re
import sys, os, json
import struct
from functools import wraps

################################################################################
# HELPERS
################################################################################

# XXX - move to _gdb.py
# Taken from gef. Let's us see proper backtraces from python exceptions
def show_last_exception():
    PYTHON_MAJOR = sys.version_info[0]
    horizontal_line = "-"
    right_arrow = "->"
    down_arrow = "\\->"

    print("")
    exc_type, exc_value, exc_traceback = sys.exc_info()
    print(" Exception raised ".center(80, horizontal_line))
    print("{}: {}".format(exc_type.__name__, exc_value))
    print(" Detailed stacktrace ".center(80, horizontal_line))
    for fs in traceback.extract_tb(exc_traceback)[::-1]:
        if PYTHON_MAJOR==2:
            filename, lineno, method, code = fs
        else:
            try:
                filename, lineno, method, code = fs.filename, fs.lineno, fs.name, fs.line
            except:
                filename, lineno, method, code = fs

        print("""{} File "{}", line {:d}, in {}()""".format(down_arrow, filename,
                                                            lineno, method))
        print("   {}    {}".format(right_arrow, code))

# XXX - move to _gdb.py
def get_info():
    res = gdb.execute("maintenance info sections ?", to_string=True)
    bin_name = basename(build_bin_name(res))
    if not bin_name:
        raise("get_info: failed to find bin name")
    if bin_name[0] == '_':
        return bin_name[1:]
    return bin_name

# XXX - Not sure if these should go into dlmalloc()
# XXX - move to _gdb.py
def get_inferior():
    if not is_gdb:
        return
    try:
        if len(gdb.inferiors()) == 0:
            logmsg("No gdb inferior could be found.")
            return -1
        else:
            inferior = gdb.inferiors()[0]
            return inferior
    except AttributeError:
        logmsg("This gdb's python support is too old.")
        exit()

# XXX - move to _gdb.py
def has_inferior(f):
    "decorator to make sure we have an inferior to operate on"

    @wraps(f)
    def with_inferior(*args, **kwargs):
        inferior = get_inferior()
        if inferior != -1:
            if (inferior.pid != 0) and (inferior.pid is not None):
                return f(*args, **kwargs)
            else:
                logmsg("No debugee could be found.  Attach or start a program.")
                exit()
        else:
            exit()
    return with_inferior

# General class for most dlmalloc-related methods to avoid namespace overlap
# with other heap libraries we might load at the same time. Most helper methods
# try to match the macros from malloc-2.8.x.c files
class dl_helper:

    DLMALLOC_VERSION  = "2.6"

    MALLOC_ALIGNMENT  = 8
    SIZE_T_ZERO       = 0
    SIZE_T_ONE        = 1
    SIZE_T_TWO        = 2
    CHUNK_ALIGN_MASK  = MALLOC_ALIGNMENT - SIZE_T_ONE

    NSMALLBINS        = 32
    NTREEBINS         = 32
    SMALLBIN_SHIFT    = 3
    SMALLBIN_WIDTH    = SIZE_T_ONE << SMALLBIN_SHIFT
    TREEBIN_SHIFT     = 8
    MIN_LARGE_SIZE    = SIZE_T_ONE << TREEBIN_SHIFT
    MAX_SMALL_SIZE    = MIN_LARGE_SIZE - SIZE_T_ONE
    #MAX_SMALL_REQUEST = (MAX_SMALL_SIZE - CHUNK_ALIGN_MASK - CHUNK_OVERHEAD)

    PINUSE_BIT = 1
    IS_MMAPPED = 2
    SIZE_BITS = (PINUSE_BIT|IS_MMAPPED)

    # XXX - If we find the malloc_params struct in mem, we should update these
    DEFAULT_TRIM_THRESHOLD = 2 * 1024 * 1024

    treebin_sz = [ 0x180, 0x200, 0x300, 0x400, 0x600, 0x800, 0xc00, 0x1000,
        0x1800, 0x2000, 0x3000, 0x4000, 0x6000, 0x8000, 0xc000, 0x10000,
        0x18000, 0x20000, 0x30000, 0x40000, 0x60000, 0x80000, 0xc0000, 0x100000,
        0x180000, 0x200000, 0x300000, 0x400000, 0x600000, 0x800000, 0xc00000,
        0xffffffff]

    def __init__(self, size_sz=0):
        self.terse = True # XXX - This should be configurable
        # Non-gdb users will have to specify the size themselves
        if size_sz == 0:
            self.retrieve_sizesz()
        else:
            self.SIZE_SZ = size_sz

        self.INUSE_HDR_SZ      = 2 * self.SIZE_SZ
        self.FREE_HDR_SZ       = 4 * self.SIZE_SZ
        self.MAX_HDR_SZ        = self.FREE_HDR_SZ

        self.MIN_CHUNK_SZ      = 4 * self.SIZE_SZ
        self.MALLOC_ALIGNMENT  = 2 * self.SIZE_SZ
        self.MALLOC_ALIGN_MASK = self.MALLOC_ALIGNMENT - 1
        self.MINSIZE           = (self.MIN_CHUNK_SZ+self.MALLOC_ALIGN_MASK) & \
                                    ~self.MALLOC_ALIGN_MASK

        self.MSEGMENT_SZ       = 4 * self.SIZE_SZ

        # The MSTATE_SZ constants used here are a best guess. It will be
        # dynamically adjusted if found to be incorrect. We want this size to
        # be the largest possible though, so we always have enough memory to
        # figure it out.
        if self.SIZE_SZ == 4:
            self.MSTATE_SZ = 0x1dc
        elif self.SIZE_SZ == 8:
            self.MSTATE_SZ = 0x3b0

        self.MALLOC_PARAM_SZ = (self.SIZE_SZ * 5) + 4


        self.dlchunk_callback = None
        self.dlchunk_callback_cached = None
        self.cached_mstate = None
        self.colors = True

    def logmsg(self, s, end=None):
        if type(s) == str:
            if end != None:
                print("[libdlmalloc] " + s, end=end)
            else:
                print("[libdlmalloc] " + s)
        else:
            print(s)

    # XXX - move to _gdb.py
    def retrieve_sizesz(self):
        "Retrieve the SIZE_SZ after binary loading finished"

        _machine = self.get_arch()
        if "elf64" in _machine:
            self.SIZE_SZ = 8
        elif "elf32" in _machine:
            self.SIZE_SZ = 4
        else:
            raise Exception("Retrieving the SIZE_SZ failed.")

    def register_callback(self, func):
        self.dlchunk_callback = func
        self.logmsg("Registered new dlchunk callback")

    # XXX - move to _gdb.py
    def get_arch(self):
        res = gdb.execute("maintenance info sections ?", to_string=True)
        if "elf32-i386" in res and "elf64-x86-64" in res:
            raise("get_arch: could not determine arch (1)")
        if "elf32-i386" not in res and "elf64-x86-64" not in res:
            raise("get_arch: could not determine arch (2)")
        if "elf32-i386" in res:
            return "elf32-i386"
        elif "elf64-x86-64" in res:
            return "elf64-x86-64"
        else:
            raise("get_arch: failed to find arch")

    # This is the 64-bit version of the macro since the 32-bit uses inline asm
    def compute_tree_index(self, sz):
        x = sz >> self.TREEBIN_SHIFT
        if x == 0:
            return 0
        elif x > 0xffff:
            return self.NTREEBINS-1
        else:
            y = x
            n = ((y - 0x100) >> 16) & 8
            k = (((y << n) - 0x1000) >> 16) & 4
            n += k
            y <<= k
            k = ((y - 0x4000) >> 16) & 2
            n += k
            y <<= k
            k = 14 - n + (y >> 15)
            return (k << 1) + ((sz >> (k + (self.TREEBIN_SHIFT-1)) & 1))

    def chunk2mem(self, p):
        "conversion from malloc header to user pointer"
        return (p.address + (2 * self.SIZE_SZ))

    def mem2chunk(self, mem):
        "conversion from user pointer to malloc header"
        return (mem - (2 * self.SIZE_SZ))

    def request2size(self, req):
        "pad request bytes into a usable size"

        if (req + self.SIZE_SZ + self.MALLOC_ALIGN_MASK < self.MINSIZE):
            return self.MINSIZE
        else:
            return (int(req + self.SIZE_SZ + self.MALLOC_ALIGN_MASK) & \
                    ~self.MALLOC_ALIGN_MASK)

    def pinuse(self, p):
        "extract inuse bit of previous chunk"
        return (p.size & self.PINUSE_BIT)

    def chunksize(self, p):
        "Get size, ignoring use bits"
        return (p.size & ~self.SIZE_BITS)

    def ptr_from_chunk(self, p):
        return (p.address + p.hdr_size)

    def next_chunk(self, p):
        "Ptr to next physical malloc_chunk."
        return (p.address + (p.size & ~self.SIZE_BITS))

    def prev_chunk(self, p):
        "Ptr to previous physical malloc_chunk"
        return (p.address - p.prev_size)

    def next_pinuse(self, p):
        "extract next chunk's pinuse bit"
        chunk = dl_chunk(self, self.next_chunk(p), inuse=False)
        return self.pinuse(chunk)

    def chunk_plus_offset(self, p, s):
        "Treat space at ptr + offset as a chunk"
        return dl_chunk(self, p.address + s, inuse=False)

    def chunk_minus_offset(self, p, s):
        "Treat space at ptr - offset as a chunk"
        return dl_chunk(self, p.address - s, inuse=False)

    def set_cinuse(self, p):
        "set chunk as being inuse without otherwise disturbing"
        chunk = dl_chunk(self, (p.address + (p.size & ~self.SIZE_BITS)),
                            inuse=False)
        next_chunk = self.next_chunk(p)
        next_chunk.size |= self, self.PINUSE_BIT
        next_chunk.write()

    def clear_cinuse(self, p):
        "clear chunk as being inuse without otherwise disturbing"
        chunk = dl_chunk(self, (p.address + (p.size & ~self.SIZE_BITS)), 
                            inuse=False)
        next_chunk = self.next_chunk(p)
        next_chunk.size &= ~self.PINUSE_BIT
        next_chunk.write()

    def pinuse(self, p):
        "extract p's inuse bit"
        return (p.size & self.PINUSE_BIT)

    def set_pinuse(self, p):
        "set chunk as having prev_inuse without otherwise disturbing"
        chunk = dl_chunk(self, (p.address + (p.size & ~self.SIZE_BITS)), 
                            inuse=False)
        chunk.size |= self.PINUSE_BIT
        chunk.write()

    def clear_pinuse(self, p):
        "clear chunk as not having pre_inuse without otherwise disturbing"
        chunk = dl_chunk(self, (p.address + (p.size & ~self.SIZE_BITS)), 
                             inuse=False)
        chunk.size &= ~self.PINUSE_BIT
        chunk.write()

    def is_small(self, sz):
        "check if size is in smallbin range"
        return (sz < self.MIN_LARGE_SIZE)

    def small_index(self, sz):
        "return the smallbin index"

        if self.SMALLBIN_WIDTH == 16:
            return (sz >> 4)
        else:
            return (sz >> 3)

    # The very last chunk in a segment is free but does not have the PINUSE
    # flag set. This should never normally happen, because coalescing should
    # always force a free chunk to be adjacent to an inuse chunk. So we can
    # detect it. Size might always be 0x30 on 32-bit too? Not sure
    def is_end_chunk(self, p):
        if not self.next_pinuse(p) and not self.pinuse(p):
            return True
        return False

    def top(self, mstate):
        return mstate.top

    # XXX - This should decode the footer if it exists
    def mstate_for_ptr(self, ptr):
        "find the heap and corresponding mstate for a given ptr"
        return (ptr & ~(self.HEAP_MAX_SIZE-1))

    # XXX - move to _gdb.py
    def hexdump(self, p, maxlen=0, off=0):
        data = self.ptr_from_chunk(p) + off
        size = self.chunksize(p) - p.hdr_size - off
        if size < 0:
            self.logmsg("[!] Chunk corrupt? Bad size")
            return
        elif size == 0:
            self.logmsg("[!] Empty chunk?")
            return
        if maxlen != 0:
            if size > maxlen:
                size = maxlen
        print("0x%x bytes of chunk data:" % size)
        cmd = "x/%dwx 0x%x\n" % (size/4, data)
        gdb.execute(cmd, True)
        return

    def chunk_info(self, p):
        info = []
        info.append("0x%lx " % p.address)
        if self.next_pinuse(p):
            info.append("M ")
        else:
            info.append("F ")
        sz = self.chunksize(p)
        if sz == 0:
            self.logmsg("[!] Chunk at address 0x%.x invalid or corrupt?" % p.address)
        if self.terse:
            info.append("sz:0x%.05x " % sz)
        else:
            info.append("sz:0x%.08x " % sz)
        flag_str = ""
        if self.terse:
            info.append("fl:")
            if self.pinuse(p):
                flag_str += "P"
            else:
                flag_str += "-"
            info.append("%1s" % flag_str)

        else:
            info.append("flags: ")
            if self.pinuse(p):
                flag_str += "PINUSE"
            else:
                flag_str += "------"
            info.append("%6s" % flag_str)

        if self.dlchunk_callback != None:
            size = self.chunksize(p) - p.hdr_size
            cbinfo = {}
            cbinfo["caller"] = "dlchunk" # This is a lie but shouldn't matter
            cbinfo["allocator"] = "dlmalloc"
            cbinfo["version"] = self.DLMALLOC_VERSION
            cbinfo["addr"] = p.data_address
            cbinfo["hdr_sz"] = p.hdr_size
            cbinfo["chunksz"] = self.chunksize(p)
            cbinfo["min_hdr_sz"] = self.INUSE_HDR_SZ
            cbinfo["data_size"] = size
            cbinfo["inuse"] = p.inuse
            cbinfo["chunk_info"] = True
            cbinfo["size_sz"] = self.SIZE_SZ
            if p.from_mem:
                cbinfo["mem"] = p.mem[p.hdr_size:]

            extra = self.dlchunk_callback(cbinfo)
            info.append(" " + extra)

        return ''.join(info)

    def print_segment_chunks(self, seg=None, show_free=True, show_inuse=True, 
            sz=0, min_sz=0, max_sz=0):
        addr = seg.base
        while addr < (seg.base + seg.size):
            chunk = dl_chunk(self.dl, addr)
            chunksz = self.dl.chunksize(chunk)
            if min_sz != 0:
                if chunksz > min_sz:
                    continue
            if max_sz != 0:
                if chunksz > max_sz:
                    continue
            if sz != 0:
                if chunksz != sz:
                    continue
            if show_free != True and not self.dl.next_pinuse(chunk):
                continue
            if show_inuse != True and self.dl.next_pinuse(chunk):
                continue

            print(self.dl.chunk_info(chunk))
            addr += self.dl.chunksize(chunk)
        # Walk from the start showing each chunk, but only printing an 
        # abbreviated version.

    def print_mstate_chunks(self, addr=None, mstate=None, seg=None):
        cur_seg = mstate.seg
        while True:
            self.print_segment_chunks(cur_seg)
            if cur_seg.next == 0:
                break
            cur_seg = dl_msegment(self.dl, cur_seg.next)

    # XXX - anything that walks segments is redundant so should be done with
    # callbacks maybe?
    def print_mstate_segments(self, addr=None, mstate=None, seg=None):
        cur_seg = mstate.seg
        while True:
            print(cur_seg)
            if cur_seg.next == 0:
                break
            cur_seg = dl_msegment(self.dl, cur_seg.next)

    # XXX - This is broken atm.
    def search_heap(self, seg, search_for, min_size, max_size):
        "walk chunks searching for value starting from the seg address"
        results = []

        # XXX - Use global constants for 0x440 and 0x868
        if self.SIZE_SZ == 4:
            p = dl_chunk(seg) # need to fix
        elif self.SIZE_SZ == 8:
            # empiric offset: chunks start after the dl_mstate + offset
            p = dl_chunk(seg)
#        heap_size = heap_info(mstate_for_ptr(ar_ptr))

        while True:
            if self.chunksize(p) == 0x0:
                self.logmsg("sz=0x0 detected at 0x%x, assuming end of heap" 
                        % p.address)
                break
            if max_size == 0 or self.chunksize(p) <= max_size:
                if self.chunksize(p) >= min_size:
                    print(self.chunk_info(p)) # debug
                    if self.search_chunk(p, search_for):
                        results.append(p.address)
            p = dl_chunk(self.dl, addr=(p.address + self.chunksize(p)))
        return results

    def search_chunk(self, p, search_for, depth=0):
        "searches a chunk. includes the chunk header in the search"

        if depth == 0 or depth > self.chunksize(p):
            depth = self.chunksize(p)

        try:
            out_str = gdb.execute('find /1w 0x%x, 0x%x, %s' % \
                (p.address, p.address + depth, search_for), \
                to_string = True)
        except Exception:
            #print(sys.exc_info()[0])
            #print("[libdlmalloc] failed to execute 'find'")
            return False

        str_results = out_str.split('\n')

        for str_result in str_results:
            if str_result.startswith('0x'):
                return True

        return False

    # Assumes caller checked for cached mstate...
    def is_smallbin_empty(self, bidx):
        mstate = self.cached_mstate
        if mstate.smallmap & (1 << bidx):
            return False
        return True

    # Assumes caller checked for cached mstate...
    def is_treebin_empty(self, bidx):
        mstate = self.cached_mstate
        if mstate.treemap & (1 << bidx):
            return False
        return True

    # Count the number of entries in a smallbin
    # XXX - We could speed this up significantly by just reading the fd instead
    # of creating new chunks each time. Quite slow over serial
    def smallbin_count(self, bidx, depth=0, get_sz_set=False):
        sz_set = []
        if self.cached_mstate == None:
            print("Can't currently count bins without cached mstate")
            return None
        mstate = self.cached_mstate
        if bidx > len(mstate.smallbins):
            print("idx %d is outside of smallbin range")
            return None

        if not self.is_smallbin_empty(bidx):
            bins_addr = mstate.address + mstate.small_bins_off
            # Each index holds an fd and bck pointer
            bin_addr = bins_addr + (2*self.SIZE_SZ) * bidx
            # Due to trickery, the chunk address points to the "prev_size"
            # of the chunk which doesn't, actually exist. But we need to use
            # that address
            bin_addr -= 2*self.SIZE_SZ

            count = 1
            cur = dl_chunk(dl=self, addr=bin_addr)
            while cur.fd != bin_addr:
                count += 1
                if depth != 0 and count > depth:
                    return count
                cur = dl_chunk(dl=self, addr=cur.fd)
                if get_sz_set:
                    sz_set.append(self.chunksize(cur))
            if get_sz_set:
                print(sz_set)
            return count
        return 0

    def treebin_count_children(self, p, depth=0, sz_set=None):
        count = 0
        if sz_set != None:
            sz_set.append(self.chunksize(p))
        if p.left != 0:
            count += 1
            if depth != 0 and count > depth:
                return count
            chunk = dl_chunk(dl=self, addr=p.left)
            count += self.treebin_count_children(chunk, depth, sz_set)
        if p.right != 0:
            count += 1
            if depth != 0 and count > depth:
                return count
            chunk = dl_chunk(dl=self, addr=p.right)
            count += self.treebin_count_children(chunk, depth, sz_set)
        return count

    # Count the number of entries in a treebin
    def treebin_count(self, bidx, depth=0, get_sz_set=False):
        if get_sz_set:
            sz_set = []
        else:
            sz_set = None
        if self.cached_mstate == None:
            print("Can't currently count bins without cached mstate")
            return None
        mstate = self.cached_mstate
        if bidx > len(mstate.treebins):
            print("idx %d is outside of treebin range")
            return None
        if not self.is_treebin_empty(bidx):
            count = 1
            cur = dl_chunk(dl=self, addr=mstate.treebins[bidx])
            count += self.treebin_count_children(cur, depth, sz_set)
            if get_sz_set:
                print("bin sizes: " + ", ".join(("0x{:02x}".format(s) \
                                for s in sz_set)))
            return count

        return 0

    # XXX - fixme
    def print_smallbins(self, inferior, mstate=None):
        "walk and print the small bins"

        print("Smallbins")

        pad_width = 33

        if mstate == None and self.cached_mstate == None:
            self.logmsg("Don't know where mstate is and no address specified")
            return

        if mstate == None:
            mstate = self.cached_mstate
        else:
            mstate = dl_mstate(mstate)
            if mstate == None:
                self.logmsg("Can't print bins from bad mstate")
                return
            else:
                cached_mstate = mstate

        # XXX - This doesn't properly print everything
        for i in range(2, (self.NSMALLBINS+1), 2):

            print("")
            print("[ sb {:02} ] ".format(int(i/2)))
    #        print("{:#x}{:>{width}}".format(int(), "-> ", width=5), end="")
            print("[ {:#x} | {:#x} ] ".format(int(mstate.smallbins[i]), int(mstate.smallbins[i+1])))
            print("")

            nextc = dl_chunk(mstate.smallbins[i])
            while (1):
                if nextc.fd == mstate.smallbins[i]:
                    break
                print(self.chunk_info(nextc))
                nextc = dl_chunk(nextc.fd)
    #            print("")
    #            print("{:>{width}}{:#x} | {:#x} ] ".format("[ ", int(chunk.fd), int(chunk.bk), width=pad_width))
    #            print("({})".format(int(chunksize(chunk))), end="")
    #            fd = chunk.fd
    #
    #        if sb_num != None: #only print one smallbin
    #            return
    # XXX - this currently assumes p is a chunk vs mstate
    def dispatch_callback(self, p, debug=False, caller="dlchunk"):
        if self.dlchunk_callback != None:
            size = self.chunksize(p) - p.hdr_size
            if p.data_address != None:
                # We can provide an excess of information and the callback can
                # choose what to use
                cbinfo = {}
                cbinfo["caller"] = caller
                cbinfo["allocator"] = "dlmalloc"
                cbinfo["version"] = self.DLMALLOC_VERSION
                cbinfo["addr"] = p.data_address
                if p.from_mem:
                    cbinfo["mem"] = p.mem[p.hdr_size:]
                cbinfo["hdr_sz"] = p.hdr_size
                cbinfo["chunksz"] = self.chunksize(p)
                cbinfo["min_hdr_sz"] = self.INUSE_HDR_SZ
                cbinfo["data_size"] = size
                cbinfo["inuse"] = p.inuse
                cbinfo["size_sz"] = self.SIZE_SZ
                if debug:
                    cbinfo["debug"] = True
                # We expect callback to tell us how much data it
                # 'consumed' in printing out info
                return self.dlchunk_callback(cbinfo)
        return 0


################################################################################
# STRUCTURES
################################################################################

class dl_structure(object):

    def __init__(self, dl, inferior=None):
        self.dl     = dl
        self.is_x86 = dl.SIZE_SZ == 4
        self.address = None
        self.initOK = True

        if inferior == None:
            self.inferior = get_inferior()
            if self.inferior == -1:
                self.dl.logmsg("Error obtaining gdb inferior")
                self.initOK = False
                return
        else:
            self.inferior = inferior

    # XXX - move this to _gdb.py
    def _get_cpu_register(self, reg):
        """
        Get the value holded by a CPU register
        """

        expr = ''
        if reg[0] == '$':
            expr = reg
        else:
            expr = '$' + reg

        try:
            val = self._normalize_long(long(gdb.parse_and_eval(expr)))
        except Exception:
            self.dl.logmsg("[!] Did you run a process? Can't retrieve registers")
            return None
        return val

    def _normalize_long(self, l):
        return (0xffffffff if self.is_x86 else 0xffffffffffffffff) & l

    def _is_register(self, s):
        """
        Is it a valid register ?
        """
        x86_reg = ['eax', 'ebx', 'ecx', 'edx', 'esi',
                    'edi', 'esp', 'ebp', 'eip']
        x64_reg = ['rax', 'rbx', 'rcx', 'rdx', 'rsi',
                    'rdi', 'rsp', 'rbp', 'rip'] + \
                        ['r%d' % i for i in range(8, 16)]

        if s[0] == '$':
            s = s[1:]

        if s in (x86_reg if self.is_x86 else x64_reg):
            return True
        return False

    def _parse_base_offset(self, r):
        base = r
        offset = 0
        if "+" in r:
            # we assume it is a register or address + a hex value
            tmp = r.split("+")
            base = tmp[0]
            offset = int(tmp[1], 16)
        if "-" in r:
            # we assume it is a register or address - a hex value
            tmp = r.split("-")
            base = tmp[0]
            offset = int(tmp[1], 16)*-1
        if self._is_register(base):
            base = self._get_cpu_register(base)
            if not base:
                return None
        else:
            try:
                # we assume it's an address
                base = int(base, 16)
            except Exception:
                print('Error: not an address')
                return None
        return base, offset

    def validate_addr(self, addr):
        if addr == None or addr == 0:
            self.initOK = False
            self.address = None
            return False

        elif type(addr) == str:
            res = self._parse_base_offset(addr)
            if res == None:
                self.dl.logmsg('[!] first arg MUST be an addr or a register (+ optional offset)"')
                self.initOK = False
                return False
            self.address = res[0] + res[1]
        else:
            self.address = addr
        return True


################################################################################
class dl_chunk(dl_structure):
    "python representation of a struct malloc_chunk {} (malloc-2.8.3.c)"

    def __init__(self, dl, addr=None, mem=None, size=None, inferior=None, 
            inuse=None):
        # sets self.dl, self.inferior, and self.initOK
        dl_structure.__init__(self, dl, inferior)
        if not self.initOK:
            return

        self.prev_size   = 0
        self.size        = 0
        self.data        = None
        self.fd          = None
        self.bk          = None

        # Tree chunk specific
        self.left        = None
        self.right       = None
        self.parent      = None
        self.bindex      = None

        # Actual chunk flags
        self.cinuse_bit  = 0
        self.pinuse_bit  = 0
        self.mmapped_bit = 0

        # General indicator if we are inuse
        self.inuse       = inuse
        self.istree      = False

        self.data_address = None
        self.hdr_size = 0

        self.mem = mem
        self.from_mem = False

        # setup self.address
        if not self.validate_addr(addr):
            return

        if mem == None:
            # a string of raw memory was not provided
            try:
                # MAX_HDR_SZ is based on SIZE_SZ already
                mem = self.inferior.read_memory(self.address, self.dl.MAX_HDR_SZ)
                # XXX - Technically if the last chunk is only 0x10 bytes, and
                # we read it as a MAX_HDR_SZ it will fail. Better way to do the
                # above
            except TypeError:
                self.dl.logmsg("Invalid address specified.")
                self.initOK = False
                return
            except RuntimeError:
                self.dl.logmsg("Could not read address {0:#x}".format(self.address))
                self.initOK = False
                return
        else:
            self.from_mem = True
            # a string of raw memory was provided
            if self.inuse:
                if (len(mem) != self.dl.MIN_HDR_SZ) and \
                                (len(mem) < self.dl.FREE_HDR_SZ):
                    self.dl.logmsg("Insufficient memory provided for a dl_chunk.")
                    self.initOK = False
                    return
            else:
                if (len(mem) != self.dl.FREE_HDR_SZ) and \
                                (len(mem) < self.dl.FREE_HDR_SZ):
                    self.dl.logmsg("Insufficient memory provided for a free chunk.")
                    self.initOK = False
                    return

        # First we just read the header
        if self.dl.SIZE_SZ == 4:
            (self.prev_size,
            self.size) = struct.unpack_from("<II", mem, 0x0)
        elif self.dl.SIZE_SZ == 8:
            (self.prev_size,
            self.size) = struct.unpack_from("<QQ", mem, 0x0)

        # read next chunk size field to determine if current chunk is inuse
        if size == None:
            nextchunk_addr = self.address + (self.size & ~self.dl.SIZE_BITS)
            self.pinuse_bit = self.size & self.dl.PINUSE_BIT
            real_size = (self.size & ~self.dl.SIZE_BITS)
        else:
            nextchunk_addr = self.address + (size & ~self.dl.SIZE_BITS)
            self.pinuse_bit = size & self.dl.PINUSE_BIT
            real_size = size & ~self.dl.SIZE_BITS
        try:
            mem2 = self.inferior.read_memory(nextchunk_addr + self.dl.SIZE_SZ, 
                    self.dl.SIZE_SZ)
        except gdb.MemoryError:
            self.dl.logmsg("Could not read nextchunk's size. Invalid chunk address?")
            self.initOK = False
            return
        if self.dl.SIZE_SZ == 4:
            nextchunk_size = struct.unpack_from("<I", mem2, 0x0)[0]
        elif self.dl.SIZE_SZ == 8:
            nextchunk_size = struct.unpack_from("<Q", mem2, 0x0)[0]
        self.cinuse_bit = nextchunk_size & self.dl.PINUSE_BIT

        if inuse == None:
            if self.cinuse_bit:
                self.inuse = True
                self.hdr_size = self.dl.INUSE_HDR_SZ
            else:
                self.inuse = False
        else:
            # Trust the caller is right
            self.inuse = inuse
            self.hdr_size = self.dl.INUSE_HDR_SZ

        if self.inuse:
#            if read_data:
#                if self.address != None:
#                    # a string of raw memory was not provided
#                    try:
#                        mem = self.inferior.read_memory(self.address, real_size + self.dl.SIZE_SZ)
#                    except TypeError:
#                        self.dl.logmsg("Invalid address specified.")
#                        return None
#                    except RuntimeError:
#                        self.dl.logmsg("Could not read address {0:#x}".format(self.address))
#                        return None
#
                real_size = (real_size - self.dl.SIZE_SZ) / self.dl.SIZE_SZ
#                self.data = struct.unpack_from("<%dI" % real_size, mem, self.dl.INUSE_HDR_SZ)

        if not self.inuse:
            # We sometimes provide an address to use for reference, even when
            # we pass in mem. So can't just check for self.address != None
            if self.address != None and mem == None:
                # a string of raw memory was not provided
                if self.inferior != None:
                    if self.dl.SIZE_SZ == 4:
                        mem = self.inferior.read_memory(self.address, self.dl.MAX_HDR_SZ)
                    elif self.dl.SIZE_SZ == 8:
                        mem = self.inferior.read_memory(self.address, self.dl.MAX_HDR_SZ)

            # Both small and large chunks use a regular free chunk structure
            # There is no concept of tree chunk in dlmalloc 2.6.x
            if self.dl.SIZE_SZ == 4:
                (self.fd, \
                self.bk  ) = struct.unpack_from("<II", mem, self.dl.INUSE_HDR_SZ)
            elif self.dl.SIZE_SZ == 8:
                (self.fd, \
                self.bk  ) = struct.unpack_from("<QQ", mem, self.dl.INUSE_HDR_SZ)
            self.hdr_size = self.dl.FREE_HDR_SZ

        if self.address != None:
            self.data_address = self.address + self.hdr_size

    def __str__(self):
        if self.prev_size == 0 and self.size == 0:
            return ""
        # inuse chunk
        elif self.inuse:
            mc = "struct malloc_chunk @ "
            mc += "{:#x} ".format(self.address)
            mc += "{"
            mc += "\n{:11} = ".format("prev_size")
            mc += "{:#x}".format(self.prev_size)
            mc += "\n{:11} = ".format("size")
            mc += "{:#x}".format(self.size & ~self.dl.SIZE_BITS)
            if self.pinuse_bit == 1:
                mc += " (PINUSE)"
            return mc
        else:
            if self.istree:
                mc = "struct malloc_tree_chunk @ "
            else:
                mc = "struct malloc_chunk @ "
            mc += "{:#x} ".format(self.address)
            mc += "{"
            mc += "\n{:11} = ".format("prev_size")
            mc += "{:#x}".format(self.prev_size)
            mc += "\n{:11} = ".format("head")
            mc += "{:#x}".format(self.dl.chunksize(self))
            if self.pinuse_bit == 1:
                mc += " (PINUSE)"
            mc += "\n{:11} = ".format("fd")
            mc += "{:#x}".format(self.fd)
            mc += "\n{:11} = ".format("bk")
            mc += "{:#x}".format(self.bk)
            if self.istree:
                mc += "\n{:11} = ".format("left")
                mc += "{:#x}".format(self.left)
                mc += "\n{:11} = ".format("right")
                mc += "{:#x}".format(self.right)
                mc += "\n{:11} = ".format("parent")
                mc += "{:#x}".format(self.parent)
                mc += "\n{:11} = ".format("bindex")
                mc += "{:#x}".format(self.bindex)
            return mc

################################################################################
class dl_msegment(dl_structure):
    "python representation of a struct malloc_segment"

    def __init__(self, dl, addr=None, mem=None, inferior=None):
        dl_structure.__init__(self, dl)
        #super(dl_msegment, self).__init__()
        self.dl     = dl

        self.base   = 0
        self.size   = 0
        self.next   = 0
        self.sflags = 0

        if addr == None or addr == 0:
            if mem == None:
                self.dl.logmsg("Please specify a valid struct dl_chunk address.")
                self.initOK = False
                return

            self.address = None
        elif type(addr) == str:
            res = self._parse_base_offset(addr)
            if res == None:
                print('The first argument MUST be either an address or a register (+ optional offset)"')
                self.initOK = False
                return
            self.address = res[0] + res[1]
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if self.address != None:
            # a string of raw memory was not provided
            if inferior != None:
                mem = inferior.read_memory(self.address, self.dl.MSEGMENT_SZ)

        if mem == None:
            # a string of raw memory was not provided
            try:
                mem = inferior.read_memory(self.address, self.dl.MSEGMENT_SZ)
            except TypeError:
                self.dl.logmsg("Invalid address specified.")
                self.initOK = False
                return
            except RuntimeError:
                self.dl.logmsg("Could not read address {0:#x}".format(self.address))
                self.initOK = False
                return

        # We either need to read a regular free chunk or a tree chunk
        if self.dl.SIZE_SZ == 4:
            (self.base,
            self.size,
            self.next,
            self.sflags) = struct.unpack_from("<4I", mem, 0)
        elif self.dl.SIZE_SZ == 8:
            (self.base, \
            self.size,
            self.next,
            self.sflags) = struct.unpack_from("<4Q", mem, 0)

    def __str__(self):
        mc = "struct malloc_segment @ "
        mc += "{:#x} ".format(self.address)
        mc += "{"
        mc += "\n{:11} = ".format("base")
        mc += "{:#x}".format(self.base)
        mc += "\n{:11} = ".format("size")
        mc += "{:#x}".format(self.size)
        mc += "\n{:11} = ".format("next")
        mc += "{:#x}".format(self.next)
        mc += "\n{:11} = ".format("sflags")
        mc += "{:#x}".format(self.sflags)
        return mc

################################################################################
# XXX: make it inherit from dl_structure
class dl_mstate:
    "python representation of a struct malloc_state {} (malloc-2.8.3.c)"

    def __init__(self, dl, addr=None, mem=None, inferior=None):
        self.initOK        = False
        self.dl            = dl

        # mstate structure members
        self.smallmap      = 0
        self.treemap       = 0
        self.dvsize        = 0
        self.topsize       = 0
        self.least_addr    = 0
        self.dv            = 0
        self.top           = 0
        self.trim_check    = 0
        self.magic         = 0
        self.smallbins     = None
        self.treebins      = None
        self.footprint     = 0
        self.max_footprint = 0
        self.mflags        = 0
        self.mutex         = [] # We rely on being able to use len on this so
                                # want it to be something like an empty list
        self.seg           = None # dl_msegment
        self.size = self.dl.MSTATE_SZ

        # printing options
        self.prefix_address = False # show address of each member when printed

        if addr == None or addr == 0:
            if mem == None:
                self.dl.logmsg("Please specify a valid struct dl_mstate address.")
                return None
            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                # read more bytes to support the segment size bruteforce below?
                mem = inferior.read_memory(addr, self.dl.MSTATE_SZ) #+0x30)
            except TypeError:
                self.dl.logmsg("Invalid address specified.")
                self.initOK = False
                return None
            except RuntimeError:
                self.dl.logmsg("Could not read address {0:#x}".format(addr))
                self.initOK = False
                return
        else:
            if len(mem) != self.dl.MSTATE_SZ:
                self.dl.logmsg("Insufficient memory provided for a struct dl_mstate")
                self.initOK = False
                return None

        # The offset values can likely be the same for both SIZE_SZ
        if self.dl.SIZE_SZ == 4:
            # I do the 2 * explicitly to denote the unused part which is
            # technically part of smallbins in the source, but not actually
            # used
            self.small_bins_off = (9 * self.dl.SIZE_SZ) + (2 * self.dl.SIZE_SZ)
            nsbins = (self.dl.NSMALLBINS * 2) # in src is (NSMALLINBS+1)*2
            self.tree_bins_off = self.small_bins_off + \
                                 (nsbins * self.dl.SIZE_SZ)
            self.footprint_off = self.tree_bins_off + \
                                 (self.dl.NTREEBINS * self.dl.SIZE_SZ)

            (self.smallmap,
             self.treemap,
             self.dvsize,
             self.topsize,
             self.least_addr,
             self.dv,
             self.top,
             self.trim_check,
             self.magic) = struct.unpack_from("<9I", mem, 0x0)
            self.unused = struct.unpack_from("<2I", mem, self.small_bins_off)
            self.smallbins = struct.unpack_from("<%dI" % nsbins, mem, 
                    self.small_bins_off)
            self.treebins = struct.unpack_from("<%dI" % self.dl.NTREEBINS, mem, 
                    self.tree_bins_off)
            (self.footprint,
             self.max_footprint,
             self.mflags) = struct.unpack_from("<3I", mem, self.footprint_off)

            # NOTE: This is only present of USE_LOCKS is defined, which for
            # now we assume is true. However, not only that, but the
            # pthread_mutex_t structure can change. We have observed
            # 0x10 and 0x14 bytes. We don't want to hardcode this, so we rely
            # on the fact that the dl_msegment structure should have an address
            # value that matches the self.least_addr if our sizeof(mutex) guess 
            # is right.
            # If it is wrong, we adjust the size and try again
            # For general ref of a 0x14-byte mutex see:
            # http://www.jbox.dk/sanos/source/include/pthread.h.html
            mutex_off = self.footprint_off + (3*self.dl.SIZE_SZ)
            mutex_dwords = 5
            while mutex_dwords > 0:
                seg_off =  mutex_off + (mutex_dwords * self.dl.SIZE_SZ)
                self.mutex = struct.unpack_from("<%dI" % mutex_dwords, mem, 
                        mutex_off)
                self.seg = dl_msegment(self.dl, self.address + seg_off, 
                        mem[seg_off:])
                if self.seg.base != self.least_addr:
                    mutex_dwords -= 1
                else:
                    break

            if mutex_dwords == 0:
                self.seg = dl_msegment(self.dl, self.address + mutex_off,
                        mem[mutex_off:])
                if self.seg.base != self.least_addr:
                    self.dl.logmsg("Problem reading dlsegment")
                    return

        elif self.dl.SIZE_SZ == 8:
            # See 32-bit comments for the explicit 2*SIZE_SZ
            self.small_bins_off = 2*4 + 7*self.dl.SIZE_SZ + (2*self.dl.SIZE_SZ)
            nsbins = (self.dl.NSMALLBINS * 2)
            self.tree_bins_off = self.small_bins_off + \
                                    (nsbins * self.dl.SIZE_SZ)
            self.footprint_off = self.tree_bins_off + \
                                    (self.dl.NTREEBINS * self.dl.SIZE_SZ)
            mutex_off = self.footprint_off + 0x14
            seg_off =  mutex_off + 0x2C
            (self.smallmap,
             self.treemap,
             self.dvsize,
             self.topsize,
             self.least_addr,
             self.dv,
             self.top,
             self.trim_check,
             self.magic) = struct.unpack_from("<2I7Q", mem, 0x0)
            # XXX - since the very base index isn't used due to some 
            # quirks, it would simplify code elsewhere to unpack it into some
            # unused/unprinted location
            # This is missing self.unused and instead calculates exact
            # small_bins_off
            self.smallbins = struct.unpack_from("<%dQ" % nsbins, mem, 
                    self.small_bins_off)
            self.treebins = struct.unpack_from("<%dQ" % self.dl.NTREEBINS, mem,
                    self.tree_bins_off)
            (self.footprint,
             self.max_footprint,
             self.mflags) = struct.unpack_from("<2QI", mem, self.footprint_off)

            mutex_dwords = 5
            while mutex_dwords > 0:
                seg_off =  mutex_off + 4 + (mutex_dwords * self.dl.SIZE_SZ)
                self.mutex = struct.unpack_from("<I%dQ" % mutex_dwords, mem, 
                        mutex_off)
                self.seg = dl_msegment(self.dl, self.address + seg_off, 
                        mem[seg_off:])
                if self.seg.base != self.least_addr:
                    mutex_dwords -= 1
                else:
                    break

            if mutex_dwords == 0:
                self.seg = dl_msegment(self.dl, self.address + mutex_off, 
                        mem[mutex_off:])
                if self.seg.base != self.least_addr:
                    self.dl.logmsg("Problem reading dlsegment")
                    return

        # XXX - why 5?
        self.size = self.size - (5 - mutex_dwords)*self.dl.SIZE_SZ
        self.initOK = True
        self.dl.cached_mstate = self

    def __str__(self):
            mc = "struct dl_mstate @ "
            mc += "{:#x} ".format(self.address)
            mc += "{"
            mc += "\n{:11} = ".format("smallmap")
            mc += "{:#032b}".format(self.smallmap, '032b')
            mc += "\n{:11} = ".format("treemap")
            mc += "{:#032b}".format(self.treemap)
            mc += "\n{:11} = ".format("dvsize")
            mc += "{:#x}".format(self.dvsize)
            mc += "\n{:11} = ".format("topsize")
            mc += "{:#x}".format(self.topsize)
            mc += "\n{:11} = ".format("least_addr")
            mc += "{:#x}".format(self.least_addr)
            mc += "\n{:11} = ".format("dv")
            mc += "{:#x}".format(self.dv)
            mc += "\n{:11} = ".format("top")
            mc += "{:#x}".format(self.top)
            mc += "\n{:11} = ".format("trim_check")
            mc += "{:#x}".format(self.trim_check)
            mc += "\n{:11} = ".format("magic")
            mc += "{:#x}".format(self.magic)
            # NOTE: We don't print self.unused because it has no purpose
            # We rely on self.unused to keep the code below simpler though
            i = 0
            while i < len(self.smallbins):
                bidx = int(i/2)
                maxsz = (bidx * 8)
                mc += "\n{:12} ".format("smallbin[%02d]" % bidx)
                mc += "{:10} = ".format("(sz 0x%x)" % maxsz)
                mc += "{:#10x}, ".format(self.smallbins[i])
                mc += "{:#10x}".format(self.smallbins[i+1])
                if self.smallmap & (1 << bidx) == 0:
                    mc += " [EMPTY]"
                i += 2
            # XXX - make this look nicer in output
            i = 0
            while i < len(self.treebins):
                maxsz = self.dl.treebin_sz[i]
                mc += "\n{:10} ".format("treebin[%02d]" % i)
                mc += "{:15} = ".format("(sz 0x%x)" % maxsz)
                mc += "{:#10x}".format(self.treebins[i])
                if self.treemap & (1 << i) == 0:
                    mc += " [EMPTY]"
                i += 1
            mc += "\n{:11} = ".format("footprint")
            mc += "{:#x}".format(self.footprint)
            mc += "\n{:11} = ".format("max_footprint")
            mc += "{:#x}".format(self.max_footprint)
            mc += "\n{:11} = ".format("mflags")
            mc += "{:#x}".format(self.mflags)
            i = 0
            mc += "\n{:11} = ".format("mutex")
            while i < len(self.mutex):
                mc += "{:#x},".format(self.mutex[i])
                i += 1
            i = 0
            mc += "\nseg = %s" % self.seg
            return mc

################################################################################
class malloc_params:
    "python representation of a struct malloc_params"

    def __init__(self, dl, addr=None, mem=None, inferior=None):
        self.dl = dl
        self.magic = 0
        self.page_size = 0
        self.granularity = 0
        self.mmap_threshold   = 0
        self.trim_threshold   = 0
        self.default_mflags = 0

        if addr == None:
            if mem == None:
                self.dl.logmsg("Please specify a struct malloc_par address.")
                return None

            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                mem = inferior.read_memory(addr, self.dl.MALLOC_PARAM_SZ)
            except TypeError:
                self.dl.logmsg("Invalid address specified.")
                return None
            except RuntimeError:
                self.dl.logmsg("Could not read address {0:#x}".format(addr))
                return

        if self.dl.SIZE_SZ == 4:
            (self.magic, \
            self.page_size, \
            self.granularity, \
            self.mmap_threshold  , \
            self.trim_threshold  , \
            self.default_mflags) = struct.unpack("<6I", mem)
        elif self.dl.SIZE_SZ == 8:
            (self.magic, \
            self.page_size, \
            self.granularity, \
            self.mmap_threshold  , \
            self.trim_threshold  , \
            self.default_mflags) = struct.unpack("<5QI", mem)

    def __str__(self):
        mp = "struct malloc_params {"
        mp += "\n{:16} = ".format("magic")
        mp += "{:#x}".format(self.magic)
        mp += "\n{:16} = ".format("page_size")
        mp += "{:#x}".format(self.page_size)
        mp += "\n{:16} = ".format("granularity")
        mp += "{:#x}".format(self.granularity)
        mp += "\n{:16} = ".format("mmap_threshold")
        mp += "{:#x}".format(self.mmap_threshold)
        mp += "\n{:16} = ".format("trim_threshold")
        mp += "{:#x}".format(self.trim_threshold)
        mp += "\n{:16} = ".format("default_mflags")
        mp += "{:#x}".format(self.default_mflags)
        return mp

# XXX import this stuff from a separate file
if is_gdb:
################################################################################
# GDB COMMANDS
################################################################################

# This is a super class with few convenience methods to let all the cmds parse
# gdb variables easily
    class dlcmd(gdb.Command):

        def __init__(self, dl, name):
            self.dl = dl
            super(dlcmd, self).__init__(name, gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

        def parse_var(self, var):
            if self.dl.SIZE_SZ == 4:
                p = self.tohex(int(gdb.parse_and_eval(var)), 32)
            elif self.dl.SIZE_SZ == 8:
                p = self.tohex(int(gdb.parse_and_eval(var)), 64)
            return int(p, 16)

        # Because python is incapable of turning a negative integer into a hex value
        # easily apparently...
        def tohex(self, val, nbits):
            result = hex((val + (1 << nbits)) % (1 << nbits))
            # -1 because hex() only sometimes tacks on a L to hex values...
            if result[-1] == 'L':
                return result[:-1]
            else:
                return result

################################################################################
    class dlhelp(dlcmd):
        "Details about all libdlmalloc gdb commands"

        def __init__(self, dl, help_extra=None):
            self.help_extra = help_extra
            dlcmd.__init__(self, dl, "dlhelp")

        def invoke(self, arg, from_tty):
            self.dl.logmsg('dlmalloc commands for gdb')
            if self.help_extra != None:
                self.dl.logmsg(self.help_extra)
            self.dl.logmsg('dlchunk    : show one or more chunks metadata and contents')
            self.dl.logmsg('dlmstate   : print mstate structure information. caches address after first use')
            self.dl.logmsg('dlcallback : register a callback or query/modify callback status')
            self.dl.logmsg('dlhelp     : this help message')
            self.dl.logmsg('NOTE: Pass -h to any of these commands for more extensive usage. Eg: dlchunk -h')

    class dlcallback(dlcmd):
        "Manage callbacks"

        def __init__(self, dl):
            dlcmd.__init__(self, dl, "dlcallback")
#        super(dlcallback, self).__init__("dlcallback", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)
            self.dl = dl

        def help(self):
            self.dl.logmsg('usage: dlcallback <option>')
            self.dl.logmsg(' disable                  temporarily disable the registered callback')
            self.dl.logmsg(' enable                   enable the registered callback')
            self.dl.logmsg(' status                   check if a callback is registered')
            self.dl.logmsg(' clear                    forget the registered callback')
            self.dl.logmsg(' register <name> <module> use a global function <name> as callback from <module>')
            self.dl.logmsg('                          ex: register mpcallback libmempool/libmempool')

        def invoke(self, arg, from_tty):
            if arg == '':
                self.help()
                return

            arg = arg.lower()
            if arg.find("enable") != -1:
                self.dl.dlchunk_callback = self.dl.dlchunk_callback_cached
                self.dl.logmsg('callback enabled')
                if self.dl.dlchunk_callback == None:
                    self.dl.logmsg('NOTE: callback was enabled, but is unset')
            elif arg.find("disable") != -1:
                self.dl.dlchunk_callback_cached = self.dl.dlchunk_callback
                self.dl.dlchunk_callback = None
                self.dl.logmsg('callback disabled')
            elif arg.find("clear") != -1:
                self.dl.dlchunk_callback = None
                self.dl.dlchunk_callback_cached = None
                self.dl.logmsg('callback cleared')
            elif arg.find("status") != -1:
                if self.dl.dlchunk_callback:
                    self.dl.logmsg('a callback is registered and enabled')
                elif self.dl.dlchunk_callback == None and \
                         self.dl.dlchunk_callback_cached:
                    self.dl.logmsg('a callback is registered and disabled')
                else:
                    self.dl.logmsg('a callback is not registered')
            elif arg.find("register") != -1:
                args = arg.split(' ')
                if len(args) < 2:
                    self.dl.logmsg('[!] Must specify object name')
                    self.help()
                    return
                if args[1] not in globals():
                    if len(args) == 3:
                        try:
                            modpath = os.path.dirname(args[2])
                            modname = os.path.basename(args[2])
                            if modpath != "": 
                                if modpath[0] == '/':
                                    sys.path.insert(0, modpath)
                                else:
                                    sys.path.insert(0, os.path.join(os.getcwd(), 
                                                modpath))
                            mod  = importlib.import_module(modname)
                            importlib.reload(mod)
                            if args[1] in dir(mod):
                                self.dl.dlchunk_callback = getattr(mod, args[1])
                                self.dl.dlchunk_callback_cached = None
                        except Exception as e:
                            self.dl.logmsg("[!] Couldn't load module: %s" % args[2])
                            print(e)
                    else:
                        self.dl.logmsg("[!] Couldn't find object %s. Specify module" % 
                                args[1])
                        self.help()
                else:
                    self.dl.dlchunk_callback = globals()[args[1]]
                    self.dl.dlchunk_callback_cached = None
                self.dl.logmsg('%s registered as callback' % args[1])
            else:
                self.help()

################################################################################
    class dlchunk(dlcmd):
        "print a comprehensive view of a dlchunk"

        def __init__(self, dl):
#        dlcmd.__init__(self, dl)
            dlcmd.__init__(self, dl, "dlchunk")
#        super(dlchunk, self).__init__("dlchunk", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)
            self.dl = dl

        def help(self):
            self.dl.logmsg('usage: dlchunk [-v] [-f] [-x] [-c <count>] <addr>')
            self.dl.logmsg(' <addr>  a dlmalloc chunk header')
            self.dl.logmsg(' -v      use verbose output (multiples for more verbosity)')
            self.dl.logmsg(' -f      use <addr> explicitly, rather than be smart')
            self.dl.logmsg(' -x      hexdump the chunk contents')
            self.dl.logmsg(' -m      max bytes to dump with -x')
            self.dl.logmsg(' -c      number of chunks to print')
            # I suspect we want this to be a different command?
            self.dl.logmsg(' -s      search pattern when print chunks')
            self.dl.logmsg(' --depth depth to search inside chunk')
            self.dl.logmsg(' -d      debug and force printing stuff')
            self.dl.logmsg("Flag legend: P=PINUSE")
            return

        @has_inferior
        def invoke(self, arg, from_tty):
            "Usage can be obtained via dlmalloc -h"
            try:

                if arg == '':
                    self.help()
                    return

                verbose = 0
                force = False
                hexdump = False
                maxbytes = 0

                s_found = False
                c_found = False
                m_found = False
                depth_found = False
                debug = False
                count = 1
                search_val = None
                search_depth = 0
                for item in arg.split():
                    if m_found:
                        if item.find("0x") != -1:
                            maxbytes = int(item, 16)
                        else:
                            maxbytes = int(item)
                        m_found = False
                    elif depth_found:
                        if item.find("0x") != -1:
                            search_depth = int(item, 16)
                        else:
                            search_depth = int(item)
                        depth_found = False
                    elif s_found:
                        if item.find("0x") != -1:
                            search_val = item
                        s_found = False
                    elif c_found:
                        count = int(item)
                        c_found = False
                    elif item.find("-v") != -1:
                        verbose += 1
                    elif item.find("-f") != -1:
                        force = True
                    elif item.find("-x") != -1:
                        hexdump = True
                    elif item.find("-m") != -1:
                        m_found = True
                    elif item.find("-s") != -1:
                        s_found = True
                    elif item.find("--depth") != -1:
                        depth_found = True 
                    elif item.find("-c") != -1:
                        c_found = True
                    # XXX Probably make this a helper
                    elif item.find("0x") != -1:
                        if item.find("-") != -1 or item.find("+") != -1:
                            p = self.parse_var(item)
                        else:
                            try:
                                p = int(item, 16)
                            except ValueError:
                                p = self.parse_var(item)
                    elif item.find("$") != -1:
                        p = self.parse_var(item)
                    elif item.find("-d") != -1:
                        debug = True # This is an undocumented dev option
                    elif item.find("-h") != -1:
                        self.help()
                        return

                if p == None:
                    print("WARNING: No address supplied?")
                    self.help()
                    return

                p = dl_chunk(self.dl, p)
                dump_offset = 0
                while True:
                    suffix = ""
                    if search_val != None:
                        # Don't print if the chunk doesn't have the pattern
                        if not self.dl.search_chunk(p, search_val, 
                                depth=search_depth):
                            suffix = " [NO MATCH]"
                        else:
                            suffix = " [MATCH]"

                    if verbose == 0:
                        print(self.dl.chunk_info(p) + suffix)
                    elif verbose == 1:
                        print(p)
                        dump_offset = self.dl.dispatch_callback(p, debug=debug)
                    if hexdump:
                        self.dl.hexdump(p, maxbytes, dump_offset)
                    count -= 1
                    if count != 0:
                        if verbose or hexdump:
                            print('--')
                        if self.dl.is_end_chunk(p) and force == False:
                            print("<<< end of heap segment >>>")
                            break
                        if self.dl.chunksize(p) == 0:
                            print("[!] Detected chunksz 0")
                            break
                        p = dl_chunk(self.dl, addr=(p.address + self.dl.chunksize(p)))
                        if p.initOK == False:
                            break
                    else:
                        break
            except Exception as e:
                show_last_exception()

################################################################################
    class dlmstate(dlcmd):
        "print a comprehensive view of a dlmstate"

        def __init__(self, dl):
            dlcmd.__init__(self, dl, "dlmstate")
#        super(dlmstate, self).__init__("dlmstate", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)
            self.dl = dl

        def help(self):
            self.dl.logmsg('usage: dlmstate [-v] [-f] [-x] [-c <count>] <addr>')
            self.dl.logmsg(' <addr>  a mstate struct addr. Optional if mstate cached')
            self.dl.logmsg(' -v      use verbose output (multiples for more verbosity)')
            self.dl.logmsg(' -c      print bin counts')
            self.dl.logmsg(' --depth how deep to count each bin (default 10)')
            self.dl.logmsg(' NOTE: Last defined mstate will be cached for future use')
            return

        # This should be in dl_helper probably
        def print_bin_counts(self, p, depth=10):
            mc = ""
            i = 0
            while i < len(p.smallbins):
                bidx = int(i/2)
                maxsz = (bidx * 8)
                mc += "\n{:12} ".format("smallbin[%02d]" % bidx)
                mc += "{:10} = ".format("(sz 0x%x)" % maxsz)
                mc += "{:#10x}, ".format(p.smallbins[i])
                mc += "{:#10x}".format(p.smallbins[i+1])
                if p.smallmap & (1 << bidx) == 0:
                    mc += " [EMPTY]"
                else:
                    count = self.dl.smallbin_count(bidx, depth)
                    if count > depth:
                        mc += " [%d+]" % depth
                    else:
                        mc += " [%d]" % count
                i += 2
            i = 0
            while i < len(p.treebins):
                maxsz = self.dl.treebin_sz[i]
                mc += "\n{:10} ".format("treebin[%02d]" % i)
                mc += "{:15} = ".format("(sz 0x%x)" % maxsz)
                mc += "{:#10x}".format(p.treebins[i])
                if p.treemap & (1 << i) == 0:
                    mc += " [EMPTY]"
                else:
                    count = self.dl.treebin_count(i, depth)
                    if count > depth:
                        mc += " [%d+]" % depth
                    else:
                        mc += " [%d]" % count

                i += 1
            print(mc)

        @has_inferior
        def invoke(self, arg, from_tty):

            if self.dl.cached_mstate == None and (arg == None or arg == ''):
                self.help()
                return

            verbose = 0
            bincount = False
            p = None
            count_depth = 10
            depth_found = False
            if arg != None:
                for item in arg.split():
                    if item.find("-v") != -1:
                        verbose += 1
                    elif item.find("-c") != -1:
                        bincount = True
                    elif item.find("--depth") != -1:
                        depth_found = True 
                    elif depth_found:
                        if item.find("0x") != -1:
                            count_depth = int(item, 16)
                        else:
                            count_depth = int(item)
                        depth_found = False
                    elif item.find("0x") != -1:
                        p = int(item, 16)
                    elif item.find("$") != -1:
                        p = self.parse_var(item)
                    elif item.find("-h") != -1:
                        self.help()
                        return

            if p == None and self.dl.cached_mstate == None:
                print("WARNING: No address supplied?")
                self.help()
                return

            if p != None:
                p = dl_mstate(self.dl, p)
            else:
                self.dl.logmsg("Using cached mstate")
                p = self.dl.cached_mstate

            if p.topsize == 0 or p.least_addr == 0:
                self.dl.logmsg("[!] doesn't appeart be a valid mstate")

            # Assume we couldn't read it from memory
            if p.initOK == False:
                return

            if bincount:
                self.print_bin_counts(p, count_depth)
                return

            if verbose == 0:
                print(p)
            # XXX - not sure what all verbose should show
            elif verbose == 1:
                # XXX - Not sure this is the best way to do this :|
                p.prefix_address = True
                print(p)
                p.prefix_address = False

            if self.dl.dlchunk_callback != None:
                if p != None:
                    cbinfo = {}
                    cbinfo["caller"] = "dlmstate"
                    cbinfo["allocator"] = "dlmalloc"
                    cbinfo["size_sz"] = self.dl.SIZE_SZ
                    cbinfo["addr"] = p.address + p.size
                    self.dl.dlchunk_callback(cbinfo)

# XXX - finish me
    class dlsearch(dlcmd):
        def __init__(self):
            super(dlsearch, self).__init__("dlsearch", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

        def help(self):
            self.dl.logmsg('usage: dlsearch <hex> <min_size> <max_size>')

        def invoke(self, arg, from_tty):
            if arg == '':
                self.help()
                return
            arg = arg.split()
            #if arg[0].find("0x") == -1 or (len(arg[0]) != 10 and len(arg[0]) != 18):
            #    self.dl.logmsg("you need to provide a word or giant word for hex")
            #    return
            search_for = arg[0]
            if len(arg) > 3:
                self.help()
                return
            if len(arg) >= 2:
                max_size = int(arg[1], 16)
            else:
                max_size = 0
            if len(arg) == 3:
                min_size = int(arg[1], 16)
            else:
                min_size = 0

            # need segment parsing
#            while ar_ptr != main_arena_address:
#                self.dl.logmsg("Handling arena @ 0x%x" % dl_mstate(ar_ptr).address)
#
#                results = dl.search_heap(ar_ptr, search_for, min_size, max_size)
#
#                if len(results) == 0:
#                    self.dl.logmsg('value %s not found' % (search_for))
#                    return
#
#                for result in results:
#                    self.dl.logmsg("%s found in chunk at 0x%lx" % (search_for, int(result)))

if __name__ == "__main__":
    dlh = dl_helper()
    dlhelp(dlh)
    dlchunk(dlh)
    dlmstate(dlh)
    dlcallback(dlh)
    dlh.logmsg("loaded")
