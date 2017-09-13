# libdlmalloc

**libdlmalloc** is a python script designed for use with GDB that can be used to
analyse the Doug Lea's allocator, aka dlmalloc. It currently supports dlmalloc
2.8.x versions. Note that some parts can also be used independently GDB, for
instance to do offline analysis of some snapshotted heap memory.

libdlmalloc was inspired by other gdb python scripts for analyzing heaps like
[libtalloc](https://github.com/nccgroup/libtalloc),
[unmask_jemalloc](https://github.com/argp/unmask_jemalloc) and
[libheap](https://github.com/cloudburst/libheap). Some basic functionality is
almost identical to these projects.

## Supported versions

libdlmalloc has been tested predominately on 32-bit and 64-bit Cisco ASA
devices which use dlmalloc 2.8.3. It should work with other 2.8.x versions,
however due to significant differences it will not work on earlier releases,
such as <= 2.7.x.

If you successfully test libdlmalloc on some specific 2.8.x release or some
specific device, please let the authors know and we will update the documents.

## Installation 

The script just requires a relatively modern version of GDB with python3
support. We have primarily tested on python3, so we expect it will break on
python2.7 atm.

If you want to use the gdb commands you can use:

```
    (gdb) source libdlmalloc_28x.py
```

A bunch of the core logic is broken out into the `dl_helper` class, which allows
you to directly import libdlmalloc and access certain important structures
outside of a GDB session. This is useful if you want to analyze offline
chunk/heap snapshots.

# Usage

Most of the functionality is modelled after the approach in unmask_jemalloc and
libtalloc where a separate GDB command is provided. Though we do also use a
fair number of switches.

To see a full list of currently supported commands you can use the `dlhelp`
command:

## dlhelp

This is the main function to view the available commands. Each of the commands
supports the `-h` option which allows you to obtain more detailed usage
instructions.

```
(gdb) dlhelp
[libdlmalloc] dlmalloc commands for gdb
[libdlmalloc] dlchunk    : show one or more chunks metadata and contents
[libdlmalloc] dlmstate   : print mstate structure information. caches address after first use
[libdlmalloc] dlcallback : register a callback or query/modify callback status
[libdlmalloc] dlhelp     : this help message
[libdlmalloc] NOTE: Pass -h to any of these commands for more extensive usage. Eg: dlchunk -h
```

## Chunk analysis

`dlchunk` can provide you with a summary of a chunk, or more verbose
information of every field. You can also use it to list information about
multiple chunks, search chunks, etc. Usage for dlchunk can be seen below:

```
(gdb) dlchunk -h
[libdlmalloc] usage: dlchunk [-v] [-f] [-x] [-c <count>] <addr>
[libdlmalloc]  <addr>  a dlmalloc chunk header
[libdlmalloc]  -v      use verbose output (multiples for more verbosity)
[libdlmalloc]  -f      use <addr> explicitly, rather than be smart
[libdlmalloc]  -x      hexdump the chunk contents
[libdlmalloc]  -m      max bytes to dump with -x
[libdlmalloc]  -c      number of chunks to print
[libdlmalloc]  -s      search pattern when print chunks
[libdlmalloc]  --depth depth to search inside chunk
[libdlmalloc]  -d      debug and force printing stuff
[libdlmalloc] Flag legend: C=CINUSE, P=PINUSE
```

Basic output looks like this:

```
(gdb) dlchunk 0xacff59d0
0xacff59d0 M sz:0x000f8 fl:CP
```

As you can see you want to give it the address of the actual dlmalloc metadata
itself. To get more verbose output you can use `-v`.

```
(gdb) dlchunk -v 0xacff59d0
struct malloc_chunk @ 0xacff59d0 {
prev_foot   = 0x8140d4d0
size        = 0xf8 (CINUSE|PINUSE)
```

You can also list multiple adjacent chunks by using the `-c <count>` switch.

```
(gdb) dlchunk -c 2 0xacff59d0
0xacff59d0 M sz:0x000f8 fl:CP
0xacff5ac8 M sz:0x00270 fl:CP
(gdb) dlchunk -v -c 2 0xacff59d0
struct malloc_chunk @ 0xacff59d0 {
prev_foot   = 0x8140d4d0
size        = 0xf8 (CINUSE|PINUSE)
--
struct malloc_chunk @ 0xacff5ac8 {
prev_foot   = 0x8140d4d0
size        = 0x270 (CINUSE|PINUSE)
```

You can dump the hex contents of a chunk with `-x` and control how many bytes
you want to dump with `-m`.


```
(gdb) dlchunk -v -x -m 16 -c 2 0xacff59d0
struct malloc_chunk @ 0xacff59d0 {
prev_foot   = 0x8140d4d0
size        = 0xf8 (CINUSE|PINUSE)
0x10 bytes of chunk data:
0xacff59d8:	0xa11c0123	0x000000cc	0x00000000	0x00000000
--
struct malloc_chunk @ 0xacff5ac8 {
prev_foot   = 0x8140d4d0
size        = 0x270 (CINUSE|PINUSE)
0x10 bytes of chunk data:
0xacff5ad0:	0xa11c0123	0x00000244	0x00000000	0x00000000
```

You can also search inside the chunks. Let's search 2 chunks for the value
`0x00000244`, which we see above is only in the second chunk.

```
(gdb) dlchunk -s 0x00000244 -c 2 0xacff59d0
0xacff59d0 M sz:0x000f8 fl:CP [NO MATCH]
0xacff5ac8 M sz:0x00270 fl:CP [MATCH]
```

All matches inside the number of chunks searched will be shown. Let's search
for `0xa11c01123` which we saw above is present in both chunks:

```
(gdb) dlchunk -s 0xa11c0123 -c 2 0xacff59d0
0xacff59d0 M sz:0x000f8 fl:CP [MATCH]
0xacff5ac8 M sz:0x00270 fl:CP [MATCH]
```

## dlmstate

The dlmstate command can be used for analyzing the `mstate` structure used to
manage a discrete dlmalloc heap (aka mspace if compiled with `MSPACES`). You
can see the usage of the command with the `-h` switch.


```
(gdb) dlmstate -h
[libdlmalloc] usage: dlmstate [-v] [-f] [-x] [-c <count>] <addr>
[libdlmalloc]  <addr>  a mstate struct addr. Optional if mstate cached
[libdlmalloc]  -v      use verbose output (multiples for more verbosity)
[libdlmalloc]  -c      print bin counts
[libdlmalloc]  --depth how deep to count each bin (default 10)
[libdlmalloc]  NOTE: Last defined mstate will be cached for future use
```

If you know the address holding the mstate, which is usually the first chunk
inside of the first malloc asegment, you can pass it to dlmstate:

```
(gdb) dlmstate 0xa8400008
struct dl_mstate @ 0xa8400008 {
smallmap    = 0b000000000000010000011111111100
treemap     = 0b000000000000000000000000000111
dvsize      = 0x0
topsize     = 0x2ebdf040
least_addr  = 0xa8400000
dv          = 0x0
top         = 0xad020f90
trim_check  = 0x200000
magic       = 0x2900d4d8
smallbin[00] (sz 0x0)   = 0xa840002c, 0xa840002c [EMPTY]
smallbin[01] (sz 0x8)   = 0xa8400034, 0xa8400034 [EMPTY]
smallbin[02] (sz 0x10)  = 0xacbf7ad0, 0xa88647f0
smallbin[03] (sz 0x18)  = 0xa95059b8, 0xa9689a20
smallbin[04] (sz 0x20)  = 0xac79a028, 0xa87206f8
smallbin[05] (sz 0x28)  = 0xacff0120, 0xa948a0f8
smallbin[06] (sz 0x30)  = 0xac4e4af8, 0xacb56878
smallbin[07] (sz 0x38)  = 0xacfe3880, 0xacfe0df0
smallbin[08] (sz 0x40)  = 0xa9509b28, 0xa9509b28
smallbin[09] (sz 0x48)  = 0xa8a1dc80, 0xa8a1dc80
smallbin[10] (sz 0x50)  = 0xac782cb0, 0xac782cb0
smallbin[11] (sz 0x58)  = 0xacbf7a88, 0xacbf7a88 [EMPTY]
smallbin[12] (sz 0x60)  = 0xac782c00, 0xac782c00 [EMPTY]
smallbin[13] (sz 0x68)  = 0xacbf7a78, 0xacbf7a78 [EMPTY]
smallbin[14] (sz 0x70)  = 0xa89b9650, 0xa89b9650 [EMPTY]
smallbin[15] (sz 0x78)  = 0xac789828, 0xac789828 [EMPTY]
smallbin[16] (sz 0x80)  = 0xa89b9738, 0xa94af740
smallbin[17] (sz 0x88)  = 0xac4e5700, 0xac4e5700 [EMPTY]
smallbin[18] (sz 0x90)  = 0xac788030, 0xac788030 [EMPTY]
smallbin[19] (sz 0x98)  = 0xac782bc8, 0xac782bc8 [EMPTY]
smallbin[20] (sz 0xa0)  = 0xa89b9718, 0xa89b9718 [EMPTY]
smallbin[21] (sz 0xa8)  = 0xa8a1dc20, 0xa8a1dc20 [EMPTY]
smallbin[22] (sz 0xb0)  = 0xac782af8, 0xac782af8 [EMPTY]
smallbin[23] (sz 0xb8)  = 0xac789ed0, 0xac789ed0 [EMPTY]
smallbin[24] (sz 0xc0)  = 0xacbf7a20, 0xacbf7a20 [EMPTY]
smallbin[25] (sz 0xc8)  = 0xac789940, 0xac789940 [EMPTY]
smallbin[26] (sz 0xd0)  = 0xac789eb8, 0xac789eb8 [EMPTY]
smallbin[27] (sz 0xd8)  = 0xa94af6e8, 0xa94af6e8 [EMPTY]
smallbin[28] (sz 0xe0)  = 0xacbf78e8, 0xacbf78e8 [EMPTY]
smallbin[29] (sz 0xe8)  = 0xac4e4e68, 0xac4e4e68 [EMPTY]
smallbin[30] (sz 0xf0)  = 0xac4e5780, 0xac4e5780 [EMPTY]
smallbin[31] (sz 0xf8)  = 0xac7880b0, 0xac7880b0 [EMPTY]
treebin[00] (sz 0x180)      = 0xac783cb0
treebin[01] (sz 0x200)      = 0xac789dc0
treebin[02] (sz 0x300)      = 0xa883db48
treebin[03] (sz 0x400)      =        0x0 [EMPTY]
treebin[04] (sz 0x600)      =        0x0 [EMPTY]
treebin[05] (sz 0x800)      =        0x0 [EMPTY]
treebin[06] (sz 0xc00)      =        0x0 [EMPTY]
treebin[07] (sz 0x1000)     =        0x0 [EMPTY]
treebin[08] (sz 0x1800)     =        0x0 [EMPTY]
treebin[09] (sz 0x2000)     =        0x0 [EMPTY]
treebin[10] (sz 0x3000)     =        0x0 [EMPTY]
treebin[11] (sz 0x4000)     =        0x0 [EMPTY]
treebin[12] (sz 0x6000)     =        0x0 [EMPTY]
treebin[13] (sz 0x8000)     =        0x0 [EMPTY]
treebin[14] (sz 0xc000)     =        0x0 [EMPTY]
treebin[15] (sz 0x10000)    =        0x0 [EMPTY]
treebin[16] (sz 0x18000)    =        0x0 [EMPTY]
treebin[17] (sz 0x20000)    =        0x0 [EMPTY]
treebin[18] (sz 0x30000)    =        0x0 [EMPTY]
treebin[19] (sz 0x40000)    =        0x0 [EMPTY]
treebin[20] (sz 0x60000)    =        0x0 [EMPTY]
treebin[21] (sz 0x80000)    =        0x0 [EMPTY]
treebin[22] (sz 0xc0000)    =        0x0 [EMPTY]
treebin[23] (sz 0x100000)   =        0x0 [EMPTY]
treebin[24] (sz 0x180000)   =        0x0 [EMPTY]
treebin[25] (sz 0x200000)   =        0x0 [EMPTY]
treebin[26] (sz 0x300000)   =        0x0 [EMPTY]
treebin[27] (sz 0x400000)   =        0x0 [EMPTY]
treebin[28] (sz 0x600000)   =        0x0 [EMPTY]
treebin[29] (sz 0x800000)   =        0x0 [EMPTY]
treebin[30] (sz 0xc00000)   =        0x0 [EMPTY]
treebin[31] (sz 0xffffffff) =        0x0 [EMPTY]
footprint   = 0x33800000
max_footprint = 0x33800000
mflags      = 0x7
mutex       = 0x0,0x0,0x0,0x0,0xa8400000,
seg = struct malloc_segment @ 0xa84001d4 {
base        = 0xa8400000
size        = 0x33800000
next        = 0x0
sflags      = 0x8
```

To speed up output on slower devices we cache the last mstate data that we
read. So if you just run dlmstate again, you will see the previously dumped
output (which of course could be stale).

```
(gdb) dlmstate
[libdlmalloc] Using cached mstate
struct dl_mstate @ 0xa8400008 {
smallmap    = 0b000000000000010000011111111100
treemap     = 0b000000000000000000000000000111
dvsize      = 0x0
topsize     = 0x2ebdf040
least_addr  = 0xa8400000
dv          = 0x0
top         = 0xad020f90
trim_check  = 0x200000
magic       = 0x2900d4d8
smallbin[00] (sz 0x0)   = 0xa840002c, 0xa840002c [EMPTY]
smallbin[01] (sz 0x8)   = 0xa8400034, 0xa8400034 [EMPTY]
smallbin[02] (sz 0x10)  = 0xacbf7ad0, 0xa88647f0
smallbin[03] (sz 0x18)  = 0xa95059b8, 0xa9689a20
[...]
```

The `-c` switch can be used to count the number of chunks in a given bin. Note
that this can be quite slow if you're debugging over a serial line, so we also
provide the `--depth` option to limit how many bin entries will be counted. By
default the depth is set to 10:

```
(gdb) dlmstate -c
[libdlmalloc] Using cached mstate

smallbin[00] (sz 0x0)   = 0xa840002c, 0xa840002c [EMPTY]
smallbin[01] (sz 0x8)   = 0xa8400034, 0xa8400034 [EMPTY]
smallbin[02] (sz 0x10)  = 0xacbf7ad0, 0xa88647f0 [10+]
smallbin[03] (sz 0x18)  = 0xa95059b8, 0xa9689a20 [10+]
smallbin[04] (sz 0x20)  = 0xac79a028, 0xa87206f8 [10+]
smallbin[05] (sz 0x28)  = 0xacff0120, 0xa948a0f8 [10+]
smallbin[06] (sz 0x30)  = 0xac4e4af8, 0xacb56878 [10+]
smallbin[07] (sz 0x38)  = 0xacfe3880, 0xacfe0df0 [10]
smallbin[08] (sz 0x40)  = 0xa9509b28, 0xa9509b28 [2]
smallbin[09] (sz 0x48)  = 0xa8a1dc80, 0xa8a1dc80 [2]
smallbin[10] (sz 0x50)  = 0xac782cb0, 0xac782cb0 [2]
[...]
```

As shown the count is displayed in brackets to the right of the bin contents.
We use the mstate bitmap to first test if a bin is empty, so you can expect to
occasionally see bin entries that have valid pointers that to the heap, but
that are marked `[EMPTY]`. These pointers are just stale at this point.

## dlcallback

We support the concept of inter-plugin callbacks. You can register a callback
function in a specified module and that function will be called with a dict
holding a bunch of information about the state of whatever is being looked at.
The callback is called when both dlchunk and dlmstate area finished doing
whatever they do with their arguments.

The usage can be seen with the `-h` switch:

```
(gdb) dlcallback -h
[libdlmalloc] usage: dlcallback <option>
[libdlmalloc]  disable                  temporarily disable the registered callback
[libdlmalloc]  enable                   enable the registered callback
[libdlmalloc]  status                   check if a callback is registered
[libdlmalloc]  clear                    forget the registered callback
[libdlmalloc]  register <name> <module> use a global function <name> as callback from <module>
[libdlmalloc]                           ex: register mpcallback libmempool/libmempool
```

To demonstrate this functionality, we will use a callback we developed for a
separate GDB plugin called [libmempool](https://github.com/nccgroup/libmempool),


```
(gdb) dlcallback register mpcallback libmempool/libmempool
[libmempool] loaded
[libdlmalloc] mpcallback registered as callback
(gdb) dlcallback status
[libdlmalloc] a callback is registered and enabled
```

Now when we use a command like dlchunk, we can see some additional annotation:

```
(gdb) dlchunk 0xacff59d0
0xacff59d0 M sz:0x000f8 fl:CP alloc_pc:0x08262b45,-
(gdb) dlchunk -v 0xacff59d0
struct malloc_chunk @ 0xacff59d0 {
prev_foot   = 0x8140d4d0
size        = 0xf8 (CINUSE|PINUSE)
struct mp_header @ 0xacff59d8 {
mh_magic      = 0xa11c0123
mh_len        = 0xcc
mh_refcount   = 0x0
mh_unused     = 0x0
mh_fd_link    = 0xa9515ed0 (OK)
mh_bk_link    = 0xa84005c4 (-)
alloc_pc      = 0x8262b45 (-)
free_pc       = 0x0 (-)
```

Similarly, we can see significantly more data tacked onto the default dlmalloc
mstate shown by dlmstate:

```
(gdb) dlmstate
[libdlmalloc] Using cached mstate
struct dl_mstate @ 0xa8400008 {
smallmap    = 0b000000000000010000011111111100
treemap     = 0b000000000000000000000000000111
dvsize      = 0x0
topsize     = 0x2ebdf040
least_addr  = 0xa8400000
dv          = 0x0
top         = 0xad020f90
trim_check  = 0x200000
magic       = 0x2900d4d8
smallbin[00] (sz 0x0)   = 0xa840002c, 0xa840002c [EMPTY]
smallbin[01] (sz 0x8)   = 0xa8400034, 0xa8400034 [EMPTY]
smallbin[02] (sz 0x10)  = 0xacbf7ad0, 0xa88647f0
smallbin[03] (sz 0x18)  = 0xa95059b8, 0xa9689a20
smallbin[04] (sz 0x20)  = 0xac79a028, 0xa87206f8
smallbin[05] (sz 0x28)  = 0xacff0120, 0xa948a0f8
smallbin[06] (sz 0x30)  = 0xac4e4af8, 0xacb56878
smallbin[07] (sz 0x38)  = 0xacfe3880, 0xacfe0df0
smallbin[08] (sz 0x40)  = 0xa9509b28, 0xa9509b28
smallbin[09] (sz 0x48)  = 0xa8a1dc80, 0xa8a1dc80
smallbin[10] (sz 0x50)  = 0xac782cb0, 0xac782cb0
smallbin[11] (sz 0x58)  = 0xacbf7a88, 0xacbf7a88 [EMPTY]
smallbin[12] (sz 0x60)  = 0xac782c00, 0xac782c00 [EMPTY]
smallbin[13] (sz 0x68)  = 0xacbf7a78, 0xacbf7a78 [EMPTY]
smallbin[14] (sz 0x70)  = 0xa89b9650, 0xa89b9650 [EMPTY]
smallbin[15] (sz 0x78)  = 0xac789828, 0xac789828 [EMPTY]
smallbin[16] (sz 0x80)  = 0xa89b9738, 0xa94af740
smallbin[17] (sz 0x88)  = 0xac4e5700, 0xac4e5700 [EMPTY]
smallbin[18] (sz 0x90)  = 0xac788030, 0xac788030 [EMPTY]
smallbin[19] (sz 0x98)  = 0xac782bc8, 0xac782bc8 [EMPTY]
smallbin[20] (sz 0xa0)  = 0xa89b9718, 0xa89b9718 [EMPTY]
smallbin[21] (sz 0xa8)  = 0xa8a1dc20, 0xa8a1dc20 [EMPTY]
smallbin[22] (sz 0xb0)  = 0xac782af8, 0xac782af8 [EMPTY]
smallbin[23] (sz 0xb8)  = 0xac789ed0, 0xac789ed0 [EMPTY]
smallbin[24] (sz 0xc0)  = 0xacbf7a20, 0xacbf7a20 [EMPTY]
smallbin[25] (sz 0xc8)  = 0xac789940, 0xac789940 [EMPTY]
smallbin[26] (sz 0xd0)  = 0xac789eb8, 0xac789eb8 [EMPTY]
smallbin[27] (sz 0xd8)  = 0xa94af6e8, 0xa94af6e8 [EMPTY]
smallbin[28] (sz 0xe0)  = 0xacbf78e8, 0xacbf78e8 [EMPTY]
smallbin[29] (sz 0xe8)  = 0xac4e4e68, 0xac4e4e68 [EMPTY]
smallbin[30] (sz 0xf0)  = 0xac4e5780, 0xac4e5780 [EMPTY]
smallbin[31] (sz 0xf8)  = 0xac7880b0, 0xac7880b0 [EMPTY]
treebin[00] (sz 0x180)      = 0xac783cb0
treebin[01] (sz 0x200)      = 0xac789dc0
treebin[02] (sz 0x300)      = 0xa883db48
treebin[03] (sz 0x400)      =        0x0 [EMPTY]
treebin[04] (sz 0x600)      =        0x0 [EMPTY]
treebin[05] (sz 0x800)      =        0x0 [EMPTY]
treebin[06] (sz 0xc00)      =        0x0 [EMPTY]
treebin[07] (sz 0x1000)     =        0x0 [EMPTY]
treebin[08] (sz 0x1800)     =        0x0 [EMPTY]
treebin[09] (sz 0x2000)     =        0x0 [EMPTY]
treebin[10] (sz 0x3000)     =        0x0 [EMPTY]
treebin[11] (sz 0x4000)     =        0x0 [EMPTY]
treebin[12] (sz 0x6000)     =        0x0 [EMPTY]
treebin[13] (sz 0x8000)     =        0x0 [EMPTY]
treebin[14] (sz 0xc000)     =        0x0 [EMPTY]
treebin[15] (sz 0x10000)    =        0x0 [EMPTY]
treebin[16] (sz 0x18000)    =        0x0 [EMPTY]
treebin[17] (sz 0x20000)    =        0x0 [EMPTY]
treebin[18] (sz 0x30000)    =        0x0 [EMPTY]
treebin[19] (sz 0x40000)    =        0x0 [EMPTY]
treebin[20] (sz 0x60000)    =        0x0 [EMPTY]
treebin[21] (sz 0x80000)    =        0x0 [EMPTY]
treebin[22] (sz 0xc0000)    =        0x0 [EMPTY]
treebin[23] (sz 0x100000)   =        0x0 [EMPTY]
treebin[24] (sz 0x180000)   =        0x0 [EMPTY]
treebin[25] (sz 0x200000)   =        0x0 [EMPTY]
treebin[26] (sz 0x300000)   =        0x0 [EMPTY]
treebin[27] (sz 0x400000)   =        0x0 [EMPTY]
treebin[28] (sz 0x600000)   =        0x0 [EMPTY]
treebin[29] (sz 0x800000)   =        0x0 [EMPTY]
treebin[30] (sz 0xc00000)   =        0x0 [EMPTY]
treebin[31] (sz 0xffffffff) =        0x0 [EMPTY]
footprint   = 0x33800000
max_footprint = 0x33800000
mflags      = 0x7
mutex       = 0x0,0x0,0x0,0x0,0xa8400000,
seg = struct malloc_segment @ 0xa84001d4 {
base        = 0xa8400000
size        = 0x33800000
next        = 0x0
sflags      = 0x8
struct mp_mstate @ 0xa84001e4 {
mp_smallbin[00] - sz: 0x00000000 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[01] - sz: 0x00000008 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[02] - sz: 0x00000010 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[03] - sz: 0x00000018 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[04] - sz: 0x00000020 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[05] - sz: 0x00000028 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[06] - sz: 0x00000030 cnt: 0x0213, mh_fd_link: 0xacfdf800
mp_smallbin[07] - sz: 0x00000038 cnt: 0x0cb3, mh_fd_link: 0xaae0ff70
mp_smallbin[08] - sz: 0x00000040 cnt: 0x1c99, mh_fd_link: 0xac4e4b30
mp_smallbin[09] - sz: 0x00000048 cnt: 0x027b, mh_fd_link: 0xaae0fe30
mp_smallbin[10] - sz: 0x00000050 cnt: 0x0415, mh_fd_link: 0xac782c68
mp_smallbin[11] - sz: 0x00000058 cnt: 0x012d, mh_fd_link: 0xac799fd8
mp_smallbin[12] - sz: 0x00000060 cnt: 0x0125, mh_fd_link: 0xacbf7a78
mp_smallbin[13] - sz: 0x00000068 cnt: 0x0a06, mh_fd_link: 0xac789b78
mp_smallbin[14] - sz: 0x00000070 cnt: 0x003e, mh_fd_link: 0xa9515fc8
mp_smallbin[15] - sz: 0x00000078 cnt: 0x0074, mh_fd_link: 0xac789830
mp_smallbin[16] - sz: 0x00000080 cnt: 0x0124, mh_fd_link: 0xac7827a0
mp_smallbin[17] - sz: 0x00000088 cnt: 0x0016, mh_fd_link: 0xac799f50
mp_smallbin[18] - sz: 0x00000090 cnt: 0x0025, mh_fd_link: 0xac784e58
mp_smallbin[19] - sz: 0x00000098 cnt: 0x004e, mh_fd_link: 0xac4e56f8
mp_smallbin[20] - sz: 0x000000a0 cnt: 0x01c8, mh_fd_link: 0xacfefbf0
mp_smallbin[21] - sz: 0x000000a8 cnt: 0x0189, mh_fd_link: 0xacff05e0
mp_smallbin[22] - sz: 0x000000b0 cnt: 0x00e9, mh_fd_link: 0xacbf79c8
mp_smallbin[23] - sz: 0x000000b8 cnt: 0x0165, mh_fd_link: 0xac96be20
mp_smallbin[24] - sz: 0x000000c0 cnt: 0x0017, mh_fd_link: 0xac789a50
mp_smallbin[25] - sz: 0x000000c8 cnt: 0x001a, mh_fd_link: 0xacb4d998
mp_smallbin[26] - sz: 0x000000d0 cnt: 0x004d, mh_fd_link: 0xa9519150
mp_smallbin[27] - sz: 0x000000d8 cnt: 0x0024, mh_fd_link: 0xacbf78f0
mp_smallbin[28] - sz: 0x000000e0 cnt: 0x002c, mh_fd_link: 0xacff49d8
mp_smallbin[29] - sz: 0x000000e8 cnt: 0x0014, mh_fd_link: 0xa89b9658
mp_smallbin[30] - sz: 0x000000f0 cnt: 0x0008, mh_fd_link: 0xacfde720
mp_smallbin[31] - sz: 0x000000f8 cnt: 0x0044, mh_fd_link: 0xacff59d8
mp_treebin[00] - sz: 0x00000180 cnt: 0x0190, mh_fd_link: 0xacb48318
mp_treebin[01] - sz: 0x00000200 cnt: 0x0134, mh_fd_link: 0xa95059d8
mp_treebin[02] - sz: 0x00000300 cnt: 0x01ac, mh_fd_link: 0xad01cd38
mp_treebin[03] - sz: 0x00000400 cnt: 0x004e, mh_fd_link: 0xacffbac8
mp_treebin[04] - sz: 0x00000600 cnt: 0x0073, mh_fd_link: 0xac4e4fa0
mp_treebin[05] - sz: 0x00000800 cnt: 0x0030, mh_fd_link: 0xacfebe20
mp_treebin[06] - sz: 0x00000c00 cnt: 0x0277, mh_fd_link: 0xac7887e8
mp_treebin[07] - sz: 0x00001000 cnt: 0x004f, mh_fd_link: 0xa9507570
mp_treebin[08] - sz: 0x00001800 cnt: 0x0041, mh_fd_link: 0xac784fa8
mp_treebin[09] - sz: 0x00002000 cnt: 0x0010, mh_fd_link: 0xac74f248
mp_treebin[10] - sz: 0x00003000 cnt: 0x0024, mh_fd_link: 0xac796020
mp_treebin[11] - sz: 0x00004000 cnt: 0x0028, mh_fd_link: 0xacf9a3e0
mp_treebin[12] - sz: 0x00006000 cnt: 0x009a, mh_fd_link: 0xad01cf68
mp_treebin[13] - sz: 0x00008000 cnt: 0x000b, mh_fd_link: 0xacae3978
mp_treebin[14] - sz: 0x0000c000 cnt: 0x0027, mh_fd_link: 0xad014678
mp_treebin[15] - sz: 0x00010000 cnt: 0x000b, mh_fd_link: 0xacab7098
mp_treebin[16] - sz: 0x00018000 cnt: 0x0062, mh_fd_link: 0xacafa7c8
mp_treebin[17] - sz: 0x00020000 cnt: 0x0007, mh_fd_link: 0xac2cda88
mp_treebin[18] - sz: 0x00030000 cnt: 0x0012, mh_fd_link: 0xac800720
mp_treebin[19] - sz: 0x00040000 cnt: 0x000a, mh_fd_link: 0xac6e21e0
mp_treebin[20] - sz: 0x00060000 cnt: 0x0006, mh_fd_link: 0xaa5b0f28
mp_treebin[21] - sz: 0x00080000 cnt: 0x0004, mh_fd_link: 0xacf152e8
mp_treebin[22] - sz: 0x000c0000 cnt: 0x000e, mh_fd_link: 0xaac896f0
mp_treebin[23] - sz: 0x00100000 cnt: 0x0000, mh_fd_link: 0x0
mp_treebin[24] - sz: 0x00180000 cnt: 0x0004, mh_fd_link: 0xa934b730
mp_treebin[25] - sz: 0x00200000 cnt: 0x0001, mh_fd_link: 0xaa6d6cc8
mp_treebin[26] - sz: 0x00300000 cnt: 0x0003, mh_fd_link: 0xacc1feb0
mp_treebin[27] - sz: 0x00400000 cnt: 0x0001, mh_fd_link: 0xa8f39370
mp_treebin[28] - sz: 0x00600000 cnt: 0x0000, mh_fd_link: 0x0
mp_treebin[29] - sz: 0x00800000 cnt: 0x0001, mh_fd_link: 0xa9689a40
mp_treebin[30] - sz: 0x00c00000 cnt: 0x0001, mh_fd_link: 0xaae41208
mp_treebin[31] - sz: 0xffffffff cnt: 0x0001, mh_fd_link: 0xab641738 [UNSORTED]
```

## Callback dict

Right now we just blast a lot of information from libdlmalloc to the callback
function and it can choose to do whatever it wants to with the information. We
provide more information than most callbacks will need. Also the expectation is
that the callback will likely need to be aware of the plugin issuing the
callback, in order for it to inform what additional information it will show.
On the flip side, the plugin (libdlmalloc in this case) calling into the
callback doesn't currently need to know (or care) about anything that the
this external callback provider does.

An example of some of the data we provide to the callback function is:

* `caller`: name of calling gdb command or function
* `allocator`: backing allocator that manages the chunk address we send
* `addr`: address of the chunk contents after the core alloctor's metadata
* `hdr_sz`: size of the core allocator's metadata header
* `chunksz`: size of the chunk according to the core allocators metadata header
* `min_hdr_sz`: the minimum header size possible for this core allocator
* `data_size`: size of the data at `addr`
* `inuse`: whether a chunk is inuse according to the core allocator
* `chunk_info`: whether or not the calling library is printing chunk info
* `size_sz`: The calculated size of a `size_t` data type on the debugged platform

# Future development

We will likely add functionality to libdlmalloc as we need or while doing
future Cisco ASA research. Planned additions currently are:

- Abstract out the debug engine logic to be more like libheap or shadow's newer
  designs
- Write `dlsearch` which walks all msegments searching for some value.
- A dlchunk option for a free chunk that allows finding the bin by walking the
  linkage, and thus infering the associated `mstate` base address

# Notes on dlmalloc

## dlmalloc vs ptmalloc

The ptmalloc allocator, which is part of glibc, was regularly forked from
dlmalloc. The following table demonstrates the relationship of versions:

| dlmalloc       | ptmalloc  | Types of bins                |
| -------------- | --------- | ---------------------------- |
| dlmalloc 2.5.x | N/A       | bins                         |
| dlmalloc 2.6.x | ptmalloc  | smallbins/bins               |
| dlmalloc 2.7.x | ptmalloc2 | fastbins/smallbins/largebins |
| dlmalloc 2.8.x | ptmalloc3 | smallbins/treebins           |

## Reading

dlmalloc 2.8.x differs in many ways from earlier dlmalloc versions, namely due
to the use of a tree structure for large allocations. The best documentation is
the [source code](http://g.oswego.edu/pub/misc/). For some good background on
the differences between ptmalloc2 and ptmalloc3 (which translates to dlmalloc
2.7.x vs 2.8.x) see blackngel's Phrack 67 paper [The House Of Lore:
Reloaded](http://phrack.org/issues/67/8.html).

# Contact

We would love to hear feedback about this tool and also are happy to get pull
requests.

* Aaron Adams
    * Email: `aaron<dot>adams<at>nccgroup<dot>trust`
    * Twitter: @fidgetingbits

* Cedric Halbronn
    * Email: `cedric<dot>halbronn<at>nccgroup<dot>trust`
    * Twitter: @saidelike
