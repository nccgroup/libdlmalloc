* Add an offset command for printing objects? Seems useful to prefix with
  +0x124 type stuff
* dlsearch - walk an mstates segments looking for data
* Look into using argparse with a custom override for integer values that
  need to be read from gdb?
* remove all the old libheap stuff we don't actually use
* If we know the address of the mstate we could cache the address of the dv
  and check each free chunk we analyze against that value and mark it as
  such. This would prevent invalid values shown for the victim chunk when
  using -v.
* Support setting the dl_helper 'foot' option to dictate if we bother with the
  footer-related stuff
