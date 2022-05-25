* Start target process with gdb
* starti to start after load
* info file to find out randomized entry point address
* break on the entry

* disable ASLR
   `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`
