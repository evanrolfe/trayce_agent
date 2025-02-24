# Dynamically link libelf

**Background:**

`apt install` was failing in CI, saying it could not find the repository sources. I think this should work but after looking into it I realised the build container in `Dockerfile` was running Ubuntu 22.04 which is 3 years old now, so I decided to upgrade to 25.04. This then brought about a new error when compiling the binary. I resolved it using a cursor-generated fix (it changed it to be dynamically linked). So it compiled succesfully, but then at run time I was getting this error:
```
sh: ./trayce_agent: not found
```

**Problem:**
This was confusing because the `./trayce_agent` file was there, I soon realised that the binary was being executed but it was failing to find the dyamically linked library `libelf`. I then tried going back to static linking:
```
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'
```
But the I got this error:
```
31.72 /usr/local/go/pkg/tool/linux_amd64/link: running gcc failed: exit status 1
31.72 /usr/bin/gcc -m64 -o $WORK/b001/exe/a.out ...
31.72 /usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/14/../../../x86_64-linux-gnu/libelf.a(elf_begin.o): in function `file_read_elf':
31.72 (.text+0x2c9): undefined reference to `eu_search_tree_init'
31.72 /usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/14/../../../x86_64-linux-gnu/libelf.a(elf_end.o): in function `elf_end':
31.72 (.text+0xd7): undefined reference to `eu_search_tree_fini'
31.72 collect2: error: ld returned 1 exit status
```

After much trial and error I found this bug:

https://sourceware.org/bugzilla/show_bug.cgi?id=32293

So it appears that there is a bug in [libelf](https://sourceware.org/git/?p=elfutils.git) v0.192 which means it can't be statically linked. That bug has been fixed but a new version containing that fix hasn't been released yet. From their commit history it looks like they release twice a year - once around November and once around March. So hopefully a release will be done soon.

**Solution:**
The temporary solution is to use a dynamically linked binary. I couldn't figure out which alpine packages to install so I just used ubuntu for the final image too. Once version 0.193 is released we can use this to go back to static linking + alpine.
