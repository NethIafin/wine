## How to install:

1. Packages
`doas pkg_add git gmake bison llvm libinotify`

2. PE cross-compiler wrapper. The llvm package strips clang's builtin headers, so this puts them back in a private resource dir
```sh
CLANG=$(ls /usr/local/bin/clang-[0-9]* | sort -t- -k2 -n | tail -1)
FULLV=$($CLANG --version | sed -n 's/.*clang version \([0-9.]*\).*/\1/p')
RES=~/.local/lib/clang-pe; mkdir -p $RES ~/.local/bin
cp -R "$($CLANG -print-resource-dir)/include" $RES/
for h in float.h inttypes.h iso646.h limits.h stdarg.h stdbool.h stddef.h stdint.h; do
  ftp -o $RES/include/$h https://raw.githubusercontent.com/llvm/llvm-project/llvmorg-$FULLV/clang/lib/Headers/$h
done
printf '#!/bin/sh\nexec %s -resource-dir %s "$@"\n' $CLANG $RES > ~/.local/bin/clang-pe
chmod +x ~/.local/bin/clang-pe; export PATH=~/.local/bin:$PATH
```

3. Build (takes some good time to complete)
ulimit required because some files are too large to compile on default limits
`sysctl -n hw.ncpuonline` - gives you how many cpu's you have
```sh
cd ~/src/wine-src && mkdir build64 && cd build64
../configure --enable-archs=x86_64 x86_64_CC=clang-pe --disable-tests --without-wayland \
  LDFLAGS=-L/usr/local/lib \
  INOTIFY_LIBS="-L/usr/local/lib/inotify -Wl,-rpath,/usr/local/lib/inotify -linotify"
ulimit -d $(ulimit -H -d)
gmake -j$(sysctl -n hw.ncpuonline)
```
You can add `--with-opengl` after `--disable-tests` to force OpenGL build. Simpler to work with on VM or old PCs.

4. Install
`doas env PATH=$PATH gmake install`
Install into wxallowed mount

5. Add `:openfiles-cur=4096:openfiles-max=16384:` to your login class in /etc/login.conf, then log in again.
Most windows apps will need a ton of openfiles

6. Create the prefix and run an app
```sh
wineboot -i                    # creates ~/.wine
wine notepad
wine /path/to/the.exe
```

## Issues:

### Cannot run 32 bit windows apps
This cannot be supported at all. Thankfully most apps are transitioning to full 64 bits.

### Cannot pass integrity checks or local anti-cheat does not work
Wine under OpenBSD has to actively create Stubs and will rewrite code to jump to those stubs. This is the only way to fix %gs on OpenBSD.

### Sound is choppy / breaking
Winepulse on Wine for OpenBSD and pulseaudio driver on OpenBSD needs some love. Unfortunately Wine uses pulseaudio.

### Application that works well on Linux is lagging hard on OpenBSD
There are 2 more fixes that are required before this port is fixed
1. SIGUSR1/SIGUSR2 - Process cannot signal a chosen thread on another process. It will be processed by currently active thread on that process. This means that we need to store the target thread ID, send signal, check signal on the receiving end, and then pass it to correct thread on the receiving end by retrieving back the thread ID. Chromium/Electron applications love using that to wait/wake on data received from the internet.
2. LEA+%GS smart fix - some applications that use mimalloc will inline a 4 byte instruction that we cannot patch (we need 5+ byte instruction). We can take LEA that is behind it and together send it into a stub. Most applications don't use mimalloc, but those that do might have up to about 20% decreased performance as they have to pay full SIGSEGV round trip for every case until that smart fix is implemented.

There are also issues with drivers. OpenBSD generally has delayed support and only Intel/Radeon works well (no NVidia).
