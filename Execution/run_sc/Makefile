CC64 = x86_64-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -w -Wno-incompatible-pointer-types -fno-stack-check -mno-stack-arg-probe -Os -DBOF -c


bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	# 64-bit build
	@($(CC64) $(CFLAGS) runsc.c -o _bin/runsc.x64.o && $(STRIP64) _bin/runsc.x64.o && echo '[+] runsc x64' || echo '[!] runsc x64')
clean:
	@(rm -rf _bin)



