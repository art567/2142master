EXE		= stcppipe
CFLAGS		+= -O2 -s

DESTDIR		=
prefix		= /usr/local
exec_prefix	= $(prefix)
bindir		= $(exec_prefix)/bin
BINDIR		= $(DESTDIR)$(bindir)

SRC		= $(EXE).c
LIBS		= -lssl -lcrypto -lpthread

all:
	$(CC) $(SRC) $(CFLAGS) -o $(EXE) $(LIBS)

install:
	install -m 755 -d $(BINDIR)
	install -m 755 $(EXE) $(BINDIR)

clean:
	rm -f *.o $(EXE)

.PHONY: clean install
