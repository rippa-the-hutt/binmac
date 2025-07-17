.EXPORT_ALL_VARIABLES:
P=binmac
PD=debug
S=assembly
T=test
EXT_SOURCES= binIO.cpp
EXT_OBJECTS= RippaSSL/Cipher.o RippaSSL/Mac.o RippaSSL/Base.o binIO.o
EXT_ASSEMBL= RippaSSL/Cipher.s RippaSSL/Mac.s RippaSSL/Base.s binIO.s
SOURCES=main.cpp $(EXT_SOURCES)
OBJECTS=main.o $(EXT_OBJECTS)
ASSEMBL=main.s $(EXT_ASSEMBL)
T_SOURCES=tests.cpp $(EXT_SOURCES)
T_OBJECTS=tests.o $(EXT_OBJECTS)
DFLAGS= -Wall -ggdb -O0 -std=c++17 -D_GLIBCXX_DEBUG
CFLAGS= -Wall       -Os -std=c++17
LDLIBS= -lssl -lcrypto
CC=g++

$(P): $(P).o
	$(CC) -o $(P) $(OBJECTS) $(LDLIBS)

$(P).o: $(SOURCES)
	$(CC) $(CFLAGS) -c $(SOURCES)
	cd RippaSSL && $(MAKE)

$(PD): $(PD).o
	$(CC) -o $(PD) $(OBJECTS) $(LDLIBS)

$(PD).o: $(SOURCES)
	$(CC) $(DFLAGS) -c $(SOURCES)
	cd RippaSSL && $(MAKE) $(PD).o

$(T): $(T).o
	$(CC) -o $(T) $(T_OBJECTS) $(LDLIBS)

$(T).o: $(T_SOURCES)
	$(CC) $(DFLAGS) -c $(T_SOURCES)
	cd RippaSSL && $(MAKE) $(T).o

$(S): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDLIBS) -fverbose-asm -S $(SOURCES)
	cd RippaSSL && $(MAKE) $(S)

clean:
	rm *.o *.exe $(OBJECTS) $(P) $(PD) $(T) $(ASSEMBL)
