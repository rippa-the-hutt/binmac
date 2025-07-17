LOCAL_SOURCES= Cipher.cpp Mac.cpp Base.cpp
LOCAL_OBJECTS= Cipher.o   Mac.o   Base.o

$(P).o: $(LOCAL_SOURCES)
	$(CC) $(CFLAGS) -c $(LOCAL_SOURCES)

$(PD).o: $(LOCAL_SOURCES)
	$(CC) $(DFLAGS) -c $(LOCAL_SOURCES)

$(T).o: $(LOCAL_SOURCES)
	$(CC) $(DFLAGS) -c $(LOCAL_SOURCES)

$(S): $(LOCAL_OBJECTS)
	$(CC) $(CFLAGS) -fverbose-asm -S $(LOCAL_SOURCES)
