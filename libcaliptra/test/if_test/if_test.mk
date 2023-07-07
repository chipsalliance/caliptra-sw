Q=@

SOURCE = if_test.c if_test_impl.c
OBJS := $(patsubst %.c,%.o, $(filter %.c,$(SOURCE)))

CALIPTRA_API = ../../src/caliptra_api.o

.PHONY = run clean

TARGET = if_test

INCLUDE = ../../inc/

$(TARGET): $(OBJS)
	$(Q)$(CC) -o $(TARGET) $(CFLAGS) $(CALIPTRA_API) $(OBJS)

%.o: %.c
	@echo [CC] $< \-\> $@
	$(Q)$(CC) ${CFLAGS} -c $< -o $@

run:
	$(Q)./$(TARGET)

clean:
	@echo [CLEAN] $(OBJS) $(TARGET)
	$(Q)rm -f $(OBJS) $(TARGET)
