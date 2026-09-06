CC      := cc
CFLAGS  := -O2 -Wall -Werror -fPIC
LDFLAGS := -shared

TARGET := pam_phone_approve.so
SRC    := pam_phone_approve.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpam

clean:
	rm -f $(TARGET)

.PHONY: all clean
