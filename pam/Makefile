CC      := cc
CFLAGS  := -O2 -Wall -Werror -fPIC
LDFLAGS := -shared

TARGET := pam_fingerkey.so
SRC    := pam_fingerkey.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpam

clean:
	rm -f $(TARGET)

.PHONY: all clean
