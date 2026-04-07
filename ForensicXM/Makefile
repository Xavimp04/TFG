CC=gcc
CFLAGS=-I./include
SRC=src/main.c src/analyzer_sys.c src/analyzer_users.c src/persistence.c src/analyzer_logs.c src/analyzer_bin.c src/analyzer_integrity.c src/report.c src/analyzer_net.c src/analyzer_memory.c src/analyzer_rootkit.c src/analyzer_caps.c src/cJSON.c
OBJ=$(SRC:.c=.o)
BIN=bin/forensicXM

LDFLAGS=-lcrypto

all: $(BIN)

$(BIN): $(SRC)
	mkdir -p bin
	$(CC) $(CFLAGS) $(SRC) -o $(BIN) $(LDFLAGS)

clean:
	rm -f bin/forensicXM src/*.o