CC=gcc
CFLAGS=-I./include
SRC=src/main.c src/analyzer_sys.c src/analyzer_users.c src/persistence.c src/analyzer_logs.c src/analyzer_bin.c
OBJ=$(SRC:.c=.o)
BIN=bin/forensicXM

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(BIN)

clean:
	rm -f bin/forensicXM src/*.o