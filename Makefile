GCC     := gcc
CFLAGS  := -Wall -Wextra -Werror -std=c11 -Iinclude
LDFLAGS := -Wl,-Tstub/woody_stub.ld
NAME    := woody_woodpacker

SRCS    := src/main.c src/packer.c src/encryption.c src/utils.c stub/decrypt.c
OBJS    := $(SRCS:.c=.o)

all: $(NAME)

$(NAME): $(OBJS) stub/woody_stub.ld
	$(GCC) $(OBJS) $(LDFLAGS) -o $(NAME)

src/%.o: src/%.c include/woody.h
	$(GCC) $(CFLAGS) -c $< -o $@

stub/%.o: stub/%.c include/woody.h
	$(GCC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
