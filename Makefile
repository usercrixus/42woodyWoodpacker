CC      := cc
CFLAGS  := -Wall -Wextra -Werror -std=c11 -Iinclude
LDFLAGS := -Wl,-Tsrc/stub/woody_stub.ld
NAME    := woody_woodpacker

SRCS    := src/main.c src/packer.c src/encryption/xtea_ctr/xtea_ctr_encrypt.c src/encryption/xtea_ctr/xtea_ctr_decrypt.c src/utils.c src/stub/decrypt.c
OBJS    := $(SRCS:.c=.o)

all: $(NAME)

$(NAME): $(OBJS) src/stub/woody_stub.ld
	$(CC) $(OBJS) $(LDFLAGS) -o $(NAME)

src/%.o: src/%.c include/woody.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
