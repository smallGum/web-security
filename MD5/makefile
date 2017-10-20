vpath %.h header
vpath %.c src
main: main.o md5.o
	gcc -o $@ main.o md5.o
main.o: main.c md5.h
	gcc -c $< -Iheader
md5.o: md5.c md5.h
	gcc -c $< -Iheader
.PHONY:clean
clean:
	-rm main *.o
