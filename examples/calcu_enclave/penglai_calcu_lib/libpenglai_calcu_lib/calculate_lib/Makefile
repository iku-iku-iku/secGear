all: calculate.a test_demo/test

calculate.o: calculate.c
	gcc -c -o $@ $^

calculate.a: calculate.o
	ar crv $@ $^

test_demo/test: test_demo/test.c calculate.a
	gcc -o $@ -I. $^

clean:
	rm *.a *.o test_demo/test
