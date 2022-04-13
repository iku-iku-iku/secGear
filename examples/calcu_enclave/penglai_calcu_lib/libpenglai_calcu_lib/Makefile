all: out/libpenglai_calcu_lib.a

out/calculate.o: calculate_lib/calculate.c
	mkdir out
	gcc -c -include bypass_to_penglai_tcalcu.h -o $@ $^

out/libpenglai_calcu_lib.a: out/calculate.o
	ar crv $@ $^

# Note: Try compile test.c with libpenglai_calcu_lib.a,
# the output will be 'undefined reference to `penglai_printf`',
# verify calcu_lib's POSIX interface is bypassed successfully.
out/test: calculate_lib/test_demo/test.c out/libpenglai_calcu_lib.a
	gcc -o $@ -I calculate_lib/ $^

clean:
	rm -r out
