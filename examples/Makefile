all:
	$(foreach file, $(wildcard *.c), x86_64-unknown-linux-gnu-gcc $(file) -o build/$(basename $(file));)

clean:
	rm -r build/*
