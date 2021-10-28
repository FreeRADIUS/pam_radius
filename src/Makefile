all: pam_radius_auth.o md5.o

pam_radius_auth.o: pam_radius_auth.c pam_radius_auth.h config.h
	$(CC) $(CFLAGS) -c $< -o $@

md5.o: md5.c md5.h
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	@rm -f *~ *.so *.o src/*.o src/*~
