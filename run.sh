#!/bin/sh

make clean
make
rm -f stdout PQCencryptKAT_1413.rsp PQCencryptKAT_1413.req
./PQCgenKAT_encrypt > stdout
md5sum -c md5sums
