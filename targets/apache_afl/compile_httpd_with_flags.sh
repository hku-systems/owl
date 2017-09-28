#!/bin/bash

PREFIX="${PREFIX:-/usr/local/apache_clean}"

echo -e " \e[32mAPR"
echo
echo "Running apr with: c-compiler:$CC $CFLAGS c++-compiler:$CXX $CXXFLAGS"
sleep 2
cd apr-* && ./configure --prefix="$PREFIX" && apr=$(pwd) && make clean && make -j6 && sudo make install && cd ..

echo -e " \e[33mAPRUTIL"
echo
echo "Running aprutil with: c-compiler:$CC $CFLAGS c++-compiler:$CXX $CXXFLAGS"
sleep 2
cd apr-util-* && ./configure --prefix="$PREFIX" --with-apr=$apr && aprutil=$(pwd) && make clean && make -j6 && sudo make install && cd ..

echo -e " \e[34mPCRE"
echo
echo "Running pcre with: c-compiler:$CC $CFLAGS c++-compiler:$CXX $CXXFLAGS"
sleep 2
cd pcre-8* && ./configure --disable-cpp --prefix="$PREFIX" && pcre=$(pwd) && make clean && make -j6 && sudo make install && sudo make install && cd ..

echo -e " \e[35mNGHTTP"
echo
echo "Running nghttp with: c-compiler:$CC $CFLAGS c++-compiler:$CXX $CXXFLAGS"
sleep 2
cd nghttp2* && ./configure --prefix="$PREFIX" && nghttp=$(pwd) && make clean && make -j6 && sudo make install && cd ..

if [[ -z "$apr" || -z "$aprutil" || -z "$nghttp" || -z "$pcre" ]]; then
  echo "\e[0m[-] Dependencies compilation failed."
  echo APR: $apr
  echo APR-Util: $aprutil
  echo nghttp: $nghttp
  echo PCRE8: $pcre
  return 1;
fi

echo -e "\e[0m[+] Using the following paths"
echo $apr
echo $aprutil
echo $nghttp
echo $pcre
sleep 4

cd httpd-2*   
LIBS="-L$apr/.libs -L$aprutil/.libs -L$pcre/.libs -L$nghttp/lib/" CFLAGS=" $CFLAGS -I$nghttp/lib/includes -march=skylake -g -ggdb -fno-builtin -fno-inline -fsanitize=thread" LDFLAGS="$CFLAGS" ./configure --enable-unixd --disable-pie --enable-mods-static=few --prefix="$PREFIX" --with-mpm=event --enable-http2 --with-apr=$apr --with-apr-util=$aprutil --with-nghttp2=$nghttp --enable-nghttp2-staticlib-deps --with-pcre=$pcre/pcre-config && make clean && make -j6
