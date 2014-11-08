export CPLUS_INCLUDE_PATH=/usr/local/include:/opt/local/include
export LIBRARY_PATH=/usr/local/lib:/opt/local/lib

all: xtftpd

clean:
	rm xtftpd

xtftpd: xtftpd.cxx
	clang++ -g -std=c++11 -Wall -I/usr/local/include -I/opt/local/include -L/usr/local/lib -L/opt/local/lib -llog4cxx -lPocoFoundation -lPocoUtil -lPocoNet -o xtftpd xtftpd.cxx
