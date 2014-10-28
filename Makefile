all: xtftpd

xtftpd: xtftpd.cxx
	clang++ -std=c++11 -Wall -I/usr/local/include -L/usr/local/lib -lPocoFoundation -lPocoUtil -lPocoNet -o xtftpd xtftpd.cxx
