SRC = func.cpp ftp.o http.o smtp.o

all: ftp http smtp
	g++ -o network-miner main.cpp $(SRC) -lpcap

ftp:
	g++ -c -o ftp.o ./FTP_SYL/FTP.cpp

http:
	g++ -c -o http.o ./HTTP_PSM/http.cpp

smtp:
	g++ -c -o smtp.o ./SMTP_KBS/smtp.cpp

clean:
	rm network-miner *.o