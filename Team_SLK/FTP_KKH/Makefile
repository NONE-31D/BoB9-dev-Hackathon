include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o main.o main.cpp 
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o network-major main.o jsoncpp.cpp -I. -DJSON_IS_AMALGAMATION $(PCAPPP_LIBS)

# Clean Target
clean:
	rm main.o
	rm network-major
