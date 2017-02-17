# libFuzz
libFuzz testing



BASIC Conversion 
1. const uint8_t *data to  const char * buffer
	reinterpret_cast<const char *>(data)
	
2. 	const uint8_t *data to unsigned char *md
	std::string s(reinterpret_cast<const char *>(Data), Size);
	s.c_str()
