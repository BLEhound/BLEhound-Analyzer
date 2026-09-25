# libblehound: BLEhound sniffer dongle host protocol (Apache-2.0).
# Independent of Wireshark; usable standalone with a plain CMake project.

add_library(blehound STATIC
	src/cobs.c
	src/cmd.c
	src/frame.c
	src/adv.c
	src/agg.c
	src/sync.c
	src/aes128.c
	src/rpa.c
)
target_include_directories(blehound PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(blehound PROPERTIES
	POSITION_INDEPENDENT_CODE ON
	FOLDER "Libs"
)

add_executable(blehound_test tests/test_blehound.c)
target_link_libraries(blehound_test blehound)
set_target_properties(blehound_test PROPERTIES FOLDER "Tests")

add_executable(blehound_raw2pcap tests/raw2pcap.c)
target_link_libraries(blehound_raw2pcap blehound)
set_target_properties(blehound_raw2pcap PROPERTIES FOLDER "Tests")

add_executable(blehound_tri2pcap tests/tri2pcap.c)
target_link_libraries(blehound_tri2pcap blehound)
set_target_properties(blehound_tri2pcap PROPERTIES FOLDER "Tests")
