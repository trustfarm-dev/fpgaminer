cmake_minimum_required (VERSION 2.8)

project(fpga_miner)


# Confirm LIBUSB Has Been Installed
IF (NOT WIN32)
	find_package(PkgConfig)
	pkg_check_modules(PC_LIBUSB libusb-1.0)
ENDIF(NOT WIN32)
FIND_PATH( LIBUSB_INCLUDE_DIR libusb.h  PATHS ${PC_LIBUSB_INCLUDEDIR} ${PC_LIBUSB_INCLUDE_DIRS}  PATH_SUFFIXES include )
FIND_LIBRARY( LIBUSB_LIBRARIES NAMES usb-1.0  PATHS ${PC_LIBUSB_LIBDIR} ${PC_LIBUSB_LIBRARY_DIRS} PATH_SUFFIXES lib )

IF (LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARIES)
	SET(LIBUSB_FOUND TRUE)
ELSE (LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARIES)
	SET(LIBUSB_FOUND FALSE)
ENDIF (LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARIES)

IF (LIBUSB_FOUND)
	message(STATUS "LIBUSB: Found")
ELSE (LIBUSB_FOUND)
	message(STATUS "LIBUSB: Not Found!")
ENDIF (LIBUSB_FOUND)


# Confirm CURL Has Been Installed
FIND_PATH( CURL_INCLUDE_DIR curl/curl.h  PATHS ${PC_CURL_INCLUDEDIR} ${PC_CURL_INCLUDE_DIRS}  PATH_SUFFIXES include )
FIND_LIBRARY( CURL_LIBRARIES NAMES curl  PATHS ${PC_CURL_LIBDIR} ${PC_CURL_LIBRARY_DIRS} PATH_SUFFIXES lib )

IF (CURL_INCLUDE_DIR AND CURL_LIBRARIES)
	SET(CURL_FOUND TRUE)
ELSE (CURL_INCLUDE_DIR AND CURL_LIBRARIES)
	SET(CURL_FOUND FALSE)
ENDIF (CURL_INCLUDE_DIR AND CURL_LIBRARIES)

IF (CURL_FOUND)
	message(STATUS "CURL: Found")
ELSE (CURL_FOUND)
	message(STATUS "CURL: Not Found!")
ENDIF (CURL_FOUND)


add_subdirectory(compat/jansson)

include_directories(${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/algo ${PROJECT_SOURCE_DIR}/compat/jansson ${CURL_INCLUDE_DIR} ${LIBUSB_INCLUDE_DIR})

set(SRC_LIST fpga-miner.c
		api.c
		fpgautils.c
		libztex.c
		util.c
		./algo/blake256-8.c
		./algo/blake2s.c
		./algo/groestl.c
		./algo/myr-groestl.c
		./algo/keccak256.c
		./algo/keccak512.c
		./algo/sha2.c
		./algo/sph_blake.c
		./algo/sph_blake2s.c
		./algo/sph_groestl.c
		./algo/sph_keccak.c
		./algo/sph_bmw.c
		./algo/sph_cubehash.c
		./algo/sph_skein.c
		./algo/sph_jh.c
		./algo/sponge.c
		./algo/lyra2.c
		./algo/lyra2re.c
		./algo/nist5.c
	)
			
set(TARGET_NAME fpga_miner)

IF ( WIN32 )
	add_executable(${TARGET_NAME} ${SRC_LIST} ./compat/winansi.c)
ELSE ( WIN32 )
	add_executable(${TARGET_NAME} ${SRC_LIST})
ENDIF ( WIN32 )

target_link_libraries(${TARGET_NAME} crypto pthread ${CURL_LIBRARIES} ${LIBUSB_LIBRARIES} jansson)

IF(WIN32)
	target_link_libraries(${TARGET_NAME} Ws2_32)
ENDIF(WIN32)

IF(UNIX)
	target_link_libraries(${TARGET_NAME} m)
ENDIF(UNIX)

set_target_properties( ${TARGET_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR} )
