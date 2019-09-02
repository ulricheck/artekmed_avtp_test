find_package(Magnum REQUIRED GL)
if(CORRADE_TARGET_UNIX)
    find_package(Magnum REQUIRED WindowlessGlxApplication)
endif()
if(CORRADE_TARGET_WINDOWS)
    find_package(Magnum REQUIRED WindowlessWglApplication)
endif()

find_package(CUDA REQUIRED)

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

add_executable(opencv_stream_sender opencv_stream_sender.cpp)
set_property(TARGET opencv_stream_sender PROPERTY CXX_STANDARD 11)

target_link_libraries(opencv_stream_sender PRIVATE
        CONAN_PKG::magnum
        CONAN_PKG::corrade
        CONAN_PKG::opencv
        CONAN_PKG::nvenc_rtsp
)
target_include_directories(opencv_stream_sender
        PRIVATE ${CUDA_INCLUDE_DIRS}
        )
