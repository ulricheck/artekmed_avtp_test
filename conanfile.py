from conans import ConanFile, CMake
from conans import tools
from conans.tools import os_info, SystemPackageTool
import os, sys
import sysconfig
from io import StringIO

class ArtekmedP02Conan(ConanFile):
    name = "artekmed_k4a_capture"
    version = "0.1.0"

    description = "artekmed_k4a_capture"
    url = "https://github.com/TUM-CAMP-NARVIS/artekmed_k4a_capture"
    license = "GPL"

    short_paths = True
    settings = "os", "compiler", "build_type", "arch"
    generators = "cmake", "virtualrunenv"

    requires = (
        "magnum/2019.01@camposs/stable",
        "corrade/2019.01@camposs/stable",
        "opencv/3.4.3@camposs/stable",
        "nvpipe/0.2@camposs/stable",
        "libavtp/0.1@camposs/stable",
        "kinect-azure-sensor-sdk/1.2.0@camposs/stable",
        )

    default_options = {
        "magnum:with_anyimageimporter": True,
        "magnum:with_tgaimporter": True,
        "magnum:with_anysceneimporter": True,
        "magnum:with_gl_info": True,
        "magnum:with_objimporter": True,
        "magnum:with_tgaimageconverter": True,
        "magnum:with_imageconverter": True,
        "magnum:with_anyimageconverter": True,
        "magnum:with_sdl2application": True,
        "magnum:with_eglcontext": False,
        "magnum:with_windowlesseglapplication": False,
        "magnum:target_gles": False,
        "magnum:with_opengltester": True,
    }

    # all sources are deployed with the package
    exports_sources = "modules/*", "src/*", "CMakeLists.txt"

    def configure(self):
        self.options["opencv"].with_gtk = True
        self.options["opencv"].shared = True
        self.options['magnum'].with_windowlessglxapplication = True

    def imports(self):
        self.copy(src="bin", pattern="*.dll", dst="./bin") # Copies all dll files from packages bin folder to my "bin" folder
        self.copy(src="lib", pattern="*.dll", dst="./bin") # Copies all dll files from packages bin folder to my "bin" folder
        self.copy(src="lib", pattern="*.dylib*", dst="./lib") # Copies all dylib files from packages lib folder to my "lib" folder
        self.copy(src="lib", pattern="*.so*", dst="./lib") # Copies all so files from packages lib folder to my "lib" folder
        self.copy(src="lib", pattern="*.a", dst="./lib") # Copies all static libraries from packages lib folder to my "lib" folder
        self.copy(src="bin", pattern="*", dst="./bin") # Copies all applications

    def build(self):
        cmake = CMake(self)
        cmake.verbose = True
        cmake.configure()
        cmake.build()
        cmake.install()
