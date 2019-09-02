
#include <Corrade/configure.h>
#include <Corrade/Utility/Arguments.h>

#include <Magnum/GL/DefaultFramebuffer.h>

#ifdef CORRADE_TARGET_UNIX
#include <Magnum/Platform/WindowlessGlxApplication.h>
#endif
#ifdef CORRADE_TARGET_WINDOWS
#include <Magnum/Platform/WindowlessWglApplication.h>
#endif


#include <Magnum/ImageView.h>
#include <Magnum/PixelFormat.h>
#include <Magnum/GL/PixelFormat.h>


#include <memory>
#include <iostream>
#include <vector>
#include <chrono>

#include <k4a/k4a.hpp>
#include <opencv2/opencv.hpp>
#include "nvenc_rtsp/ServerPipeRTSP.h"


using namespace Magnum;

class K4AStreamSender : public Platform::WindowlessApplication {
public:
    explicit K4AStreamSender(const Arguments &arguments);
    int exec() override;

private:
    k4a::device m_dev;

    std::shared_ptr<nvenc_rtsp::ServerPipeRTSP> m_colorStream;
    std::shared_ptr<nvenc_rtsp::ServerPipeRTSP> m_depthStream;

    std::string m_ipAddress{"127.0.0.1"};
    unsigned int m_dstPort{55555};
    unsigned int m_bitrate{50};
    unsigned int m_framerate{30};

    bool m_debug{false};

    bool m_depthStreamEnabled{true};
    bool m_colorStreamEnabled{true};

};

K4AStreamSender::K4AStreamSender(const Arguments &arguments) : Platform::WindowlessApplication{arguments} {
    Magnum::Utility::Arguments args;
    args.addOption("ip", "127.0.0.1").setHelp("ip", "IP Address to bind to")
        .addOption("port", "55555").setHelp("port", "Port to bind to")
        .addBooleanOption("debug").setHelp("debug", "Show debug windows")
        .addBooleanOption("nodepth").setHelp("nodepth", "Skip depth stream")
        .addBooleanOption("nocolor").setHelp("nocolor", "Skip color stream")
        .addSkippedPrefix("magnum", "engine-specific options");

    args.parse(arguments.argc, arguments.argv);

    m_ipAddress = args.value("ip");
    m_dstPort = args.value<Magnum::Int>("port");
    m_debug = args.isSet("debug");
    m_depthStreamEnabled = !args.isSet("nodepth");
    m_colorStreamEnabled = !args.isSet("nocolor");

    // Check for devices
    //
    const uint32_t deviceCount = k4a::device::get_installed_count();
    if (deviceCount == 0) {
        throw std::runtime_error("No Azure Kinect devices detected!");
    }

    // Start the device
    //
    k4a_device_configuration_t config = K4A_DEVICE_CONFIG_INIT_DISABLE_ALL;
    config.camera_fps = K4A_FRAMES_PER_SECOND_30;
    config.depth_mode = K4A_DEPTH_MODE_NFOV_UNBINNED;
    config.color_format = K4A_IMAGE_FORMAT_COLOR_BGRA32;
    config.color_resolution = K4A_COLOR_RESOLUTION_1536P;

    // This means that we'll only get captures that have both color and
    // depth images, so we don't need to check if the capture contains
    // a particular type of image.
    //
    config.synchronized_images_only = true;

    Magnum::Debug{} << "Started opening K4A device...";

    m_dev = k4a::device::open(K4A_DEVICE_DEFAULT);
    m_dev.start_cameras(&config);

    Magnum::Debug{} << "Finished opening K4A device.";

}

int K4AStreamSender::exec() {
    Magnum::Debug{} << "Start Streaming";

    try{
        if (m_debug) {
            cv::namedWindow("ColorImage",cv::WINDOW_NORMAL);
            cv::namedWindow("DepthImage",cv::WINDOW_NORMAL);
        }
        cv::Mat colorImage;
        cv::Mat depthImage;

        k4a::capture capture;
        for(;;) {
            if (m_dev.get_capture(&capture, std::chrono::milliseconds(50)))
            {

                // Depth Image Stream
                if (m_depthStreamEnabled) {

                    NvPipe_Format nvpFormat{NVPIPE_RGBA32};

                    const k4a::image inputImage = capture.get_depth_image();
                    int w = inputImage.get_width_pixels();
                    int h = inputImage.get_height_pixels();


                    switch (inputImage.get_format()) {
                        case K4A_IMAGE_FORMAT_DEPTH16:
                            depthImage = cv::Mat(cv::Size(w, h), CV_16UC1, (void *)inputImage.get_buffer(), cv::Mat::AUTO_STEP);
                            nvpFormat = NVPIPE_UINT16;
                            break;

                        case K4A_IMAGE_FORMAT_IR16:
                        case K4A_IMAGE_FORMAT_COLOR_BGRA32:
                        case K4A_IMAGE_FORMAT_COLOR_MJPG:
                        case K4A_IMAGE_FORMAT_COLOR_NV12:
                        case K4A_IMAGE_FORMAT_COLOR_YUY2:
//                case K4A_IMAGE_FORMAT_CUSTOM8:
//                case K4A_IMAGE_FORMAT_CUSTOM16:
                        case K4A_IMAGE_FORMAT_CUSTOM:
                        default:
                            throw std::runtime_error("kinect4azure depth frame format is (currently) not supported!");
                    }

                    if (!m_depthStream) {
                        m_depthStream = std::make_shared<nvenc_rtsp::ServerPipeRTSP>(m_ipAddress, m_dstPort, nvpFormat, NVPIPE_LOSSLESS, NVPIPE_H264, m_bitrate, m_framerate);
                    }

                    unsigned long ts = inputImage.get_system_timestamp().count();
                    m_depthStream->send_frame(depthImage);
                    if (m_debug) {
                        Magnum::Debug{} << "got depth image: " << ts << "elemSize: " << depthImage.elemSize()  << "elemSize1: " << depthImage.elemSize1();
                        cv::imshow("DepthImage", depthImage);
                    }
                }

                if (m_colorStreamEnabled) {
                    NvPipe_Format nvpFormat{NVPIPE_RGBA32};

                    const k4a::image inputImage = capture.get_color_image();
                    int w = inputImage.get_width_pixels();
                    int h = inputImage.get_height_pixels();

                    switch (inputImage.get_format()) {
                        case K4A_IMAGE_FORMAT_COLOR_BGRA32:
                        {
                            auto tmpImage = cv::Mat(cv::Size(w, h), CV_8UC4, (void *)inputImage.get_buffer(), cv::Mat::AUTO_STEP);
                            cv::cvtColor(tmpImage, colorImage, cv::COLOR_BGRA2RGBA);
                            nvpFormat = NVPIPE_RGBA32;
                        }
                            break;

                        case K4A_IMAGE_FORMAT_DEPTH16:
                        case K4A_IMAGE_FORMAT_IR16:
                        case K4A_IMAGE_FORMAT_COLOR_MJPG:
                        case K4A_IMAGE_FORMAT_COLOR_NV12:
                        case K4A_IMAGE_FORMAT_COLOR_YUY2:
//                case K4A_IMAGE_FORMAT_CUSTOM8:
//                case K4A_IMAGE_FORMAT_CUSTOM16:
                        case K4A_IMAGE_FORMAT_CUSTOM:
                        default:
                            throw std::runtime_error("kinect4azure color frame format is (currently) not supported!");
                    }

                    if (!m_colorStream) {
                        m_colorStream = std::make_shared<nvenc_rtsp::ServerPipeRTSP>(m_ipAddress, m_dstPort+1, nvpFormat, NVPIPE_LOSSLESS, NVPIPE_H264, m_bitrate, m_framerate);
                    }

                    unsigned long ts = inputImage.get_system_timestamp().count();
                    m_colorStream->send_frame(colorImage);
                    if (m_debug) {
                        Magnum::Debug{} << "got color images: " << ts << "elemSize: " << colorImage.elemSize()  << "elemSize1: " << colorImage.elemSize1();
                        cv::Mat rgb;
                        cv::cvtColor(colorImage, rgb, cv::COLOR_RGBA2BGR);
                        cv::imshow("ColorImage", rgb);
                        if(cv::waitKey(5) >= 0) break;

                    }
                }

            } else {
                Magnum::Debug{} << "No Frame received for 50ms.";
            }
        }
    } catch (std::exception &e) {
        Magnum::Debug{} << "Exception: " << e.what();
        return 1;
    }
    m_dev.close();
    return 0;
}

MAGNUM_WINDOWLESSAPPLICATION_MAIN(K4AStreamSender)
