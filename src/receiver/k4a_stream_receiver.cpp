
#include <Corrade/configure.h>
#include <Corrade/Utility/Arguments.h>
#include <Corrade/Utility/System.h>

#include <Magnum/GL/DefaultFramebuffer.h>

#include <Magnum/Platform/GlfwApplication.h>

#include <Magnum/ImageView.h>
#include <Magnum/PixelFormat.h>
#include <Magnum/GL/PixelFormat.h>


#include <memory>
#include <iostream>
#include <vector>
#include <chrono>
#include <deque>
#include <mutex>

#include <opencv2/opencv.hpp>
#include "nvenc_rtsp/ClientPipeRTSP.h"

using namespace Magnum;

struct Frame {

    Frame() = default;
    Frame(const Frame& other) noexcept {
        depthImage = other.depthImage;
        colorImage = other.colorImage;
        have_depthImage = other.have_depthImage;
        have_colorImage = other.have_colorImage;
        timestamp = other.timestamp;
        is_valid = other.is_valid;
    }

    Frame& operator=(const Frame& other)  noexcept {
        depthImage = other.depthImage;
        colorImage = other.colorImage;
        have_depthImage = other.have_depthImage;
        have_colorImage = other.have_colorImage;
        timestamp = other.timestamp;
        is_valid = other.is_valid;
        return *this;
    }

    Frame(Frame&& other) noexcept
    : depthImage(std::move(other.depthImage))
    , colorImage(std::move(other.colorImage))
    , timestamp(other.timestamp)
    , have_colorImage(other.have_colorImage)
    , have_depthImage(other.have_depthImage)
    , is_valid(other.is_valid)
    {}

    cv::Mat depthImage;
    cv::Mat colorImage;
    uint64_t timestamp{0};
    bool have_colorImage{false};
    bool have_depthImage{false};
    bool is_valid{false};
};

class K4AStreamReceiver : public Platform::GlfwApplication {
public:
    explicit K4AStreamReceiver(const Arguments &arguments);

private:
    void drawEvent() override;

    void forwardCompletedFrames();

    std::shared_ptr<nvenc_rtsp::ClientPipeRTSP> m_colorStream;
    std::shared_ptr<nvenc_rtsp::ClientPipeRTSP> m_depthStream;

    size_t m_maxReceiveQueueSize{16};
    std::deque<Frame> m_resultQueue;
    std::deque<Frame> m_receiveQueue;
    std::mutex m_receiverWriteLock;

    std::string m_depthStreamUrl;
    std::string m_colorStreamUrl;

    bool m_debug{false};
    bool m_depthStreamEnabled{true};
    bool m_colorStreamEnabled{true};
};

K4AStreamReceiver::K4AStreamReceiver(const Arguments &arguments) : Platform::GlfwApplication{arguments} {
    Magnum::Utility::Arguments args;
    args.addOption("ip", "127.0.0.1").setHelp("ip", "IP Address to bind to")
        .addOption("port", "55555").setHelp("port", "Port to bind to")
        .addBooleanOption("debug").setHelp("debug", "Show debug windows")
        .addBooleanOption("nodepth").setHelp("nodepth", "Skip depth stream")
        .addBooleanOption("nocolor").setHelp("nocolor", "Skip color stream")
        .addSkippedPrefix("magnum", "engine-specific options");

    args.parse(arguments.argc, arguments.argv);

    std::string ipAddress = args.value("ip");
    unsigned int srcPort = args.value<Magnum::Int>("port");
    m_debug = args.isSet("debug");
    m_depthStreamEnabled = !args.isSet("nodepth");
    m_colorStreamEnabled = !args.isSet("nocolor");

    m_depthStreamUrl = "rtsp://" + ipAddress + ":" + std::to_string(srcPort) + "/live";
    m_colorStreamUrl = "rtsp://" + ipAddress + ":" + std::to_string(srcPort+1) + "/live";

    if (m_depthStreamEnabled) {
        m_depthStream = std::make_shared<nvenc_rtsp::ClientPipeRTSP>(m_depthStreamUrl, NVPIPE_UINT16, NVPIPE_H264,
                                                                     [&](cv::Mat mat, uint64_t timestamp) {
                 auto size = mat.size();
                 Magnum::Debug{} << "Received Depth Image: " << timestamp << " size: " << size;
                 std::lock_guard<std::mutex> lock(
                         m_receiverWriteLock);

                 bool frameStored{false};
                 for (Frame &frame: m_receiveQueue) {
                     if (!frame.have_depthImage) {
                         if (frame.timestamp == timestamp) {
                             frame.have_depthImage = true;
                             frame.depthImage = mat;
                             Magnum::Debug{} << "Completed Frame with depthImage " << timestamp;
                             frameStored = true;
                             break;
                         } else {
                             Magnum::Debug{} << "Have frame non-matching timestamp: " << frame.timestamp << " != " << timestamp;
                         }
                     }
                 }

                 if (!frameStored) {
                     Frame frame;
                     frame.have_depthImage = true;
                     frame.timestamp = timestamp;
                     frame.depthImage = mat;
                     Magnum::Debug{} << "Created Frame with depthImage " << timestamp;
                     m_receiveQueue.push_back(std::move(frame));
                 }
             });
        if (m_debug) {
            cv::namedWindow("DepthImage",cv::WINDOW_NORMAL);
        }
    }

    if (m_colorStreamEnabled) {
        m_colorStream = std::make_shared<nvenc_rtsp::ClientPipeRTSP>(m_colorStreamUrl, NVPIPE_RGBA32, NVPIPE_H264,
                                                                     [&](cv::Mat mat, uint64_t timestamp) {

                 auto size = mat.size();
                 Magnum::Debug{} << "Received Color Image: " << timestamp << " size: " << size;
                 std::lock_guard<std::mutex> lock(m_receiverWriteLock);

                 bool frameStored{false};
                 for (Frame &frame: m_receiveQueue) {
                     if (!frame.have_colorImage) {
                         if (frame.timestamp == timestamp) {
                             frame.have_colorImage = true;
                             frame.colorImage = mat;
                             frameStored = true;
                             break;
                         } else {
                             Magnum::Debug{} << "Have frame non-matching timestamp: " << frame.timestamp << " != " << timestamp;
                         }
                     }
                 }

                 if (!frameStored) {
                     Frame frame;
                     frame.have_colorImage = true;
                     frame.timestamp = timestamp;
                     frame.colorImage = mat;
                     m_receiveQueue.push_back(std::move(frame));
                 }
             });
        if (m_debug) {
            cv::namedWindow("ColorImage",cv::WINDOW_NORMAL);
        }
    }


    Magnum::Debug{} << "Finished starting receivers.";
}

void K4AStreamReceiver::drawEvent() {
    forwardCompletedFrames();

    if (!m_resultQueue.empty()) {
        auto frame = m_resultQueue.front();
        m_resultQueue.pop_front();
        Magnum::Debug{} << "Received complete frame for rendering: " << frame.timestamp;
        if (frame.is_valid) {
            if ((m_debug) && (frame.have_depthImage)) {
                cv::imshow("DepthImage", frame.depthImage);
            }
            if ((m_debug) && (frame.have_colorImage)) {
                cv::Mat displImage;
                cv::cvtColor(frame.colorImage, displImage, cv::COLOR_RGBA2BGR);
                cv::imshow("ColorImage", displImage);
                if(cv::waitKey(5) >= 0) {
                    exit();
                };
            }
        }
    }
    GL::defaultFramebuffer.clear(GL::FramebufferClear::Color);

    // render the pointcloud here.

    swapBuffers();
    redraw();
}

void K4AStreamReceiver::forwardCompletedFrames() {

    std::lock_guard<std::mutex> lock(m_receiverWriteLock);
    while ((!m_receiveQueue.empty()) &&
           (m_receiveQueue.front().have_colorImage == m_colorStreamEnabled) &&
           (m_receiveQueue.front().have_depthImage == m_depthStreamEnabled))
    {
        auto frame = m_receiveQueue.front();
        frame.is_valid = true;
        m_resultQueue.push_back(std::move(frame));
        m_receiveQueue.pop_front();
    }

    // cleanup queue remove leftover incomplete frames
    while (m_receiveQueue.size() > m_maxReceiveQueueSize) {
        auto frame = m_receiveQueue.front();
        Magnum::Warning{} << "Dropping incomplete frame: " << frame.timestamp << " color image: " << frame.have_colorImage << " depth image: " << frame.have_depthImage;
        m_receiveQueue.pop_front();
    }
}

MAGNUM_APPLICATION_MAIN(K4AStreamReceiver)
