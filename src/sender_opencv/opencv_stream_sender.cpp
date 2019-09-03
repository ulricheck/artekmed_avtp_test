
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


#include <alloca.h>
#include <argp.h>
#include <arpa/inet.h>
#include <cassert>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <opencv2/opencv.hpp>
#include <NvPipe.h>

#include "avtp.h"
#include "avtp_cvf.h"
#include "avtp_common.h"


using namespace Magnum;

#define STREAM_ID		0xAABBCCDDEEFF0001
#define DATA_LEN		1400
#define AVTP_H264_HEADER_LEN	(sizeof(uint32_t))
#define AVTP_FULL_HEADER_LEN	(sizeof(struct avtp_stream_pdu) + AVTP_H264_HEADER_LEN)
#define MAX_PDU_SIZE		(AVTP_FULL_HEADER_LEN + DATA_LEN)

enum process_result {PROCESS_OK, PROCESS_NONE, PROCESS_ERROR};


class OpenCVStreamSender : public Platform::WindowlessApplication {
public:
    explicit OpenCVStreamSender(const Arguments &arguments);
    int exec() override;

protected:
    int init_pdu(struct avtp_stream_pdu *pdu);
    ssize_t fill_buffer(void);
    ssize_t start_code_position(size_t offset);
    int prepare_packet(struct avtp_stream_pdu *pdu, char *nal_data, size_t nal_data_len);
    int process_nal(struct avtp_stream_pdu *pdu, bool process_last, size_t *nal_len);

private:
    std::shared_ptr<cv::VideoCapture> m_dev;

    NvPipe* m_colorStreamEncoder{NULL};
    std::vector<uint8_t> m_colorBuffer;

    uint64_t m_stream_id{0xAABBCCDDEEFF0001};

    std::string m_avtp_ifname{""};
    uint8_t m_avtp_macaddr[ETH_ALEN];
    int m_avtp_priority{-1};
    int m_avtp_max_transit_time{0};
    char m_avtp_buffer[MAX_PDU_SIZE * 2];
    size_t m_avtp_buffer_level{0};
    uint8_t m_avtp_seq_num{0};


//    std::string m_macAddress{""};
//    unsigned int m_dstPort{55555};
    unsigned int m_bitrate{50};
    unsigned int m_framerate{30};

    unsigned int m_scale{1};

    bool m_debug{false};

    bool m_colorStreamEnabled{true};

};

OpenCVStreamSender::OpenCVStreamSender(const Arguments &arguments) : Platform::WindowlessApplication{arguments} {
    Magnum::Utility::Arguments args;
    args
        .addOption("dst", "").setHelp("dst", "MAC Address to send stream to")
        .addOption("iface", "").setHelp("iface", "Network Interface")
        .addOption("mtt", "0").setHelp("mtt", "Max Transit Time")
        .addOption("priority", "-1").setHelp("priority", "Priority")
        .addBooleanOption("debug").setHelp("debug", "Show debug windows")
        .addSkippedPrefix("magnum", "engine-specific options");

    args.parse(arguments.argc, arguments.argv);

    std::string dst = args.value("dst");
    if (dst.empty()) {
        throw std::runtime_error("Missing MAC address to send stream to");
    }
    int res = sscanf(dst.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                 &m_avtp_macaddr[0], &m_avtp_macaddr[1], &m_avtp_macaddr[2],
                 &m_avtp_macaddr[3], &m_avtp_macaddr[4], &m_avtp_macaddr[5]);
    if (res != 6) {
        throw std::runtime_error("Invalid MAC address");
    }

    m_avtp_ifname = args.value("iface");
    m_avtp_max_transit_time = args.value<Magnum::Int>("mtt");
    m_avtp_priority = args.value<Magnum::Int>("priority");

    m_debug = args.isSet("debug");


    m_dev = std::make_shared<cv::VideoCapture>(0);
    if (!m_dev->isOpened()) {
        throw std::runtime_error("No OpenCV camera detected!");
    }

    Magnum::Debug{} << "Finished opening OpenCV camera device.";

}

int OpenCVStreamSender::exec() {
    Magnum::Debug{} << "Start Streaming - scale factor: " << m_scale;

    int fd, res;
    sockaddr_ll sk_addr;
    auto* pdu = (avtp_stream_pdu *)alloca(MAX_PDU_SIZE);

    fd = create_talker_socket(m_avtp_priority);
    if (fd < 0)
        return 1;

    res = setup_socket_address(fd, m_avtp_ifname.c_str(), m_avtp_macaddr, ETH_P_TSN, &sk_addr);
    if (res < 0) {
        close(fd);
        return 1;
    }

    res = init_pdu(pdu);
    if (res < 0) {
        close(fd);
        return 1;
    }


    try{
        if (m_debug) {
            cv::namedWindow("ColorImage",cv::WINDOW_NORMAL);
        }
        cv::Mat colorImage;

        for(;;) {
            *m_dev >> colorImage;
            unsigned long ts = std::chrono::system_clock::now().time_since_epoch().count();
            if (m_colorStreamEnabled) {

                cv::Mat image;
                cv::cvtColor(colorImage, image, cv::COLOR_BGR2RGBA);
                for (size_t i=0; i < m_scale; i++) {
                    cv::pyrUp(image, image, cv::Size(image.size().width*2, image.size().height*2));
                }

                size_t width = image.size().width;
                size_t height = image.size().height;

                // encode frame using nvenc
                uint64_t dataSize = width * height;
                uint64_t dataPitch = width;

                if (!m_colorStreamEncoder) {
                    m_colorStreamEncoder = NvPipe_CreateEncoder(NVPIPE_RGBA32, NVPIPE_H264, NVPIPE_LOSSLESS,
                                                                m_bitrate * 1000 * 1000, m_framerate, width, height);
                    if (!m_colorStreamEncoder) {
                        Magnum::Error{} << "Failed to create color encoder: " << NvPipe_GetError(NULL);
                        return 1;
                    }
                    m_colorBuffer.resize(dataSize * 2);
                }

                uint64_t size = NvPipe_Encode(m_colorStreamEncoder, image.data, dataPitch, m_colorBuffer.data(), m_colorBuffer.size(), width, height, false);
                if (size == 0) {
                    Magnum::Error{} << "Encode error: " << NvPipe_GetError(m_colorStreamEncoder);
                    return 1;
                }

                // parse stream and send via libavtp


                if (m_debug) {
                    Magnum::Debug{} << "send color image: " << ts << "size: " << image.size();
                    cv::imshow("ColorImage", colorImage);
                    if(cv::waitKey(5) >= 0) break;
                }
            }

        }
    } catch (std::exception &e) {
        Magnum::Debug{} << "Exception: " << e.what();
        return 1;
    }

    if (m_colorStreamEncoder) {
        NvPipe_Destroy(m_colorStreamEncoder);
    }

    m_dev->release();
    return 0;
}


int OpenCVStreamSender::init_pdu(struct avtp_stream_pdu *pdu)
{
    int res;

    res = avtp_cvf_pdu_init(pdu, AVTP_CVF_FORMAT_SUBTYPE_H264);
    if (res < 0)
        return -1;

    res = avtp_cvf_pdu_set(pdu, AVTP_CVF_FIELD_TV, 1);
    if (res < 0)
        return -1;

    res = avtp_cvf_pdu_set(pdu, AVTP_CVF_FIELD_STREAM_ID, m_stream_id);
    if (res < 0)
        return -1;

    /* Just state that all data is part of the frame (M=1) */
    res = avtp_cvf_pdu_set(pdu, AVTP_CVF_FIELD_M, 1);
    if (res < 0)
        return -1;

    /* No H.264 timestamp now */
    res = avtp_cvf_pdu_set(pdu, AVTP_CVF_FIELD_H264_TIMESTAMP, 0);
    if (res < 0)
        return -1;

    /* No H.264 timestamp means no PTV */
    res = avtp_cvf_pdu_set(pdu, AVTP_CVF_FIELD_H264_PTV, 0);
    if (res < 0)
        return -1;

    return 0;
}

ssize_t OpenCVStreamSender::fill_buffer(void)
{
    ssize_t n;

    n = read(STDIN_FILENO, m_avtp_buffer + m_avtp_buffer_level,
             sizeof(m_avtp_buffer) - m_avtp_buffer_level);
    if (n < 0) {
        perror("Could not read from standard input");
    }

    m_avtp_buffer_level += n;

    return n;
}

ssize_t OpenCVStreamSender::start_code_position(size_t offset)
{
    assert(offset < m_avtp_buffer_level);

    /* Simplified Boyer-Moore, inspired by gstreamer */
    while (offset < m_avtp_buffer_level - 2) {
        if (m_avtp_buffer[offset + 2] == 0x1) {
            if (m_avtp_buffer[offset] == 0x0 && m_avtp_buffer[offset + 1] == 0x0)
                return offset;
            offset += 3;
        } else if (m_avtp_buffer[offset + 2] == 0x0) {
            offset++;
        } else {
            offset += 3;
        }
    }

    return -1;
}

int OpenCVStreamSender::prepare_packet(struct avtp_stream_pdu *pdu, char *nal_data, size_t nal_data_len)
{
    int res;
    uint32_t avtp_time;
    auto* h264_pay = (struct avtp_cvf_h264_payload *) pdu->avtp_payload;

    res = calculate_avtp_time(&avtp_time, m_avtp_max_transit_time);
    if (res < 0) {
        Magnum::Error{} << "Failed to calculate avtp time";
        return -1;
    }

    res = avtp_cvf_pdu_set(pdu, AVTP_CVF_FIELD_TIMESTAMP, avtp_time);
    if (res < 0)
        return -1;

    res = avtp_cvf_pdu_set(pdu, AVTP_CVF_FIELD_SEQ_NUM, m_avtp_seq_num++);
    if (res < 0)
        return -1;

    /* Stream data len includes AVTP H264 header, as this is part
     * of the payload too*/
    res = avtp_cvf_pdu_set(pdu, AVTP_CVF_FIELD_STREAM_DATA_LEN, nal_data_len + AVTP_H264_HEADER_LEN);
    if (res < 0)
        return -1;

    memcpy(h264_pay->h264_data, nal_data, nal_data_len);

    return 0;
}

int OpenCVStreamSender::process_nal(struct avtp_stream_pdu *pdu, bool process_last, size_t *nal_len)
{
    int res;
    ssize_t start, end;

    *nal_len = 0;

    start = start_code_position(0);
    if (start == -1) {
        Magnum::Error{} << "Unable to find NAL start";
        return PROCESS_NONE;
    }
    /* Now, let's find where the next starts. This is where current ends */
    end = start_code_position(start + 1);
    if (end == -1) {
        if (!process_last) {
            return PROCESS_NONE;
        } else {
            end = m_avtp_buffer_level;
        }
    }

    *nal_len = end - start;
    if (*nal_len > DATA_LEN) {
        Magnum::Error{} << "NAL length bigger than expected. Expected " << DATA_LEN << " found " << *nal_len;
        return PROCESS_ERROR;
    }

    /* Sets AVTP packet headers and content - the NAL unit */
    res = prepare_packet(pdu, &m_avtp_buffer[start], *nal_len);
    if (res < 0) {
        return PROCESS_ERROR;
    }

    /* Finally, let's offset any remaining data on the buffer to the
     * beginning. Not really efficient, but keep things simple */
    memmove(m_avtp_buffer, m_avtp_buffer + end, m_avtp_buffer_level - end);
    m_avtp_buffer_level -= end;

    return PROCESS_OK;
}

MAGNUM_WINDOWLESSAPPLICATION_MAIN(OpenCVStreamSender)
