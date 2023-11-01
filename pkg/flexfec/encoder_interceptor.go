// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flexfec

import (
	"fmt"

	"github.com/pion/interceptor"
	"github.com/pion/rtp"
)

type FecInterceptor struct {
	interceptor.NoOp
	flexFecEncoder     FlexEncoder
	packetBuffer       []rtp.Packet
	minNumMediaPackets uint32
}

type FECEncoderOption func(d *FecInterceptor) error

type FECInterceptorFactory struct {
	opts []FECEncoderOption
}

func streamSupportFec(info *interceptor.StreamInfo) bool {
	fmt.Println("[THOMAS] streamSupportFec()?")
	fmt.Println(info.SDPFmtpLine)
	fmt.Println(info)

	// Need to check stream info to see if we should be sending FEC packets
	if info.MimeType == "video/VP8" {
		return true
	}
	return false
}

func NewFECInterceptor(opts ...FECEncoderOption) (*FECInterceptorFactory, error) {
	return &FECInterceptorFactory{}, nil
}

func (r *FECInterceptorFactory) NewInterceptor(_ string) (interceptor.Interceptor, error) {
	// Hardcoded for now:
	// payload type -> 117
	// SSRC -> 2055559999
	// Min num media packets to encode FEC -> 5
	// Min num fec packets -> 1

	interceptor := &FecInterceptor{
		packetBuffer:       make([]rtp.Packet, 0),
		minNumMediaPackets: 5,
	}
	return interceptor, nil
}

// BindLocalStream lets you modify any outgoing RTP packets. It is called once for per LocalStream. The returned method
// will be called once per rtp packet.
func (r *FecInterceptor) BindLocalStream(info *interceptor.StreamInfo, writer interceptor.RTPWriter) interceptor.RTPWriter {
	if !streamSupportFec(info) {
		return writer
	}

	// Chromium supports version flexfec-03 of existing draft, this is the one we will configure by default
	// although we should support configuring the latest (flexfec-20) as well.
	r.flexFecEncoder = NewFlexEncoder03(117, 2055559999)

	return interceptor.RTPWriterFunc(func(header *rtp.Header, payload []byte, attributes interceptor.Attributes) (int, error) {
		r.packetBuffer = append(r.packetBuffer, rtp.Packet{
			Header:  *header,
			Payload: payload,
		})

		// Send the media RTP packet
		result, error := writer.Write(header, payload, attributes)

		// Send the FEC packets
		var fecPackets []rtp.Packet
		if len(r.packetBuffer) == int(r.minNumMediaPackets) {
			fecPackets = r.flexFecEncoder.EncodeFec(r.packetBuffer, 2)

			for _, fecPacket := range fecPackets {

				fmt.Println("[FEC] writing packet with header SSRC = ", fecPacket.Header.SSRC)
				writer.Write(&fecPacket.Header, fecPacket.Payload, attributes)
			}
			// Reset the packet buffer now that we've sent the corresponding FEC packets.
			r.packetBuffer = nil
		}

		return result, error
	})
}
