# Wireshark Dissector for Encapsulated Opulent Voice

An Opulent Voice station can be divided into a modem and a host that handles the protocol from audio down to the bytes in the 40ms Opulent Voice frames. Sometimes these two components are connected by Ethernet (or a more extensive network) and the bytes composing each frame are encapsulated in a UDP packet. This dissector helps Wireshark make sense of these encapsulated frames.

Each frame consists of two major parts: a frame header, and a payload. The frame header is a fixed format of 12 bytes. The payload contains bytes from a COBS-encoded stream of IP packets. In the common case where the payload contains Opus voice packets, and the voice packets are synchronized with the frame boundaries, the payload in a frame corresponds exactly to a single COBS-encoded IP/UDP/RTP/Opus packet. For other payload types, this is not true (except by coincidence). A frame's payload may consist of, in order, the last part of one packet, one or more whole short packets, and the first part of another packet. Any of these components may be omitted. The frame boundaries are delimited by a zero byte, according to the COBS protocol.

Because of the stream nature of the COBS-encoded packets, a complete dissector for this protocol will sometimes have to reassemble payload packets from the contents of multiple frames.
