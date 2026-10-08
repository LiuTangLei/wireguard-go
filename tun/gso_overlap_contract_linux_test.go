package tun

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func overlapTCPRecord(version, payloadSize, count int, flags byte) ([]byte, GSOOptions) {
	ipLen := 20
	gso := GSOTCPv4
	if version == 6 {
		ipLen = 40
		gso = GSOTCPv6
	}
	packet := make([]byte, ipLen+20+payloadSize*count)
	if version == 4 {
		packet[0] = 0x45
		packet[8] = 64
		packet[9] = 6
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
		binary.BigEndian.PutUint16(packet[4:], 0xfff0)
		copy(packet[12:20], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	} else {
		packet[0] = 0x60
		packet[6] = 6
		packet[7] = 64
		binary.BigEndian.PutUint16(packet[4:], uint16(len(packet)-40))
		copy(packet[8:12], []byte{0x20, 1, 0x0d, 0xb8})
		packet[23] = 1
		copy(packet[24:28], []byte{0x20, 1, 0x0d, 0xb8})
		packet[39] = 2
	}
	binary.BigEndian.PutUint16(packet[ipLen:], 1234)
	binary.BigEndian.PutUint16(packet[ipLen+2:], 443)
	binary.BigEndian.PutUint32(packet[ipLen+4:], 0xfffff000)
	packet[ipLen+12] = 0x50
	packet[ipLen+13] = flags
	for i := ipLen + 20; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	return packet, GSOOptions{GSOType: gso, HdrLen: uint16(ipLen + 20), GSOSize: uint16(payloadSize), CsumStart: uint16(ipLen), CsumOffset: 16, NeedsCsum: true}
}

func overlapOutputs(count, capacity int) ([][]byte, []int) {
	bufs := make([][]byte, count)
	for i := range bufs {
		bufs[i] = make([]byte, 16+capacity)
	}
	return bufs, make([]int, count)
}

func validateDisjointTCP(t *testing.T, bufs [][]byte, sizes []int, version, payloadSize, count int, flags byte) {
	t.Helper()
	ipLen := 20
	srcOffset := 12
	addrLen := 4
	if version == 6 {
		ipLen = 40
		srcOffset = 8
		addrLen = 16
	}
	for i := 0; i < count; i++ {
		packet := bufs[i][16 : 16+sizes[i]]
		wantFlags := flags
		if i != count-1 {
			wantFlags &^= tcpFlagFIN | tcpFlagPSH
		}
		if sizes[i] != ipLen+20+payloadSize || packet[ipLen+13] != wantFlags || binary.BigEndian.Uint32(packet[ipLen+4:]) != uint32(0xfffff000+uint64(payloadSize*i)) {
			t.Fatalf("bad disjoint segment%d size%d flags%x", i, sizes[i], packet[ipLen+13])
		}
		if version == 4 && (Checksum(packet[:20], 0) != 0xffff || binary.BigEndian.Uint16(packet[4:]) != uint16(0xfff0+i)) {
			t.Fatal("disjoint IPv4 checksum/ID")
		}
		pseudo := PseudoHeaderChecksum(ipProtoTCP, packet[srcOffset:srcOffset+addrLen], packet[srcOffset+addrLen:srcOffset+addrLen*2], uint16(len(packet)-ipLen))
		if Checksum(packet[ipLen:], pseudo) != 0xffff {
			t.Fatal("disjoint TCP checksum")
		}
	}
}

func TestGSOExactStartOverlapTCPFlagsAndChecksum(t *testing.T) {
	for _, version := range []int{4, 6} {
		for _, payloadSize := range []int{64, 1400} {
			for _, count := range []int{1, 2, 4, 32} {
				for _, flags := range []byte{0x10, 0x11, 0x18, 0x19} {
					t.Run(fmt.Sprintf("v%d-payload%d-N%d-flags%x", version, payloadSize, count, flags), func(t *testing.T) {
						packet, opts := overlapTCPRecord(version, payloadSize, count, flags)
						want, ws := overlapOutputs(count, len(packet))
						n, err := splitOverlapFixture(bytes.Clone(packet), opts, want, ws, false)
						if err != nil || n != count {
							t.Fatalf("disjoint %d %v", n, err)
						}
						validateDisjointTCP(t, want, ws, version, payloadSize, count, flags)
						got, gs := overlapOutputs(count, len(packet))
						copy(got[0][16:], packet)
						in := got[0][16 : 16+len(packet)]
						if &in[0] != &got[0][16] {
							t.Fatal("fixture did not actually overlap")
						}
						n, err = splitOverlapFixture(in, opts, got, gs, true)
						if err != nil || n != count {
							t.Fatalf("overlap %d %v", n, err)
						}
						ipLen := 20
						if version == 6 {
							ipLen = 40
						}
						for i := 0; i < count; i++ {
							if gs[i] != ws[i] || !bytes.Equal(got[i][16:16+gs[i]], want[i][16:16+ws[i]]) {
								t.Errorf("documented overlap differs segment%d/%d TCPflags got=%x want=%x", i, count, got[i][16+ipLen+13], want[i][16+ipLen+13])
							}
						}
					})
				}
			}
		}
	}
}

func splitOverlapFixture(in []byte, opts GSOOptions, bufs [][]byte, sizes []int, overlap bool) (int, error) {
	slab := make([]byte, 2*(1<<16-1))
	packets := make([]ReadPacket, len(bufs))
	if overlap {
		copy(slab[ReadPacketSpacing:], in)
		in = slab[ReadPacketSpacing : ReadPacketSpacing+len(in)]
	}
	n, err := GSOSplit(in, opts, slab, packets, ReadPacketSpacing)
	for i, p := range packets[:n] {
		sizes[i] = copy(bufs[i][16:], slab[p.Offset:p.Offset+p.Size])
	}
	return n, err
}
