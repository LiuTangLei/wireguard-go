package device

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/crypto/chacha20poly1305"
	"testing"
)

func TestAWGSharedSlabExpansionPreservesAdjacentPackets(t *testing.T) {
	for _, padding := range []uint32{0, 36, 600, 4096} {
		d := newAWGUnitTestDevice(t)
		awg := defaultAWGConfig.clone()
		awg.paddings.transport = padding
		cipher, err := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
		if err != nil {
			t.Fatal(err)
		}
		slab := d.getPacketBuf()
		c := d.GetOutboundElementsContainer()
		c.awg = awg
		originals := make([][]byte, 3)
		for i := range originals {
			offset := 64 + i*128
			originals[i] = bytes.Repeat([]byte{byte(i + 1)}, 32)
			copy(slab.slab[offset:], originals[i])
			slab.incRef()
			e := d.GetOutboundElement()
			e.buffer, e.packet, e.plaintextOffset = slab, slab.slab[offset:offset+32:offset+32+outboundPlaintextTailroom], offset
			e.padding, e.nonce = padding, uint64(i)
			e.keypair, e.peer = &Keypair{send: cipher}, &Peer{device: d}
			c.elems = append(c.elems, e)
		}
		c.filling.Add(1)
		d.queue.encryption.c <- c
		c.filling.Wait()
		for i, e := range c.elems {
			start := MessageEncapsulatingTransportSize + int(padding)
			if len(e.packet) < start+MessageTransportSize {
				t.Fatalf("padding %d: missing packet", padding)
			}
			var nonce [chacha20poly1305.NonceSize]byte
			binary.LittleEndian.PutUint64(nonce[4:], uint64(i))
			plain, err := cipher.Open(nil, nonce[:], e.packet[start+MessageTransportHeaderSize:], nil)
			if err != nil || !bytes.Equal(plain[:min(len(plain), 32)], originals[i]) {
				t.Fatalf("padding %d packet %d: corruption: %v", padding, i, err)
			}
			d.PutOutboundElement(e)
		}
		slab.decRef()
		d.PutOutboundElementsContainer(c)
	}
}
