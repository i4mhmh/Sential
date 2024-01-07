package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
	"time"
)

func GetName() string {
	devices, _ := pcap.FindAllDevs()
	return devices[0].Name
}

var (
	device      string = GetName()
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      pcap.Handle
	packetCount int = 0
)

func main() {
	f, _ := os.Create("data.pcap")
	w := pcapgo.NewWriter(f)
	err := w.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)
	if err != nil {
		return
	}
	defer f.Close()

	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		packetCount++
	}
}
