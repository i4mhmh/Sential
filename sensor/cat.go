package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
	"strconv"
	"time"
)

func GetName() string {
	devices, _ := pcap.FindAllDevs()
	return devices[3].Name
}

var (
	device      string = "en0"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      pcap.Handle
	packetCount int = 0
)

func main() {

	dayNum := map[time.Weekday]int{
		time.Sunday:    7,
		time.Monday:    1,
		time.Tuesday:   2,
		time.Wednesday: 3,
		time.Thursday:  4,
		time.Friday:    5,
		time.Saturday:  6,
	}

	now := time.Now()
	dayOfWeek := now.Weekday()
	days := strconv.Itoa(dayNum[dayOfWeek])

	f, _ := os.Create("./data_" + days + ".pcap")
	w := pcapgo.NewWriter(f)
	err := w.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)
	if err != nil {
		return
	}
	defer f.Close()

	fmt.Println(device)
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		now := time.Now()
		dayOfWeek := now.Weekday()
		now_days := strconv.Itoa(dayNum[dayOfWeek])
		if now_days != days {
			main()
		}
	}
}
