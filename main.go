package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"log"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("can not find devices", err)
	}
	for _, d := range devices {
		fmt.Println("\n Name: ", d.Name)
		fmt.Println("Description: ", d.Description)
		fmt.Println("Devices addresses: ", d.Addresses)
		for _, address := range d.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
}
