package GPortScan

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

type Identification_Packet struct {
	Desc   string
	Packet []byte
}

var st_Identification_Packet [100]Identification_Packet

func init() {
	for i, packet := range IdentificationProtocol {
		szinfo := strings.Split(packet, "#")
		data, err := hex.DecodeString(szinfo[1])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		st_Identification_Packet[i].Desc = szinfo[0]
		st_Identification_Packet[i].Packet = data
	}
}
