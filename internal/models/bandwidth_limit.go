package models

type BandwidthLimit struct {
	ID           int64  `json:"id"`
	DeviceMAC    string `json:"device_mac"`
	DownloadKbps int    `json:"download_kbps"`
	UploadKbps   int    `json:"upload_kbps"`
	Enabled      bool   `json:"enabled"`
}
