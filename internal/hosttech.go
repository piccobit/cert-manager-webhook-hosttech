package internal

type Zone struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	TTL         int    `json:"ttl"`
	Nameserver  string `json:"nameserver"`
	DNSSEC      bool   `json:"dnssec"`
	DNSSECEmail string `json:"dnssec_email"`
}

type ZonesResponse struct {
	Data []Zone `json:"data"`
}

type ZoneResponse struct {
	Data struct {
		ID      int    `json:"id"`
		Type    string `json:"type"`
		Name    string `json:"name"`
		IPv4    string `json:"ipv4"`
		TTL     int    `json:"ttl"`
		Comment string `json:"comment"`
	} `json:"data"`
}

type TXTRecordRequest struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Text    string `json:"text"`
	TTL     int    `json:"ttl"`
	Comment string `json:"comment"`
}

type TXTRecordResponse struct {
	ID int `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Text    string `json:"text"`
	TTL     int    `json:"ttl"`
	Comment string `json:"comment"`
}

type TXTRecordsResponse struct {
	Data []TXTRecordResponse
}