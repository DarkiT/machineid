package main

import (
	"fmt"
	"time"

	"github.com/darkit/machineid"
	"github.com/darkit/machineid/cert"
)

func main() {
	fmt.Println("Hello, World!")

	auth, err := cert.New()

	caInfo := cert.CAInfo{
		CommonName:   "ZStudio Software CA",
		Organization: "子说工作室",
		Country:      "CN",
		Province:     "Guangdong",
		Locality:     "Guangzhou",
		ValidDays:    36500, // 100年有效期
		KeySize:      4096,
	}

	err = auth.GenerateCA(caInfo)
	if err != nil {
		fmt.Println("GenerateCA error:", err)
	}
	err = auth.SaveCA(".")
	if err != nil {
		fmt.Println("SaveCA error:", err)
		return
	}

	id, err := machineid.ProtectedID("MachineID")
	if err != nil {
		fmt.Println("ProtectedID error:", err)
		return
	}
	clientInfo := cert.ClientInfo{
		MachineID:          id,
		ExpiryDate:         time.Now().AddDate(1, 0, 0),
		CompanyName:        "XX广州分公司",
		Department:         "技术部",
		Version:            "1.0.0",
		ValidityPeriodDays: 365,
	}

	certificate, err := auth.IssueClientCert(clientInfo)
	if err != nil {
		fmt.Println("IssueClientCert error:", err)
		return
	}

	err = auth.SaveClientCert(certificate, ".")
	if err != nil {
		fmt.Println("SaveClientCert error:", err)
		return
	}
	fmt.Println("SaveClientCert success")

	err = auth.ValidateCert(certificate.CertPEM, certificate.MachineID)
	if err != nil {
		fmt.Println("ValidateCert error:", err)
		return
	}
	fmt.Println("ValidateCert success")
}
