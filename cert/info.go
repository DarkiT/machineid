package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"sync"
	"time"
)

// Authorizer 授权管理器
type Authorizer struct {
	mu             sync.RWMutex      // 读写互斥锁，用于并发安全
	caCert         *x509.Certificate // CA证书对象
	caKey          *rsa.PrivateKey   // CA私钥对象
	caCertPEM      []byte            // PEM格式的CA证书数据
	caKeyPEM       []byte            // PEM格式的CA私钥数据
	initialized    bool              // 初始化状态标志
	revokeManager  *RevokeManager    // 证书吊销管理器
	currentVersion string            // 当前程序版本号，用于版本控制和更新管理
	enterpriseID   int               // 企业标识符
}

// ClientInfo 客户端信息
type ClientInfo struct {
	// 基本信息
	MachineID  string    // 机器码可以是单个或多个（用逗号分隔）
	ExpiryDate time.Time // 授权结束日期

	// 公司信息
	CompanyName   string // 公司名称
	Department    string // 部门名称
	ContactPerson string // 联系人
	ContactPhone  string // 联系电话
	ContactEmail  string // 联系邮箱

	// 地址信息
	Country  string // 国家
	Province string // 省份
	City     string // 城市
	Address  string // 详细地址

	// 版本信息
	Version            string // 当前程序版本
	ValidityPeriodDays int    // 证书有效天数
}

// Certificate 证书信息
type Certificate struct {
	CertPEM   []byte    // PEM格式的证书
	KeyPEM    []byte    // PEM格式的私钥
	MachineID string    // 机器ID
	NotBefore time.Time // 生效时间
	NotAfter  time.Time // 过期时间
}

// CAInfo CA证书的配置信息
type CAInfo struct {
	// 基本信息
	CommonName string // CA名称，如 "My Software Root CA"
	ValidDays  int    // 有效期天数

	// 组织信息
	Organization string // 组织名称，如公司名称
	Country      string // 国家代码，如 "CN"
	Province     string // 省份
	Locality     string // 城市

	// 证书参数
	KeySize   int      // RSA密钥大小，默认4096
	KeyUsages []string // 密钥用途，可选
}

// VersionInfo 定义证书的版本信息
type VersionInfo struct {
	MinRequiredVersion string // 最低需要的客户端版本
	CertVersion        string // 证书格式版本
	MaxValidDays       int    // 最大有效天数
}
