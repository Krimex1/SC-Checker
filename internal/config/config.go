package config

const (
	Version = "2.0.0"

	DefaultTimeout  = 5
	FastTimeout     = 2
	DirWorkers      = 24
	PortWorkers     = 64
	PathWorkers     = 12

	MaxConcurrentRequests = 24
	DefaultRequestTimeout = 15

	UserAgent = "Mozilla/5.0 (compatible; SC-Checker-Go/1.0)"

	BodyPreviewShort  = 2000
	BodyPreviewMedium = 3000
	BodyPreviewLong   = 5000

	SSLPort         = 443
	ConnectTimeout  = 8
	AltPortTimeout  = 3
	BannerTimeout   = 2
	SubdomainWorkers = 20
)

var AltHTTPPorts = []int{80, 8080, 8443, 8000, 5000, 3000, 9090, 443}

var CommonPorts = []int{
	21, 22, 25, 53, 80, 110, 135, 139, 143, 443, 445,
	465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432,
	5900, 6379, 8000, 8080, 8443, 8888, 9000, 9090,
	9200, 11211, 27017, 50000, 50070,
}

var PortServices = map[int]string{
	21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
	110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
	443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "Submission",
	993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
	6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
	8443: "HTTPS-Alt", 8888: "HTTP-Proxy2", 9000: "PHP-FPM",
	9090: "Prometheus", 9200: "Elasticsearch", 11211: "Memcached",
	27017: "MongoDB", 50000: "SAP", 50070: "HDFS",
}

var SecurityHeaders = []string{
	"content-security-policy", "x-frame-options", "x-content-type-options",
	"referrer-policy", "permissions-policy", "strict-transport-security",
}

var Soft404Signatures = []string{
	"page not found", "404 not found", "sorry, we couldn't find",
	"the page you requested was not found", "error 404",
	"file not found", "requested url was not found",
	"this page doesn't exist", "no results found",
	"the resource you are looking for",
}

var TechFingerprint = map[string]string{
	"server": "Server", "x-powered-by": "X-Powered-By", "x-generator": "Generator",
	"cf-ray": "Cloudflare", "x-amz-cf-id": "CloudFront", "via": "Via",
}
