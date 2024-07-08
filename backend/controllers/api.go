package controllers

import (
	"bytes"
	"context"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"scanner/database" // Import the database package

	"github.com/gin-gonic/gin"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type Targets struct {
	Targets []string `json:"targets"`
}

func init() {
	database.InitDB("./targets.db") // Initialize the database connection
}

func GetDefault(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Hello World!",
	})
}

func ParseDomains(c *gin.Context) {
	if c.Request.Method != "POST" {
		c.JSON(http.StatusMethodNotAllowed, gin.H{
			"message": "Method not allowed",
		})
		return
	}

	domainRegex := `^(\*\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`
	ipRegex := `^(\d{1,3}\.){3}\d{1,3}$`
	subnetRegex := `^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$`

	domainPattern := regexp.MustCompile(domainRegex)
	ipPattern := regexp.MustCompile(ipRegex)
	subnetPattern := regexp.MustCompile(subnetRegex)

	var targets Targets

	if err := c.BindJSON(&targets); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid JSON",
		})
		return
	}

	for _, target := range targets.Targets {
		if domainPattern.MatchString(target) {
			if strings.HasPrefix(target, "*.") {
				domains, err := runSubfinder(target[2:])
				if err != nil {
					log.Printf("error running subfinder for %s: %v", target, err)
					continue
				}
				database.StoreDomains(domains)
			} else {
				database.StoreDomain(target)
			}
		} else if ipPattern.MatchString(target) {
			if isValidIP(target) {
				database.StoreIP(target)
			}
		} else if subnetPattern.MatchString(target) {
			ip, mask := splitSubnet(target)
			if isValidIP(ip) && isValidMask(mask) {
				ips, err := listIps(target)
				if err != nil {
					log.Printf("error listing IPs for subnet %s: %v", target, err)
					continue
				}
				database.StoreIPs(ips)
			}
		}
	}

	// Retrieve all stored targets from the database
	storedTargets, err := database.GetAllTargets()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to retrieve targets from database",
		})
		return
	}

	c.JSON(http.StatusOK, storedTargets)
}

func isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}
	return true
}

func isValidMask(mask string) bool {
	num, err := strconv.Atoi(mask)
	if err != nil || num < 0 || num > 32 {
		return false
	}
	return true
}

func splitSubnet(subnet string) (string, string) {
	parts := strings.Split(subnet, "/")
	return parts[0], parts[1]
}

func runSubfinder(domain string) ([]string, error) {
	subfinderOpts := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
	}

	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		return nil, err
	}

	output := &bytes.Buffer{}
	if err = subfinder.EnumerateSingleDomainWithCtx(context.Background(), domain, []io.Writer{output}); err != nil {
		return nil, err
	}

	return strings.Split(output.String(), "\n"), nil
}

func listIps(subnet string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, err
	}
	network := ip.Mask(ipnet.Mask)
	broadcast := make(net.IP, len(network))
	for i := range network {
		broadcast[i] = network[i] | ^ipnet.Mask[i]
	}

	networkBigInt := big.NewInt(0).SetBytes(network)
	broadcastBigInt := big.NewInt(0).SetBytes(broadcast)

	var ips []string
	for networkBigInt.Cmp(broadcastBigInt) <= 0 {
		ips = append(ips, net.IP(networkBigInt.Bytes()).String())
		networkBigInt.Add(networkBigInt, big.NewInt(1))
	}

	return ips, nil
}
