package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)
//main function
func main() {
	fmt.Println("1. Test for XSS vulnerability")
	fmt.Println("2. Test for SQL injection vulnerability")
	fmt.Print("Select an option: ")

	reader := bufio.NewReader(os.Stdin)
	option, _ := reader.ReadString('\n')
	option = strings.TrimSpace(option)

	//loop for vulns test
	switch option {
	case "1":
		testXSS()
	case "2":
		testSQLInjection()
	default:
		fmt.Println("Invalid option")
	}
}

func testXSS() {
	fmt.Println("\nXSS Testing Module")
	fmt.Print("Enter URL to test: ")
	reader := bufio.NewReader(os.Stdin)
	url, _ := reader.ReadString('\n')
	url = strings.TrimSpace(url)

	// Simple XSS test vector
	testVector := "<script>alert('XSS')</script>"

	// Test reflected XSS in URL parameters
	if strings.Contains(url, "=") {
		parts := strings.Split(url, "=")
		param := parts[len(parts)-1]
		testURL := strings.Replace(url, param, testVector, 1)

		fmt.Printf("Testing URL: %s\n", testURL)
		resp, err := http.Get(testURL)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()

		// Check if our test vector appears in the response
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), testVector) {
				fmt.Println("Possible XSS vulnerability detected!")
				return
			}
		}
		fmt.Println("No reflected XSS detected in URL parameters")
	} else {
		fmt.Println("No parameters found in URL to test")
	}
}

//declare the function
func testSQLInjection() {
	fmt.Println("\nSQL Injection Testing Module")
	fmt.Print("Enter database connection string (e.g., user:pass@tcp(127.0.0.1:3306)/dbname): ")
	reader := bufio.NewReader(os.Stdin)
	connStr, _ := reader.ReadString('\n')
	connStr = strings.TrimSpace(connStr)

	fmt.Print("Enter test query (e.g., SELECT * FROM users WHERE id = '1'): ")
	query, _ := reader.ReadString('\n')
	query = strings.TrimSpace(query)

	// Test for SQL injection vulnerability
	testVector := "1' OR '1'='1"
	if strings.Contains(query, "'1'") {
		injectedQuery := strings.Replace(query, "'1'", "'"+testVector+"'", 1)
		fmt.Printf("Testing query: %s\n", injectedQuery)

		db, err := sql.Open("mysql", connStr)
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		//do a err catch on db query
		rows, err := db.Query(injectedQuery)
		if err != nil {
			fmt.Printf("Error: %v - Possible SQL injection protection in place\n", err)
			return
		}
		defer rows.Close()

		// If we get more results than expected, it might be vulnerable
		cols, _ := rows.Columns()
		fmt.Printf("Query executed successfully. Returned columns: %v\n", cols)
		fmt.Println("This might indicate a SQL injection vulnerability")
	} else {
		fmt.Println("No obvious injection point found in query")
	}
}
