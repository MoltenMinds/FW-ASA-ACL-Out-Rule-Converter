/*******
* Author: Daniel Azar
* Date: 04/10/2020
* company: MoltenMinds
********/

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var filename = "input"
var baseName = "input.txt"
var outputFile = "-output"
var extension = ".txt"

/*
* Main method, open files, then scans them for the configuration information and generates output files.
 */
func run() {

	if len(os.Args) > 1 {
		baseName = os.Args[1]
		filename = strings.TrimPrefix(baseName, ".\\")
		extension = filepath.Ext(filename)
		filename = strings.TrimRight(filename, extension)
		if len(os.Args) > 2 {
			outputFile = os.Args[2]
		} else {
			outputFile = filename + outputFile + extension
		}
	} else {
		outputFile = filename + outputFile + extension
	}
	file, err := os.Open(baseName)
	if err != nil {
		log.Fatalf("failed opening input file: %s", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var txtlines []string
	var headerLimit int
	var footerLimit int
	var lineCounter int = 0
	var rules int = 0
	var totalRules int = 0
	var name string
	var commands string
	var newLine string
	var modifiedLines []string
	/*
		Example of expected ASA file:
		interface Port-channel1.340
			  description INSIDE_93_DCINT_MAN_RFG_MINTRANS_EXCH
			  nameif INSIDE_93_DCINT_MAN_RFG_MINTRANS_EXCH
			  security-level 30
			  ip address 10.240.115.98 255.255.255.248

		route OUTSIDE 0.0.0.0 0.0.0.0 181.209.69.246 1
		route INSIDE_DCINT-MINMOD-DNITO-MIG-511-VPN 10.1.0.0 255.255.224.0 192.168.21.5 1
	*/

	for scanner.Scan() {
		line := scanner.Text()
		lineCounter++
		txtlines = append(txtlines, line)

		var _, err = fmt.Sscanf(line, "mgmt_cli SmartMove_Create_Optimized_Policy_CiscoASA -s id.txt > /dev/null 2>&1")
		if err == nil {
			headerLimit = lineCounter
			continue
		}

		var _, err2 = fmt.Sscanf(line, "mgmt_cli logout -s id.txt")
		if err2 == nil {
			footerLimit = lineCounter
			continue
		}

		if strings.HasPrefix(line, "echo 'create layer [CSM_FW_ACL_OUT_") {
			if strings.Contains(line, "Sub-Policy") {
				continue
			}
			line = line + ">> log.txt"
			if rules != 0 {
				fmt.Println("Added " + strconv.Itoa(rules) + " rules to ACL")
				modifiedLines = append(modifiedLines, "echo -n $'\\rAdded "+strconv.Itoa(rules)+" rules' >> log.txt")
				modifiedLines = append(modifiedLines, "cmd='mgmt_cli add access-section layer \""+filename+" Network\" position top name \""+name+" ignore-warnings true -s id.txt --user-agent mgmt_cli_smartmove'")
				modifiedLines = append(modifiedLines, "run_command")
				modifiedLines = append(modifiedLines, "mgmt_cli publish -s id.txt")
			}
			modifiedLines = append(modifiedLines, line)
			totalRules += rules
			rules = 0
			continue
		}

		if strings.HasPrefix(line, "cmd='mgmt_cli add access-rule layer \"CSM_FW_ACL_OUT_") {
			if strings.Contains(line, "Sub-Policy") {
				continue
			}

			fmt.Sscanf(line, "cmd='mgmt_cli add access-rule layer \"%s\"%s", &name, &commands)
			if rules == 0 {
				fmt.Println("Working on ACL " + name)
			}
			rules++
			modifiedLines = append(modifiedLines, "echo -n $'\\rAdding rule "+strconv.Itoa(rules)+" ' >> log.txt")
			splitted := strings.Split(line, name)
			fmt.Println("Adding rule " + strconv.Itoa(rules))
			newLine = "cmd='mgmt_cli add access-rule layer \"" + filename + " Network\"" + splitted[1]
			modifiedLines = append(modifiedLines, newLine)
			modifiedLines = append(modifiedLines, "run_command")
		}
	}
	fmt.Println("Added " + strconv.Itoa(rules) + " rules to ACL")
	totalRules += rules
	fmt.Println("Added " + strconv.Itoa(totalRules) + " rules in total")
	modifiedLines = append(modifiedLines, "echo -n $'\\rAdded "+strconv.Itoa(rules)+" rules to ACL' >> log.txt")
	modifiedLines = append(modifiedLines, "cmd='mgmt_cli add access-section layer \""+filename+" Network\" position top name \""+name+" ignore-warnings true -s id.txt --user-agent mgmt_cli_smartmove'")
	modifiedLines = append(modifiedLines, "run_command")
	modifiedLines = append(modifiedLines, "mgmt_cli publish -s id.txt")
	writeFile(txtlines, modifiedLines, headerLimit, footerLimit)

}

/**
* Function: writeFile
* Writes the output file containing the VSX configuration commands.
* The bond%s in the Fprintf could be renamed for eth%s or other convenient name.
 */
func writeFile(txtlines []string, modifiedLines []string, headerLimit int, footerLimit int) {
	file, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("failed opening output file: %s", err)
	}

	defer file.Close()
	writer := bufio.NewWriter(file)
	var counter = 0
	for _, line := range txtlines {
		counter++
		if counter <= headerLimit {
			fmt.Fprintf(writer, "%s\n", line)
		} else {
			break
		}
	}
	for _, line := range modifiedLines {
		fmt.Fprintf(writer, "%s\n", line)
	}
	counter = 0
	for _, line := range txtlines {
		counter++
		if footerLimit <= counter {
			fmt.Fprintf(writer, "%s\n", line)
		}
	}
	writer.Flush()
}

func main() {
	fmt.Println(("Program started"))
	run()
	fmt.Println(("Program completed"))

}
