package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

func main(){
	reader := bufio.NewReader(os.Stdin)

	for{
		fmt.Print("gosh> ")

		input, err := reader.ReadString('\n')

		if err == io.EOF{
			fmt.Println("\nExiting Shell...")
			break

		}

		if err!=nil{
			fmt.Println("Error:", err)
			continue
		}

		input = strings.TrimSpace(input)

		fmt.Println("You typed:" ,input)
	}
}