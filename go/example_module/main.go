package main

import (
	"example_module/test_package"
	"fmt"
)

func main() {
	result := test_package.Add(3, 4)
	fmt.Println("Result:", result)
}
