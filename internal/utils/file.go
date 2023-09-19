package utils

import "os"

func ExtractFile(data []byte, destPath string) {
	f, err := os.Create(destPath)
	if err != nil {
		panic(err)
	}

	_, err = f.Write(data)
	if err != nil {
		panic(err)
	}

	f.Close()
}
