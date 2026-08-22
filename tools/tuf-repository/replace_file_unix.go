//go:build !windows

package main

import "os"

func replaceFile(from, to string) error {
	//paperboat:allow-source-policy atomic-replacement owner=tuf-repository reason=same-directory-fsynced-staging
	return os.Rename(from, to)
}
