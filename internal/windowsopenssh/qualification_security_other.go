//go:build !windows

package windowsopenssh

import (
	"errors"
	"os"
)

type qualificationSecurity string

func validateQualificationFile(path string, allowMissing bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrQualificationEnrollment
	}
	return nil
}

func captureQualificationSecurity(string, bool) (qualificationSecurity, error) {
	return "", nil
}

func restoreQualificationSecurity(string, qualificationSecurity) error {
	return nil
}
