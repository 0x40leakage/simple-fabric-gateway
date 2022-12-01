package util

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/factory"
	"github.com/pkg/errors"
	"path/filepath"
	"strings"
)

// makeFileNamesAbsolute makes all relative file names associated with CSP absolute,
// relative to 'homeDir'.
func MakeFileNamesAbsolute(opts *factory.FactoryOpts, homeDir string) error {
	var err error
	switch strings.ToUpper(opts.ProviderName) {
	case "SW":
		if opts != nil && opts.SwOpts != nil && opts.SwOpts.FileKeystore != nil {
			fks := opts.SwOpts.FileKeystore
			fks.KeyStorePath, err = MakeFileAbs(fks.KeyStorePath, homeDir)
		}
	case "GM":
		if opts != nil && opts.GmOpts != nil && opts.GmOpts.FileKeystore != nil {
			fks := opts.GmOpts.FileKeystore
			fks.KeyStorePath, err = MakeFileAbs(fks.KeyStorePath, homeDir)
		}
	}
	return err
}

// MakeFileAbs makes 'file' absolute relative to 'dir' if not already absolute
func MakeFileAbs(file, dir string) (string, error) {
	if file == "" {
		return "", nil
	}
	if filepath.IsAbs(file) {
		return file, nil
	}
	path, err := filepath.Abs(filepath.Join(dir, file))
	if err != nil {
		return "", errors.Wrapf(err, "Failed making '%s' absolute based on '%s'", file, dir)
	}
	return path, nil
}
