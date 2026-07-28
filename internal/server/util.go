package server

import (
	"os"
	"sync"
)

func PerformConcurrently(fns ...func()) {
	var wg sync.WaitGroup

	for _, fn := range fns {
		wg.Go(fn)
	}

	wg.Wait()
}

// writeFileAtomic writes data to path via a same-directory temp file, syncing
// and renaming into place, so readers never observe a partial write.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmpPath := path + ".tmp"

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	// O_CREATE only applies perm to a file it creates, and umask masks it even
	// then. Set it explicitly, so a temp file left behind by an earlier run
	// cannot keep looser permissions than the caller asked for.
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}

	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}
