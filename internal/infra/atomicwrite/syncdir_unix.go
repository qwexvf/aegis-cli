//go:build unix

package atomicwrite

import "os"

// syncDir fsyncs the directory entry. On POSIX, this is what makes a
// rename durable across crashes: rename returns "success" once the
// kernel has buffered it, but the directory inode update isn't
// guaranteed on disk until the directory itself is fsynced.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
