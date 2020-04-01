package cameradar

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

var fs fileSystem = osFS{}

type fileSystem interface {
	Open(name string) (file, error)
	Stat(name string) (os.FileInfo, error)
}

type file interface {
	io.Closer
	io.Reader
	io.ReaderAt
	io.Seeker
	Stat() (os.FileInfo, error)
}

// osFS implements fileSystem using the local disk.
type osFS struct{}

func (osFS) Open(name string) (file, error)        { return os.Open(name) }
func (osFS) Stat(name string) (os.FileInfo, error) { return os.Stat(name) }

// LoadRoutes opens a dictionary file and returns its contents as a Routes structure.
func (s *Scanner) LoadRoutes() error {
	s.term.Debugf("Loading routes dictionary from path %q\n", s.routeDictionaryPath)

	file, err := os.Open(s.routeDictionaryPath)
	if err != nil {
		return fmt.Errorf("unable to open dictionary: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s.routes = append(s.routes, scanner.Text())
	}

	s.term.Debugf("Loaded %d routes\n", len(s.routes))

	return scanner.Err()
}

// ParseRoutesFromString parses a dictionary string and returns its contents as a Routes structure.
func ParseRoutesFromString(content string) Routes {
	return strings.Split(content, "\n")
}

// LoadTargets parses the file containing hosts to targets, if the targets are
// just set to a file name.
func (s *Scanner) LoadTargets() error {
	if len(s.targets) != 1 {
		return nil
	}

	path := s.targets[0]

	_, err := fs.Stat(path)
	if err != nil {
		return nil
	}

	file, err := fs.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open targets file %q: %v", path, err)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return fmt.Errorf("unable to read targets file %q: %v", path, err)
	}

	s.targets = strings.Split(string(bytes), "\n")

	s.term.Debugf("Successfylly parsed targets file with %d entries", len(s.targets))

	return nil
}
