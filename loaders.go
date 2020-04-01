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

// LoadStreams opens a dictionary file and returns its contents as a Streams structure.
func (s *Scanner) LoadStreams() error {
	s.term.Debugf("Loading streams dictionary from path %q\n", s.streamDictionaryPath)

	file, err := os.Open(s.streamDictionaryPath)
	if err != nil {
		return fmt.Errorf("unable to open dictionary: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s.streams = append(s.streams, scanner.Text())
	}

	s.term.Debugf("Loaded %d streams\n", len(s.streams))

	return scanner.Err()
}

// ParseStreamsFromString parses a dictionary string and returns its contents as a Streams structure.
func ParseStreamsFromString(content string) Streams {
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
