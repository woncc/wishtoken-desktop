package router

import "io"

type leasedBody struct {
	io.ReadCloser
	release func()
}

func (b *leasedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.release()
	}
	return n, err
}

func (b *leasedBody) Close() error {
	defer b.release()
	return b.ReadCloser.Close()
}
