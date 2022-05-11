/*
Copyright 2021 NVIDIA CORPORATION & AFFILIATES.
*/

package utils

import (
	"io"
)

type Kubectl struct {
	Path string
	Opts []string
}

func (k *Kubectl) Run(in io.Reader, out io.Writer, _args ...string) error {
	args := append(k.Opts, _args...)
	return Execute(k.Path, in, out, args...)
}
