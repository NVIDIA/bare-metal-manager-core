/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package utils

func CombineErrors(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
