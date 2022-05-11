/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package resourcepool

import (
	"fmt"
	"math/rand"
	"reflect"
	"sync"
	"time"

	roaring "github.com/RoaringBitmap/roaring/roaring64"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type pool struct {
	name   string
	ranges [][]uint64
	// convert a resource in its native format to uint64.
	converterToInt func(interface{}) uint64
	// convert uint64 to resources native format.
	converterFromInt func(uint64) interface{}
	// list all pool resources used by its client.
	lister      func() ([]uint64, error)
	bitmap      *roaring.Bitmap
	initialized bool
	mutex       sync.Mutex
	rand        *rand.Rand
}

// newPool returns a new resource pool.
func newPool(
	name string,
	ranges [][]uint64,
	converterToInt func(interface{}) uint64,
	converterFromInt func(uint64) interface{},
	lister func() ([]uint64, error)) *pool {
	p := &pool{
		name:             name,
		converterToInt:   converterToInt,
		converterFromInt: converterFromInt,
		lister:           lister,
		rand:             rand.New(rand.NewSource(int64(time.Now().Unix()))),
	}
	p.Update(ranges)
	return p
}

// Update the resource pool with new range.
func (p *pool) Update(ranges [][]uint64) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	// Nothing changes
	if reflect.DeepEqual(ranges, p.ranges) {
		return
	}
	bitmap := roaring.NewBitmap()
	for _, r := range ranges {
		bitmap.AddRange(r[0], r[1])
	}
	// check if resources in the new range has already been allocated,
	if p.ranges != nil {
		var allocated []uint64
		it := bitmap.Iterator()
		for it.HasNext() {
			val := it.Next()
			for _, r := range p.ranges {
				if val >= r[0] && val < r[1] && !p.bitmap.Contains(val) {
					allocated = append(allocated, val)
					break
				}
			}
		}
		for _, val := range allocated {
			bitmap.Remove(val)
		}
	}
	p.ranges = ranges
	p.bitmap = bitmap
}

// Get a resource.
func (p *pool) Get() (interface{}, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if !p.initialized {
		return nil, fmt.Errorf("resouce pool not ready: %s", p.name)
	}
	if p.bitmap.IsEmpty() {
		return nil, fmt.Errorf("resource pool exhausted: %s", p.name)
	}
	// randomly select a value.
	i, _ := p.bitmap.Select(uint64(p.rand.Int63n(int64(p.bitmap.GetCardinality()))))
	p.bitmap.Remove(i)
	resource := p.converterFromInt(i)
	log.V(1).Info("Get", "Pool", p.name, "Resource", resource)
	return resource, nil
}

// Release a resource.
func (p *pool) Release(resource interface{}) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if resource == nil {
		return nil
	}
	if !p.initialized {
		return fmt.Errorf("resouce pool not ready: %s", p.name)
	}
	log.V(1).Info("Release", "Pool", p.name, "Resource", resource)
	i := p.converterToInt(resource)
	// Ensure released resource is in range.
	for _, r := range p.ranges {
		if i >= r[0] && i < r[1] {
			if ok := p.bitmap.CheckedAdd(i); !ok {
				logf.Log.WithName("ResourcePool-"+p.name).Info("Adding resource already exists", "Resource", i)
			}
			return nil
		}
	}
	return nil
}

// Allocated returns true a resource is allocated.
func (p *pool) Allocated(resource interface{}) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if !p.initialized {
		return false
	}
	i := p.converterToInt(resource)
	// Ensure released resource is in range.
	for _, r := range p.ranges {
		if i >= r[0] && i < r[1] {
			return !p.bitmap.Contains(i)
		}
	}
	return false
}

// Available is the number of resources available in the pool.
func (p *pool) Available() (uint64, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if !p.initialized {
		return 0, fmt.Errorf("resouce pool not ready: %s", p.name)
	}
	return p.bitmap.GetCardinality(), nil
}

// allocate a specific resource.
func (p *pool) allocate(resource uint64) {
	// Ensure released resource is in range.
	for _, r := range p.ranges {
		if resource >= r[0] && resource < r[1] {
			if ok := p.bitmap.CheckedRemove(resource); !ok {
				logf.Log.WithName("ResourcePool-"+p.name).Info("Removing resource does not exist", "Resource", resource)
			}
			log.V(1).Info("Allocate", "Pool", p.name, "Resource", p.converterFromInt(resource))
			return
		}
	}
}

// Reconcile with runtime.
func (p *pool) Reconcile() error {
	items, err := p.lister()
	if err != nil {
		return err
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	for _, i := range items {
		p.allocate(i)
	}
	p.initialized = true
	return nil
}
