package zgrab2

// ModuleSet is a container holding named scan modules. It is a wrapper around a
// map.
type ModuleSet map[string]ScanModule

// AddModule adds m to the ModuleSet, accessible via the given name. If the name
// is already in the ModuleSet, it is overwritten.
func (s ModuleSet) AddModule(name string, m ScanModule) {
	s[name] = m
}

// RemoveModule removes the module at the specified name. If the name is not in
// the module set, nothing happens.
func (s ModuleSet) RemoveModule(name string) {
	delete(s, name)
}

// CopyInto copies the modules in s to destination. The sets will be unique, but
// the underlying ScanModule instances will be the same.
func (s ModuleSet) CopyInto(destination ModuleSet) {
	for name, m := range s {
		destination[name] = m
	}
}

// NewModuleSet returns an empty ModuleSet.
func NewModuleSet() ModuleSet {
	return make(ModuleSet)
}
