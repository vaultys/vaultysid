package idmanager

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/vmihailenco/msgpack/v5"
)

// Store defines the interface for identity storage
type Store interface {
	// Basic key-value operations
	Set(key string, value interface{})
	Get(key string) interface{}
	Delete(key string)
	List() []string

	// Substore management
	Substore(key string) Store
	ListSubstores() []string
	DeleteSubstore(key string)
	RenameSubstore(oldname, newname string)

	// Persistence
	Save() error
	Destroy() error

	// Serialization
	ToString() (string, error)
	ToJSON() (interface{}, error)
	FromString(data string) error
	FromJSON(data interface{}) error
}

// MemoryStore implements an in-memory store
type MemoryStore struct {
	mu       sync.RWMutex
	data     map[string]interface{}
	parent   *MemoryStore
	saveFunc func() error
}

// NewMemoryStore creates a new in-memory store
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		data: make(map[string]interface{}),
	}
}

// NewMemoryStoreWithSave creates a new in-memory store with a save function
func NewMemoryStoreWithSave(saveFunc func() error) *MemoryStore {
	return &MemoryStore{
		data:     make(map[string]interface{}),
		saveFunc: saveFunc,
	}
}

// Set stores a value with the given key
func (m *MemoryStore) Set(key string, value interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
}

// Get retrieves a value by key
func (m *MemoryStore) Get(key string) interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.data[key]
}

// Delete removes a key-value pair
func (m *MemoryStore) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
}

// List returns all non-substore keys
func (m *MemoryStore) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]string, 0)
	for k := range m.data {
		if len(k) == 0 || k[0] != '!' {
			keys = append(keys, k)
		}
	}
	return keys
}

// Substore returns or creates a substore
func (m *MemoryStore) Substore(key string) Store {
	m.mu.Lock()
	defer m.mu.Unlock()

	substoreKey := "!" + key
	if existing, ok := m.data[substoreKey]; ok {
		if substore, ok := existing.(*MemoryStore); ok {
			return substore
		}
		// If it exists but is not a MemoryStore, convert it
		if data, ok := existing.(map[string]interface{}); ok {
			substore := &MemoryStore{
				data:   data,
				parent: m,
			}
			m.data[substoreKey] = substore
			return substore
		}
	}

	// Create new substore
	substore := &MemoryStore{
		data:   make(map[string]interface{}),
		parent: m,
	}
	m.data[substoreKey] = substore
	return substore
}

// ListSubstores returns all substore names
func (m *MemoryStore) ListSubstores() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	substores := make([]string, 0)
	for k := range m.data {
		if len(k) > 0 && k[0] == '!' {
			substores = append(substores, k[1:])
		}
	}
	return substores
}

// DeleteSubstore removes a substore
func (m *MemoryStore) DeleteSubstore(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, "!"+key)
}

// RenameSubstore renames a substore
func (m *MemoryStore) RenameSubstore(oldname, newname string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if oldname == newname {
		return
	}

	oldKey := "!" + oldname
	newKey := "!" + newname

	// Check if new name already exists
	if _, exists := m.data[newKey]; exists {
		return
	}

	// Move the substore
	if substore, exists := m.data[oldKey]; exists {
		m.data[newKey] = substore
		delete(m.data, oldKey)
	}
}

// Save persists the store
func (m *MemoryStore) Save() error {
	if m.saveFunc != nil {
		return m.saveFunc()
	}
	// If this is a substore, save the parent
	if m.parent != nil {
		return m.parent.Save()
	}
	return nil
}

// Destroy removes the store
func (m *MemoryStore) Destroy() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = make(map[string]interface{})
	return nil
}

// ToString serializes the store to MessagePack base64 string
func (m *MemoryStore) ToString() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, err := msgpack.Marshal(m.toSerializable())
	if err != nil {
		return "", fmt.Errorf("failed to marshal store: %w", err)
	}

	return string(data), nil
}

// ToJSON returns the store data as a JSON-serializable object
func (m *MemoryStore) ToJSON() (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.toSerializable(), nil
}

// FromString deserializes the store from MessagePack
func (m *MemoryStore) FromString(data string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var decoded map[string]interface{}
	err := msgpack.Unmarshal([]byte(data), &decoded)
	if err != nil {
		return fmt.Errorf("failed to unmarshal store: %w", err)
	}

	m.data = m.fromSerializable(decoded)
	return nil
}

// FromJSON loads the store from a JSON object
func (m *MemoryStore) FromJSON(data interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if mapData, ok := data.(map[string]interface{}); ok {
		m.data = m.fromSerializable(mapData)
		return nil
	}

	return fmt.Errorf("invalid JSON data type: expected map[string]interface{}")
}

// toSerializable converts the store data to a serializable format
func (m *MemoryStore) toSerializable() map[string]interface{} {
	result := make(map[string]interface{})

	for k, v := range m.data {
		switch val := v.(type) {
		case *MemoryStore:
			result[k] = val.toSerializable()
		default:
			result[k] = v
		}
	}

	return result
}

// fromSerializable converts serialized data back to store format
func (m *MemoryStore) fromSerializable(data map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	for k, v := range data {
		if len(k) > 0 && k[0] == '!' {
			// This is a substore
			if mapData, ok := v.(map[string]interface{}); ok {
				substore := &MemoryStore{
					data:   m.fromSerializable(mapData),
					parent: m,
				}
				result[k] = substore
			} else {
				result[k] = v
			}
		} else {
			result[k] = v
		}
	}

	return result
}

// FileStore implements file-based persistent storage
type FileStore struct {
	*MemoryStore
	filepath string
	mu       sync.Mutex
}

// NewFileStore creates a new file-based store
func NewFileStore(filepath string) (*FileStore, error) {
	fs := &FileStore{
		MemoryStore: NewMemoryStore(),
		filepath:    filepath,
	}

	// Set the save function
	fs.MemoryStore.saveFunc = fs.saveToFile

	// Try to load existing data
	if err := fs.loadFromFile(); err != nil {
		// File doesn't exist yet, that's okay
		return fs, nil
	}

	return fs, nil
}

// saveToFile saves the store to a file
func (fs *FileStore) saveToFile() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := fs.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize store: %w", err)
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write to file
	// Using ioutil.WriteFile for simplicity, in production use atomic writes
	if err := writeFile(fs.filepath, jsonBytes); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// loadFromFile loads the store from a file
func (fs *FileStore) loadFromFile() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := readFile(fs.filepath)
	if err != nil {
		return err
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return fs.FromJSON(jsonData)
}

// Helper functions for file operations
func writeFile(filepath string, data []byte) error {
	// Write to a temporary file first for atomicity
	tmpFile := filepath + ".tmp"

	file, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	_, err = file.Write(data)
	if err != nil {
		file.Close()
		os.Remove(tmpFile)
		return fmt.Errorf("failed to write data: %w", err)
	}

	if err := file.Close(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to close file: %w", err)
	}

	// Atomically rename temp file to target file
	if err := os.Rename(tmpFile, filepath); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

func readFile(filepath string) ([]byte, error) {
	file, err := os.Open(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return data, nil
}
