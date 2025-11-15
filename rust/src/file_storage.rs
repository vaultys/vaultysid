use crate::error::{Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rmp_serde::{decode, encode};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Trait defining a storage interface
pub trait Store: Send + Sync {
    /// Get a substore with the given key
    fn substore(&self, key: &str) -> Box<dyn Store>;

    /// Rename a substore
    fn rename_substore(&self, oldname: &str, newname: &str) -> Result<()>;

    /// List all substores
    fn list_substores(&self) -> Vec<String>;

    /// Delete a substore
    fn delete_substore(&self, key: &str) -> Result<()>;

    /// List all keys in this store
    fn list(&self) -> Vec<String>;

    /// Delete a key-value pair
    fn delete(&self, key: &str) -> Result<()>;

    /// Get a value by key
    fn get(&self, key: &str) -> Option<Vec<u8>>;

    /// Set a key-value pair
    fn set(&self, key: &str, value: Vec<u8>) -> Result<()>;

    /// Save the store to persistent storage
    fn save(&self) -> Result<()>;

    /// Destroy/delete the store
    fn destroy(&self) -> Result<()>;

    /// Serialize the store to a string
    fn to_string(&self) -> Result<String>;

    /// Serialize the store to JSON
    fn to_json(&self) -> Result<serde_json::Value>;

    /// Create a store from a string
    fn from_string(data: &str) -> Result<Box<dyn Store>>
    where
        Self: Sized;

    /// Create a store from JSON
    fn from_json(data: serde_json::Value) -> Result<Box<dyn Store>>
    where
        Self: Sized;
}

/// In-memory storage implementation
#[derive(Clone)]
pub struct MemoryStore {
    data: Arc<Mutex<HashMap<String, StoreValue>>>,
    save_callback: Option<Arc<dyn Fn() + Send + Sync>>,
    destroy_callback: Option<Arc<dyn Fn() + Send + Sync>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum StoreValue {
    Data(Vec<u8>),
    Substore(HashMap<String, StoreValue>),
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    /// Create a new memory store
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
            save_callback: None,
            destroy_callback: None,
        }
    }

    /// Create a memory store with callbacks
    pub fn with_callbacks<S, D>(save: S, destroy: D) -> Self
    where
        S: Fn() + Send + Sync + 'static,
        D: Fn() + Send + Sync + 'static,
    {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
            save_callback: Some(Arc::new(save)),
            destroy_callback: Some(Arc::new(destroy)),
        }
    }

    /// Create from existing data
    fn from_data(data: HashMap<String, StoreValue>) -> Self {
        Self {
            data: Arc::new(Mutex::new(data)),
            save_callback: None,
            destroy_callback: None,
        }
    }
}

impl Store for MemoryStore {
    fn substore(&self, key: &str) -> Box<dyn Store> {
        let store_key = format!("!{}", key);
        let data = self.data.clone();

        {
            let mut data_guard = data.lock().unwrap();

            if !data_guard.contains_key(&store_key) {
                data_guard.insert(store_key.clone(), StoreValue::Substore(HashMap::new()));
            }
        }

        Box::new(SubStore {
            parent_data: data,
            substore_key: store_key,
        })
    }

    fn rename_substore(&self, oldname: &str, newname: &str) -> Result<()> {
        if oldname == newname {
            return Ok(());
        }

        let old_key = format!("!{}", oldname);
        let new_key = format!("!{}", newname);

        {
            let mut data = self.data.lock().unwrap();

            if data.contains_key(&new_key) {
                return Err(Error::Other("Substore with new name already exists".into()));
            }

            if let Some(value) = data.remove(&old_key) {
                data.insert(new_key, value);
            }

            Ok(())
        }
    }

    fn list_substores(&self) -> Vec<String> {
        let data = self.data.lock().unwrap();
        data.keys()
            .filter(|k| k.starts_with('!'))
            .map(|k| k[1..].to_string())
            .collect()
    }

    fn delete_substore(&self, key: &str) -> Result<()> {
        let store_key = format!("!{}", key);
        let mut data = self.data.lock().unwrap();
        data.remove(&store_key);
        Ok(())
    }

    fn list(&self) -> Vec<String> {
        let data = self.data.lock().unwrap();
        data.keys()
            .filter(|k| !k.starts_with('!'))
            .cloned()
            .collect()
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut data = self.data.lock().unwrap();
        data.remove(key);
        Ok(())
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        let data = self.data.lock().unwrap();
        match data.get(key) {
            Some(StoreValue::Data(bytes)) => Some(bytes.clone()),
            _ => None,
        }
    }

    fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        let mut data = self.data.lock().unwrap();
        data.insert(key.to_string(), StoreValue::Data(value));
        Ok(())
    }

    fn save(&self) -> Result<()> {
        if let Some(ref callback) = self.save_callback {
            callback();
        }
        Ok(())
    }

    fn destroy(&self) -> Result<()> {
        if let Some(ref callback) = self.destroy_callback {
            callback();
        }
        Ok(())
    }

    fn to_string(&self) -> Result<String> {
        let data = self.data.lock().unwrap();
        let serialized = encode::to_vec(&*data)
            .map_err(|e| Error::SerializationError(format!("Failed to serialize: {}", e)))?;
        Ok(STANDARD.encode(serialized))
    }

    fn to_json(&self) -> Result<serde_json::Value> {
        let data = self.data.lock().unwrap();
        serde_json::to_value(&*data)
            .map_err(|e| Error::SerializationError(format!("Failed to serialize to JSON: {}", e)))
    }

    fn from_string(data: &str) -> Result<Box<dyn Store>> {
        let bytes = STANDARD
            .decode(data)
            .map_err(|e| Error::DeserializationError(format!("Failed to decode base64: {}", e)))?;
        let data: HashMap<String, StoreValue> = decode::from_slice(&bytes)
            .map_err(|e| Error::DeserializationError(format!("Failed to deserialize: {}", e)))?;
        Ok(Box::new(MemoryStore::from_data(data)))
    }

    fn from_json(data: serde_json::Value) -> Result<Box<dyn Store>> {
        let data: HashMap<String, StoreValue> = serde_json::from_value(data).map_err(|e| {
            Error::DeserializationError(format!("Failed to deserialize from JSON: {}", e))
        })?;
        Ok(Box::new(MemoryStore::from_data(data)))
    }
}

/// File-based storage implementation
pub struct FileStore {
    path: PathBuf,
    data: Arc<Mutex<HashMap<String, StoreValue>>>,
}

impl FileStore {
    /// Create a new file store at the given path
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        // Load existing data if file exists
        let data = if path.exists() {
            let contents = fs::read_to_string(&path)
                .map_err(|e| Error::Other(format!("Failed to read file: {}", e)))?;

            if contents.is_empty() {
                HashMap::new()
            } else {
                serde_json::from_str(&contents).map_err(|e| {
                    Error::DeserializationError(format!("Failed to parse file: {}", e))
                })?
            }
        } else {
            // Create parent directories if they don't exist
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| Error::Other(format!("Failed to create directories: {}", e)))?;
            }
            HashMap::new()
        };

        Ok(Self {
            path,
            data: Arc::new(Mutex::new(data)),
        })
    }

    /// Save data to file
    fn persist(&self) -> Result<()> {
        let data = self.data.lock().unwrap();
        let json = serde_json::to_string_pretty(&*data)
            .map_err(|e| Error::SerializationError(format!("Failed to serialize: {}", e)))?;

        fs::write(&self.path, json)
            .map_err(|e| Error::Other(format!("Failed to write file: {}", e)))?;

        Ok(())
    }

    /// Create from existing data
    fn from_data(path: PathBuf, data: HashMap<String, StoreValue>) -> Self {
        Self {
            path,
            data: Arc::new(Mutex::new(data)),
        }
    }
}

impl Store for FileStore {
    fn substore(&self, key: &str) -> Box<dyn Store> {
        let store_key = format!("!{}", key);
        let data = self.data.clone();
        let substore_path = self.path.with_extension(format!("{}.json", key));

        {
            let mut data_guard = data.lock().unwrap();

            if !data_guard.contains_key(&store_key) {
                data_guard.insert(store_key.clone(), StoreValue::Substore(HashMap::new()));
            }

            if let Some(StoreValue::Substore(substore_data)) = data_guard.get(&store_key) {
                Box::new(FileStore::from_data(substore_path, substore_data.clone()))
            } else {
                Box::new(FileStore::from_data(substore_path, HashMap::new()))
            }
        }
    }

    fn rename_substore(&self, oldname: &str, newname: &str) -> Result<()> {
        if oldname == newname {
            return Ok(());
        }

        let old_key = format!("!{}", oldname);
        let new_key = format!("!{}", newname);

        {
            let mut data = self.data.lock().unwrap();

            if data.contains_key(&new_key) {
                return Err(Error::Other("Substore with new name already exists".into()));
            }

            if let Some(value) = data.remove(&old_key) {
                data.insert(new_key, value);

                // Persist changes
                self.persist()?;
            }

            Ok(())
        }
    }

    fn list_substores(&self) -> Vec<String> {
        let data = self.data.lock().unwrap();
        data.keys()
            .filter(|k| k.starts_with('!'))
            .map(|k| k[1..].to_string())
            .collect()
    }

    fn delete_substore(&self, key: &str) -> Result<()> {
        let store_key = format!("!{}", key);
        let mut data = self.data.lock().unwrap();
        data.remove(&store_key);
        drop(data);
        // Persist changes
        self.persist()
    }

    fn list(&self) -> Vec<String> {
        let data = self.data.lock().unwrap();
        data.keys()
            .filter(|k| !k.starts_with('!'))
            .cloned()
            .collect()
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut data = self.data.lock().unwrap();
        data.remove(key);
        drop(data);
        // Persist changes
        self.persist()
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        let data = self.data.lock().unwrap();
        match data.get(key) {
            Some(StoreValue::Data(bytes)) => Some(bytes.clone()),
            _ => None,
        }
    }

    fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        let mut data = self.data.lock().unwrap();
        data.insert(key.to_string(), StoreValue::Data(value));
        drop(data);
        // Persist changes
        self.persist()
    }

    fn save(&self) -> Result<()> {
        self.persist()
    }

    fn destroy(&self) -> Result<()> {
        // Delete the file
        fs::remove_file(&self.path)
            .map_err(|e| Error::Other(format!("Failed to delete file: {}", e)))?;
        Ok(())
    }

    fn to_string(&self) -> Result<String> {
        let data = self.data.lock().unwrap();
        let serialized = encode::to_vec(&*data)
            .map_err(|e| Error::SerializationError(format!("Failed to serialize: {}", e)))?;
        Ok(STANDARD.encode(serialized))
    }

    fn to_json(&self) -> Result<serde_json::Value> {
        let data = self.data.lock().unwrap();
        serde_json::to_value(&*data)
            .map_err(|e| Error::SerializationError(format!("Failed to serialize to JSON: {}", e)))
    }

    fn from_string(_data: &str) -> Result<Box<dyn Store>> {
        Err(Error::Other(
            "FileStore cannot be created from string without path".into(),
        ))
    }

    fn from_json(_data: serde_json::Value) -> Result<Box<dyn Store>> {
        Err(Error::Other(
            "FileStore cannot be created from JSON without path".into(),
        ))
    }
}

/// MessagePack-based storage implementation
pub struct MessagePackStore {
    inner: MemoryStore,
}

impl Default for MessagePackStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MessagePackStore {
    /// Create a new MessagePack store
    pub fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
        }
    }

    /// Create with data
    fn from_data(data: HashMap<String, StoreValue>) -> Self {
        Self {
            inner: MemoryStore::from_data(data),
        }
    }
}

impl Store for MessagePackStore {
    fn substore(&self, key: &str) -> Box<dyn Store> {
        self.inner.substore(key)
    }

    fn rename_substore(&self, oldname: &str, newname: &str) -> Result<()> {
        self.inner.rename_substore(oldname, newname)
    }

    fn list_substores(&self) -> Vec<String> {
        self.inner.list_substores()
    }

    fn delete_substore(&self, key: &str) -> Result<()> {
        self.inner.delete_substore(key)
    }

    fn list(&self) -> Vec<String> {
        self.inner.list()
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key)
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.inner.get(key)
    }

    fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.inner.set(key, value)
    }

    fn save(&self) -> Result<()> {
        self.inner.save()
    }

    fn destroy(&self) -> Result<()> {
        self.inner.destroy()
    }

    fn to_string(&self) -> Result<String> {
        let data = self.inner.data.lock().unwrap();
        let bytes = encode::to_vec(&*data)
            .map_err(|e| Error::SerializationError(format!("Failed to serialize: {}", e)))?;
        Ok(STANDARD.encode(bytes))
    }

    fn to_json(&self) -> Result<serde_json::Value> {
        self.inner.to_json()
    }

    fn from_string(data: &str) -> Result<Box<dyn Store>> {
        let bytes = STANDARD
            .decode(data)
            .map_err(|e| Error::DeserializationError(format!("Failed to decode base64: {}", e)))?;
        let data: HashMap<String, StoreValue> = decode::from_slice(&bytes)
            .map_err(|e| Error::DeserializationError(format!("Failed to deserialize: {}", e)))?;
        Ok(Box::new(MessagePackStore::from_data(data)))
    }

    fn from_json(data: serde_json::Value) -> Result<Box<dyn Store>> {
        let data: HashMap<String, StoreValue> = serde_json::from_value(data).map_err(|e| {
            Error::DeserializationError(format!("Failed to deserialize from JSON: {}", e))
        })?;
        Ok(Box::new(MessagePackStore::from_data(data)))
    }
}

/// A substore that shares data with its parent store
struct SubStore {
    parent_data: Arc<Mutex<HashMap<String, StoreValue>>>,
    substore_key: String,
}

impl Store for SubStore {
    fn substore(&self, key: &str) -> Box<dyn Store> {
        let nested_key = format!("{}!{}", self.substore_key, key);
        let data = self.parent_data.clone();

        {
            let mut data_guard = data.lock().unwrap();

            if !data_guard.contains_key(&nested_key) {
                data_guard.insert(nested_key.clone(), StoreValue::Substore(HashMap::new()));
            }
        }

        Box::new(SubStore {
            parent_data: data,
            substore_key: nested_key,
        })
    }

    fn rename_substore(&self, oldname: &str, newname: &str) -> Result<()> {
        if oldname == newname {
            return Ok(());
        }

        let old_key = format!("{}!{}", self.substore_key, oldname);
        let new_key = format!("{}!{}", self.substore_key, newname);

        {
            let mut data = self.parent_data.lock().unwrap();

            if data.contains_key(&new_key) {
                return Err(Error::Other("Substore with new name already exists".into()));
            }

            if let Some(value) = data.remove(&old_key) {
                data.insert(new_key, value);
            }

            Ok(())
        }
    }

    fn list_substores(&self) -> Vec<String> {
        let data = self.parent_data.lock().unwrap();
        let prefix = format!("{}!", self.substore_key);
        data.keys()
            .filter(|k| k.starts_with(&prefix))
            .map(|k| {
                k[prefix.len()..]
                    .split('!')
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }

    fn delete_substore(&self, key: &str) -> Result<()> {
        let store_key = format!("{}!{}", self.substore_key, key);
        let mut data = self.parent_data.lock().unwrap();
        data.remove(&store_key);
        Ok(())
    }

    fn list(&self) -> Vec<String> {
        let data = self.parent_data.lock().unwrap();
        if let Some(StoreValue::Substore(substore_data)) = data.get(&self.substore_key) {
            substore_data
                .keys()
                .filter(|k| !k.starts_with('!'))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut data = self.parent_data.lock().unwrap();
        if let Some(StoreValue::Substore(ref mut substore_data)) = data.get_mut(&self.substore_key)
        {
            substore_data.remove(key);
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        let data = self.parent_data.lock().unwrap();
        if let Some(StoreValue::Substore(substore_data)) = data.get(&self.substore_key) {
            match substore_data.get(key) {
                Some(StoreValue::Data(bytes)) => Some(bytes.clone()),
                _ => None,
            }
        } else {
            None
        }
    }

    fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        let mut data = self.parent_data.lock().unwrap();
        if let Some(StoreValue::Substore(ref mut substore_data)) = data.get_mut(&self.substore_key)
        {
            substore_data.insert(key.to_string(), StoreValue::Data(value));
        } else {
            // Create substore if it doesn't exist
            let mut new_substore = HashMap::new();
            new_substore.insert(key.to_string(), StoreValue::Data(value));
            data.insert(
                self.substore_key.clone(),
                StoreValue::Substore(new_substore),
            );
        }
        Ok(())
    }

    fn save(&self) -> Result<()> {
        // No-op for substore - parent handles persistence
        Ok(())
    }

    fn destroy(&self) -> Result<()> {
        // No-op for substore - parent handles persistence
        Ok(())
    }

    fn to_string(&self) -> Result<String> {
        let data = self.parent_data.lock().unwrap();
        if let Some(StoreValue::Substore(substore_data)) = data.get(&self.substore_key) {
            let serialized = encode::to_vec(substore_data)
                .map_err(|e| Error::SerializationError(format!("Failed to serialize: {}", e)))?;
            Ok(STANDARD.encode(serialized))
        } else {
            Ok(STANDARD.encode(
                encode::to_vec(&HashMap::<String, StoreValue>::new()).map_err(|e| {
                    Error::SerializationError(format!("Failed to serialize: {}", e))
                })?,
            ))
        }
    }

    fn to_json(&self) -> Result<serde_json::Value> {
        let data = self.parent_data.lock().unwrap();
        if let Some(StoreValue::Substore(substore_data)) = data.get(&self.substore_key) {
            serde_json::to_value(substore_data).map_err(|e| {
                Error::SerializationError(format!("Failed to serialize to JSON: {}", e))
            })
        } else {
            Ok(serde_json::json!({}))
        }
    }

    fn from_string(_data: &str) -> Result<Box<dyn Store>> {
        Err(Error::Other(
            "SubStore cannot be created from string directly".into(),
        ))
    }

    fn from_json(_data: serde_json::Value) -> Result<Box<dyn Store>> {
        Err(Error::Other(
            "SubStore cannot be created from JSON directly".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_memory_store() {
        let store = MemoryStore::new();

        // Test basic operations
        store.set("key1", b"value1".to_vec()).unwrap();
        assert_eq!(store.get("key1"), Some(b"value1".to_vec()));

        // Test listing
        store.set("key2", b"value2".to_vec()).unwrap();
        let keys = store.list();
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));

        // Test deletion
        store.delete("key1").unwrap();
        assert_eq!(store.get("key1"), None);
    }

    #[test]
    fn test_substores() {
        let store = MemoryStore::new();

        // Create and use a substore
        let sub = store.substore("test_sub");
        sub.set("sub_key", b"sub_value".to_vec()).unwrap();

        // List substores
        let substores = store.list_substores();
        assert!(substores.contains(&"test_sub".to_string()));

        // Access the same substore again
        let sub2 = store.substore("test_sub");
        assert_eq!(sub2.get("sub_key"), Some(b"sub_value".to_vec()));
    }

    #[test]
    fn test_file_store() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_store.json");

        {
            let store = FileStore::new(&file_path).unwrap();

            // Test basic operations
            store.set("key1", b"value1".to_vec()).unwrap();
            assert_eq!(store.get("key1"), Some(b"value1".to_vec()));
        }

        // Test persistence - create new store from same file
        {
            let store = FileStore::new(&file_path).unwrap();
            assert_eq!(store.get("key1"), Some(b"value1".to_vec()));

            // Clean up
            store.destroy().unwrap();
        }
    }

    #[test]
    fn test_serialization() {
        let store = MemoryStore::new();
        store.set("key1", b"value1".to_vec()).unwrap();
        store.set("key2", b"value2".to_vec()).unwrap();

        // Test string serialization
        let serialized = store.to_string().unwrap();
        let deserialized = MemoryStore::from_string(&serialized).unwrap();

        assert_eq!(deserialized.get("key1"), Some(b"value1".to_vec()));
        assert_eq!(deserialized.get("key2"), Some(b"value2".to_vec()));

        // Test JSON serialization
        let json = store.to_json().unwrap();
        let from_json = MemoryStore::from_json(json).unwrap();

        assert_eq!(from_json.get("key1"), Some(b"value1".to_vec()));
        assert_eq!(from_json.get("key2"), Some(b"value2".to_vec()));
    }
}
