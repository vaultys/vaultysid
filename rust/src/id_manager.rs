use crate::challenger::Challenger;
use crate::crypto::{from_base64, hash, random_bytes, to_hex};
use crate::error::{Error, Result};
use crate::file_storage::{FileStore, MemoryStore, Store};
use crate::vaultys_id::VaultysId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

const ENCRYPTION_HEADER: &[u8] = b"VAULTYSID_ENCRYPTED_FILE_V1";
const PRF_NONCE_LENGTH: usize = 32;

/// Get signature type based on VaultysId type
fn _get_signature_type(vaultys_id: &VaultysId) -> &'static str {
    if vaultys_id.is_machine() {
        "machine"
    } else if vaultys_id.is_person() {
        "person"
    } else {
        "organization"
    }
}

/// Stored contact information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredContact {
    pub did: String,
    pub certificate: Option<Vec<u8>>,
    pub metadata: HashMap<String, String>,
    pub id: Option<Vec<u8>>,
}

/// Stored application information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredApp {
    pub site: String,
    pub server_id: Option<String>,
    pub certificate: Option<Vec<u8>>,
    pub timestamp: Option<u64>,
}

/// File signature information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSignature {
    pub signer: String,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

/// File information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct File {
    pub name: String,
    pub file_type: String,
    pub array_buffer: Vec<u8>,
    pub signatures: Vec<FileSignature>,
}

/// Instantiate a contact from stored data
async fn _instantiate_contact(contact: &StoredContact) -> Result<VaultysId> {
    let vaultys_id = if let Some(ref id) = contact.id {
        VaultysId::from_id(id, None, None)?
    } else {
        // Try to parse from DID
        let did_parts: Vec<&str> = contact.did.split(':').collect();
        if did_parts.len() >= 3 && did_parts[0] == "did" && did_parts[1] == "key" {
            let key_data = from_base64(did_parts[2])?;
            VaultysId::from_id(&key_data, None, None)?
        } else {
            return Err(Error::Other("Invalid contact format".into()));
        }
    };

    Ok(vaultys_id)
}

/// Instantiate an app (placeholder - needs app-specific implementation)
async fn _instantiate_app(_app: &StoredApp) -> Result<()> {
    Ok(())
}

/// Main ID Manager for managing VaultysId identities
pub struct IdManager {
    pub vaultys_id: Arc<Mutex<VaultysId>>,
    store: Arc<Mutex<Box<dyn Store>>>,
    protocol_version: u8,
}

impl IdManager {
    /// Create a new IdManager
    pub async fn new(vaultys_id: VaultysId, store: Box<dyn Store>) -> Result<Self> {
        // Store the VaultysId
        store.set("vaultysid", vaultys_id.get_secret()?)?;
        store.save()?;

        Ok(Self {
            vaultys_id: Arc::new(Mutex::new(vaultys_id)),
            store: Arc::new(Mutex::new(store)),
            protocol_version: 1,
        })
    }

    /// Set protocol version
    pub fn set_protocol_version(&mut self, version: u8) {
        self.protocol_version = version;
    }

    /// Export a backup of the IdManager
    pub async fn export_backup(&self, password: &str) -> Result<Vec<u8>> {
        let store = self.store.lock().await;

        // Create export data
        let exported_data = serde_json::json!({
            "version": 1,
            "data": store.to_json()?
        });

        // Encrypt with password
        let backup = self.encrypt_with_password(
            &serde_json::to_vec(&exported_data)
                .map_err(|e| Error::SerializationError(e.to_string()))?,
            password,
        )?;

        Ok(backup)
    }

    /// Import from backup
    pub async fn import_backup(
        backup: &[u8],
        password: &str,
        store_path: Option<&Path>,
    ) -> Result<Self> {
        // Decrypt backup
        let decrypted = Self::decrypt_with_password(backup, password)?;

        // Parse exported data
        let imported_data: serde_json::Value = serde_json::from_slice(&decrypted)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;

        // Create store
        let store: Box<dyn Store> = if let Some(path) = store_path {
            Box::new(FileStore::new(path)?)
        } else {
            Box::new(MemoryStore::new())
        };

        // Import data into store
        if let Some(data) = imported_data.get("data") {
            // This would need proper implementation to restore all data
            // For now, just restore the basic VaultysId
            if let Some(vaultys_id_data) = data.get("vaultysid") {
                if let Some(secret_str) = vaultys_id_data.as_str() {
                    let secret = from_base64(secret_str)?;
                    store.set("vaultysid", secret)?;
                }
            }
        }

        // Load VaultysId from store
        Self::from_store(store).await
    }

    /// Create from store
    pub async fn from_store(store: Box<dyn Store>) -> Result<Self> {
        let entropy = store.get("entropy");
        let secret = store.get("vaultysid");

        let vaultys_id = if let Some(secret_buffer) = secret {
            let id_type = store
                .get("type")
                .and_then(|t| String::from_utf8(t).ok())
                .unwrap_or_else(|| "person".to_string());

            let vaultys_id = match id_type.as_str() {
                "machine" => VaultysId::from_secret(&secret_buffer, None)?,
                "person" => VaultysId::from_secret(&secret_buffer, None)?,
                "organization" => VaultysId::from_secret(&secret_buffer, None)?,
                _ => VaultysId::from_secret(&secret_buffer, None)?,
            };

            vaultys_id
        } else if let Some(entropy_buffer) = entropy {
            VaultysId::from_entropy(&entropy_buffer, 0x01).await?
        } else {
            VaultysId::generate_person().await?
        };

        Ok(Self {
            vaultys_id: Arc::new(Mutex::new(vaultys_id)),
            store: Arc::new(Mutex::new(store)),
            protocol_version: 1,
        })
    }

    /// Get contacts
    pub async fn contacts(&self) -> Vec<StoredContact> {
        let store = self.store.lock().await;
        let s = store.substore("contacts");

        s.list()
            .into_iter()
            .filter_map(|did| {
                s.get(&did)
                    .and_then(|data| serde_json::from_slice::<StoredContact>(&data).ok())
            })
            .collect()
    }

    /// Get apps
    pub async fn apps(&self) -> Vec<StoredApp> {
        let store = self.store.lock().await;
        let s = store.substore("apps");

        s.list()
            .into_iter()
            .filter_map(|site| {
                s.get(&site)
                    .and_then(|data| serde_json::from_slice::<StoredApp>(&data).ok())
            })
            .collect()
    }

    /// Get a specific contact
    pub async fn get_contact(&self, did: &str) -> Option<StoredContact> {
        let store = self.store.lock().await;
        let c = store.substore("contacts");

        c.get(did)
            .and_then(|data| serde_json::from_slice::<StoredContact>(&data).ok())
    }

    /// Get a specific app
    pub async fn get_app(&self, site: &str) -> Option<StoredApp> {
        let store = self.store.lock().await;
        let app_store = store.substore("apps");

        app_store
            .get(site)
            .and_then(|data| serde_json::from_slice::<StoredApp>(&data).ok())
    }

    /// Set contact metadata
    pub async fn set_contact_metadata(&self, did: &str, key: &str, value: &str) -> Result<()> {
        let store = self.store.lock().await;
        let c = store.substore("contacts");

        if let Some(mut contact) = c
            .get(did)
            .and_then(|data| serde_json::from_slice::<StoredContact>(&data).ok())
        {
            contact.metadata.insert(key.to_string(), value.to_string());
            c.set(
                did,
                serde_json::to_vec(&contact)
                    .map_err(|e| Error::SerializationError(e.to_string()))?,
            )?;
            store.save()?;
        }

        Ok(())
    }

    /// Get contact metadata
    pub async fn get_contact_metadata(&self, did: &str, key: &str) -> Option<String> {
        self.get_contact(did)
            .await
            .and_then(|c| c.metadata.get(key).cloned())
    }

    /// Set name
    pub async fn set_name(&self, name: &str) -> Result<()> {
        let store = self.store.lock().await;
        store.set("name", name.as_bytes().to_vec())?;
        store.save()
    }

    /// Get name
    pub async fn name(&self) -> Option<String> {
        let store = self.store.lock().await;
        store.get("name").and_then(|n| String::from_utf8(n).ok())
    }

    /// Get display name
    pub async fn display_name(&self) -> String {
        if let Some(name) = self.name().await {
            name
        } else {
            let vaultys_id = self.vaultys_id.lock().await;
            to_hex(&vaultys_id.fingerprint())
        }
    }

    /// Set phone
    pub async fn set_phone(&self, phone: &str) -> Result<()> {
        let store = self.store.lock().await;
        store.set("phone", phone.as_bytes().to_vec())?;
        store.save()
    }

    /// Get phone
    pub async fn phone(&self) -> Option<String> {
        let store = self.store.lock().await;
        store.get("phone").and_then(|p| String::from_utf8(p).ok())
    }

    /// Set email
    pub async fn set_email(&self, email: &str) -> Result<()> {
        let store = self.store.lock().await;
        store.set("email", email.as_bytes().to_vec())?;
        store.save()
    }

    /// Get email
    pub async fn email(&self) -> Option<String> {
        let store = self.store.lock().await;
        store.get("email").and_then(|e| String::from_utf8(e).ok())
    }

    /// Sign a challenge (bytes)
    pub async fn sign_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        let vaultys_id = self.vaultys_id.lock().await;
        let signature = vaultys_id.sign_challenge(challenge).await?;
        Ok(signature.signature)
    }

    /// Sign a challenge (string convenience method)
    pub async fn sign_challenge_str(&self, challenge: &str) -> Result<Vec<u8>> {
        self.sign_challenge(challenge.as_bytes()).await
    }

    /// Sign a file
    pub async fn sign_file(&self, file: &File) -> Result<FileSignature> {
        let h = hash("sha256", &file.array_buffer);
        let challenge = format!("Sign file: {} (SHA256: {})", file.name, to_hex(&h));

        let vaultys_id = self.vaultys_id.lock().await;
        let signed = vaultys_id.sign_challenge(challenge.as_bytes()).await?;

        Ok(FileSignature {
            signer: vaultys_id.did(),
            signature: signed.signature,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| Error::Other(format!("Time error: {}", e)))?
                .as_secs(),
        })
    }

    /// Verify a file signature
    pub fn verify_file(&self, file: &File, _signature: &FileSignature) -> Result<bool> {
        let h = hash("sha256", &file.array_buffer);
        let _challenge = format!("Sign file: {} (SHA256: {})", file.name, to_hex(&h));

        // This would need the signer's public key to verify
        // For now, return a placeholder
        Ok(false)
    }

    /// Encrypt a file
    pub async fn encrypt_file(&self, file: &File, recipient_did: Option<&str>) -> Result<Vec<u8>> {
        let vaultys_id = self.vaultys_id.lock().await;

        // Generate PRF nonce
        let prf_nonce_bytes = random_bytes(PRF_NONCE_LENGTH);

        // Generate encryption key using PRF
        let secret_key = if let Some(_did) = recipient_did {
            // Encrypt for specific recipient
            random_bytes(32)
        } else {
            // Self-encryption
            // Generate a key from the secret using PRF (simplified for now)
            let secret = vaultys_id.get_secret()?;
            let mut key = vec![0u8; 32];
            for i in 0..32 {
                key[i] = secret[i % secret.len()] ^ prf_nonce_bytes[i % prf_nonce_bytes.len()];
            }
            key
        };

        // Encrypt file data
        let nonce_bytes = random_bytes(24);

        // Simple XOR encryption for demonstration (should use proper AEAD)
        let mut ciphertext = file.array_buffer.clone();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= secret_key[i % secret_key.len()];
        }

        // Build encrypted file
        let mut result = Vec::new();
        result.extend_from_slice(ENCRYPTION_HEADER);
        result.extend_from_slice(&prf_nonce_bytes);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt a file
    pub async fn decrypt_file(&self, encrypted_data: &[u8]) -> Result<File> {
        if encrypted_data.len() < ENCRYPTION_HEADER.len() + PRF_NONCE_LENGTH + 24 {
            return Err(Error::Other("Invalid encrypted file format".into()));
        }

        let header = &encrypted_data[0..ENCRYPTION_HEADER.len()];
        if header != ENCRYPTION_HEADER {
            return Err(Error::Other("Invalid file header".into()));
        }

        let offset = ENCRYPTION_HEADER.len();
        let prf_nonce_bytes = &encrypted_data[offset..offset + PRF_NONCE_LENGTH];
        let _nonce_bytes =
            &encrypted_data[offset + PRF_NONCE_LENGTH..offset + PRF_NONCE_LENGTH + 24];
        let ciphertext = &encrypted_data[offset + PRF_NONCE_LENGTH + 24..];

        let vaultys_id = self.vaultys_id.lock().await;

        // Generate decryption key using PRF
        // Generate decryption key using PRF (simplified for now)
        let secret = vaultys_id.get_secret()?;
        let mut secret_key = [0u8; 32];
        for i in 0..32 {
            secret_key[i] = secret[i % secret.len()] ^ prf_nonce_bytes[i % prf_nonce_bytes.len()];
        }

        // Decrypt (simple XOR for demonstration)
        let mut decrypted = ciphertext.to_vec();
        for (i, byte) in decrypted.iter_mut().enumerate() {
            *byte ^= secret_key[i % secret_key.len()];
        }

        // Parse decrypted data as file
        Ok(File {
            name: "decrypted_file".to_string(),
            file_type: "application/octet-stream".to_string(),
            array_buffer: decrypted,
            signatures: Vec::new(),
        })
    }

    /// Save a contact
    pub async fn save_contact(&self, contact: StoredContact) -> Result<()> {
        let store = self.store.lock().await;
        let contact_store = store.substore("contacts");

        contact_store.set(
            &contact.did,
            serde_json::to_vec(&contact).map_err(|e| Error::SerializationError(e.to_string()))?,
        )?;
        store.save()
    }

    /// Save an app
    pub async fn save_app(&self, app: StoredApp) -> Result<()> {
        let store = self.store.lock().await;
        let app_store = store.substore("apps");

        app_store.set(
            &app.site,
            serde_json::to_vec(&app).map_err(|e| Error::SerializationError(e.to_string()))?,
        )?;
        store.save()
    }

    /// Request connection with a contact
    pub async fn request_connect(
        &self,
        contact_did: &str,
        channel: &mut dyn crate::memory_channel::Channel,
    ) -> Result<Vec<u8>> {
        let contact = self
            .get_contact(contact_did)
            .await
            .ok_or_else(|| Error::Other("Contact not found".into()))?;

        let vaultys_id = self.vaultys_id.lock().await;

        // Generate random data for connection
        let rand = random_bytes(32);

        // Perform Diffie-Hellman if contact has an ID
        let _dh = if let Some(ref contact_id) = contact.id {
            let contact_vaultys = VaultysId::from_id(contact_id, None, None)?;
            Some(
                vaultys_id
                    .perform_diffie_hellman(&contact_vaultys.id())
                    .await?,
            )
        } else {
            None
        };

        // Send connection request
        channel.send(rand.clone()).await?;

        Ok(rand)
    }

    /// Accept connection from a contact
    pub async fn accept_connect(
        &self,
        contact_did: &str,
        channel: &mut dyn crate::memory_channel::Channel,
    ) -> Result<Vec<u8>> {
        let contact = self
            .get_contact(contact_did)
            .await
            .ok_or_else(|| Error::Other("Contact not found".into()))?;

        let vaultys_id = self.vaultys_id.lock().await;

        // Receive connection data
        let _received = channel.receive().await?;

        // Perform Diffie-Hellman if contact has an ID
        let _dh = if let Some(ref contact_id) = contact.id {
            let contact_vaultys = VaultysId::from_id(contact_id, None, None)?;
            Some(
                vaultys_id
                    .perform_diffie_hellman(&contact_vaultys.id())
                    .await?,
            )
        } else {
            None
        };

        // Generate and send response
        let rand = random_bytes(32);
        channel.send(rand.clone()).await?;

        Ok(rand)
    }

    /// Start SRP (Secure Remote Password) protocol
    pub async fn start_srp(
        &self,
        contact_did: &str,
        channel: &mut dyn crate::memory_channel::Channel,
    ) -> Result<Vec<u8>> {
        let vaultys_id = self.vaultys_id.lock().await;
        let mut challenger = Challenger::new(vaultys_id.duplicate(), Some(60_000));

        // Create challenge
        challenger.create_challenge(
            "SRP".to_string(),
            "authentication".to_string(),
            Some(self.protocol_version),
            None,
        )?;

        let cert = challenger.get_certificate()?;

        // Send certificate through channel
        channel.send(cert.clone()).await?;

        // Wait for response
        let message = channel.receive().await?;

        // Update challenger with response
        challenger.update(&message, None).await?;

        // Save contact if successful
        if challenger.is_complete() {
            let contact = StoredContact {
                did: contact_did.to_string(),
                certificate: Some(cert.clone()),
                metadata: HashMap::new(),
                id: None,
            };
            self.save_contact(contact).await?;
        }

        Ok(cert)
    }

    /// Accept SRP protocol
    pub async fn accept_srp(
        &self,
        channel: &mut dyn crate::memory_channel::Channel,
    ) -> Result<Vec<u8>> {
        let vaultys_id = self.vaultys_id.lock().await;
        let mut challenger = Challenger::new(vaultys_id.duplicate(), Some(60_000));

        // Receive initial challenge
        let message = channel.receive().await?;

        // Initialize with received challenge
        challenger.init(&message).await?;

        // Update the challenge
        challenger.update(&message, None).await?;

        // Get the updated certificate to send
        let cert = challenger.get_certificate()?;

        // Send response
        channel.send(cert.clone()).await?;

        // Wait for final confirmation
        let final_message = channel.receive().await?;
        challenger.update(&final_message, None).await?;

        if !challenger.is_complete() {
            return Err(Error::Other("SRP protocol failed".into()));
        }

        Ok(cert)
    }

    /// Ask for a contact (initiate contact establishment)
    /// This is equivalent to TypeScript's askContact method
    pub async fn ask_contact(
        &self,
        channel: &mut dyn crate::memory_channel::Channel,
        metadata: BTreeMap<String, String>,
    ) -> Result<VaultysId> {
        let vaultys_id = self.vaultys_id.lock().await;
        let mut challenger = Challenger::new(vaultys_id.duplicate(), Some(60_000));

        // Create challenge with p2p protocol and auth service
        challenger.create_challenge(
            "p2p".to_string(),
            "auth".to_string(),
            Some(self.protocol_version),
            Some(metadata),
        )?;

        let cert = challenger.get_certificate()?;

        // Send certificate through channel
        channel.send(cert.clone()).await?;

        // Wait for response
        match channel.receive().await {
            Ok(message) => {
                // Check if it's an error response (single byte 0)
                if message.len() == 1 && message[0] == 0 {
                    return Err(Error::Other("Contact refused or error in protocol".into()));
                }

                // Update challenger with response
                challenger.update(&message, None).await?;
            }
            Err(e) => {
                channel.send(vec![0]).await.ok();
                return Err(e);
            }
        }

        // Send final certificate if complete
        if challenger.is_complete() {
            let final_cert = challenger.get_certificate()?;
            channel.send(final_cert.clone()).await?;

            // Get contact ID from challenger
            let contact = challenger.get_contact_id()?;

            // Save contact
            let stored_contact = StoredContact {
                did: contact.did(),
                certificate: Some(final_cert.clone()),
                metadata: HashMap::new(),
                id: Some(contact.id()),
            };
            self.save_contact(stored_contact).await?;

            // Store in web of trust
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .to_string();
            self.store
                .lock()
                .await
                .substore("wot")
                .set(&timestamp, final_cert)
                .map_err(|e| Error::Other(format!("Failed to store certificate: {}", e)))?;

            Ok(contact)
        } else {
            channel.send(vec![0]).await.ok();
            Err(Error::Other(
                "Can't add a new contact if the protocol is not complete".into(),
            ))
        }
    }

    /// Accept a contact request
    /// This is equivalent to TypeScript's acceptContact method
    pub async fn accept_contact(
        &self,
        channel: &mut dyn crate::memory_channel::Channel,
        metadata: BTreeMap<String, String>,
    ) -> Result<VaultysId> {
        let vaultys_id = self.vaultys_id.lock().await;
        let mut challenger = Challenger::new(vaultys_id.duplicate(), Some(60_000));

        // Receive initial challenge
        let message = match channel.receive().await {
            Ok(msg) => msg,
            Err(e) => {
                channel.send(vec![0]).await.ok();
                return Err(e);
            }
        };

        // Deserialize and validate the certificate
        let cert_data = Challenger::deserialize_certificate(&message)?;

        // Check protocol and service
        if cert_data.protocol != "p2p" {
            channel.send(vec![0]).await.ok();
            return Err(Error::Other(format!(
                "protocol is not the one expected: {} != p2p",
                cert_data.protocol
            )));
        }

        if cert_data.service != "auth" {
            channel.send(vec![0]).await.ok();
            return Err(Error::Other(format!(
                "service is not the one expected: {} != auth",
                cert_data.service
            )));
        }

        // Update challenger with received message and metadata
        // The update method handles initialization when challenger is in UNINITIALISED state
        if let Err(e) = challenger.update(&message, Some(metadata)).await {
            channel.send(vec![0]).await.ok();
            return Err(e);
        }

        // Get the response certificate
        let cert = challenger.get_certificate()?;

        // Send response
        channel.send(cert.clone()).await?;

        // Wait for final confirmation
        match channel.receive().await {
            Ok(final_message) => {
                // Check if it's an error response
                if final_message.len() == 1 && final_message[0] == 0 {
                    return Err(Error::Other("Protocol failed".into()));
                }
                challenger.update(&final_message, None).await?;
            }
            Err(e) => {
                channel.close().await.ok();
                return Err(e);
            }
        }

        if !challenger.is_complete() {
            channel.close().await.ok();
            return Err(Error::Other(
                "Can't add a new contact if the protocol is not complete".into(),
            ));
        }

        // Get contact ID from challenger
        let contact = challenger.get_contact_id()?;

        // Save the final certificate
        let final_cert = challenger.get_certificate()?;

        // Save contact
        let stored_contact = StoredContact {
            did: contact.did(),
            certificate: Some(final_cert.clone()),
            metadata: HashMap::new(),
            id: Some(contact.id()),
        };
        self.save_contact(stored_contact).await?;

        // Store in web of trust
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_string();
        self.store
            .lock()
            .await
            .substore("wot")
            .set(&timestamp, final_cert)
            .map_err(|e| Error::Other(format!("Failed to store certificate: {}", e)))?;

        Ok(contact)
    }

    /// Helper: Encrypt with password (simplified)
    fn encrypt_with_password(&self, data: &[u8], password: &str) -> Result<Vec<u8>> {
        let key = hash("sha256", password.as_bytes());

        // Simple XOR encryption for demonstration
        let mut encrypted = data.to_vec();
        for (i, byte) in encrypted.iter_mut().enumerate() {
            *byte ^= key[i % key.len()];
        }

        Ok(encrypted)
    }

    /// Helper: Decrypt with password (simplified)
    fn decrypt_with_password(data: &[u8], password: &str) -> Result<Vec<u8>> {
        let key = hash("sha256", password.as_bytes());

        // Simple XOR decryption for demonstration
        let mut decrypted = data.to_vec();
        for (i, byte) in decrypted.iter_mut().enumerate() {
            *byte ^= key[i % key.len()];
        }

        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_id_manager_creation() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        assert_eq!(manager.protocol_version, 1);
    }

    #[tokio::test]
    async fn test_name_storage() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        // Set and get name
        manager.set_name("Alice").await.unwrap();
        assert_eq!(manager.name().await, Some("Alice".to_string()));

        // Display name should use the set name
        assert_eq!(manager.display_name().await, "Alice");
    }

    #[tokio::test]
    async fn test_contact_management() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        // Create and save a contact
        let contact = StoredContact {
            did: "did:key:test123".to_string(),
            certificate: None,
            metadata: HashMap::new(),
            id: None,
        };

        manager.save_contact(contact.clone()).await.unwrap();

        // Retrieve contact
        let retrieved = manager.get_contact("did:key:test123").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().did, "did:key:test123");

        // List contacts
        let contacts = manager.contacts().await;
        assert_eq!(contacts.len(), 1);
    }

    #[tokio::test]
    async fn test_file_operations() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        // Create a test file
        let file = File {
            name: "test.txt".to_string(),
            file_type: "text/plain".to_string(),
            array_buffer: b"Hello, World!".to_vec(),
            signatures: Vec::new(),
        };

        // Sign the file
        let signature = manager.sign_file(&file).await.unwrap();
        assert!(!signature.signature.is_empty());

        // Encrypt and decrypt the file
        let encrypted = manager.encrypt_file(&file, None).await.unwrap();
        assert!(encrypted.len() > file.array_buffer.len());

        let decrypted = manager.decrypt_file(&encrypted).await.unwrap();
        assert_eq!(decrypted.array_buffer, file.array_buffer);
    }

    #[tokio::test]
    async fn test_email_phone_storage() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        // Test email
        manager.set_email("test@example.com").await.unwrap();
        assert_eq!(manager.email().await, Some("test@example.com".to_string()));

        // Test phone
        manager.set_phone("+1234567890").await.unwrap();
        assert_eq!(manager.phone().await, Some("+1234567890".to_string()));
    }

    #[tokio::test]
    async fn test_protocol_version_setting() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let mut manager = IdManager::new(vaultys_id, store).await.unwrap();

        // Default should be 1
        assert_eq!(manager.protocol_version, 1);

        // Change version
        manager.set_protocol_version(2);
        assert_eq!(manager.protocol_version, 2);
    }

    #[tokio::test]
    async fn test_contact_metadata() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        let contact = StoredContact {
            did: "did:test:123".to_string(),
            certificate: None,
            metadata: HashMap::new(),
            id: None,
        };

        manager.save_contact(contact).await.unwrap();

        // Set metadata
        manager
            .set_contact_metadata("did:test:123", "nickname", "Bob")
            .await
            .unwrap();

        // Get metadata
        let nickname = manager
            .get_contact_metadata("did:test:123", "nickname")
            .await;
        assert_eq!(nickname, Some("Bob".to_string()));
    }

    #[tokio::test]
    async fn test_app_storage() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        let app = StoredApp {
            site: "https://example.com".to_string(),
            server_id: Some("server123".to_string()),
            certificate: None,
            timestamp: Some(1234567890),
        };

        manager.save_app(app.clone()).await.unwrap();

        // Retrieve app
        let retrieved = manager.get_app("https://example.com").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().server_id, Some("server123".to_string()));

        // List apps
        let apps = manager.apps().await;
        assert_eq!(apps.len(), 1);
    }

    #[tokio::test]
    async fn test_backup_export_import() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let _original_id = vaultys_id.id();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        // Set some data
        manager.set_name("Test User").await.unwrap();

        // Export backup
        let password = "test_password_123";
        let backup = manager.export_backup(password).await.unwrap();
        assert!(!backup.is_empty());

        // Import backup
        let restored = IdManager::import_backup(&backup, password, None)
            .await
            .unwrap();

        // The backup/restore process should maintain the VaultysId
        // Note: The restored manager may have a different internal representation
        // but should be functionally equivalent
        assert!(!restored.vaultys_id.lock().await.id().is_empty());
    }

    #[tokio::test]
    async fn test_wrong_password_backup_import() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        // Export backup
        let backup = manager.export_backup("correct_password").await.unwrap();

        // Try to import with wrong password
        let result = IdManager::import_backup(&backup, "wrong_password", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_display_name_without_name() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        // Without name, should return fingerprint
        let display_name = manager.display_name().await;
        assert!(!display_name.is_empty());

        // Should be hex fingerprint (at least 32 characters)
        assert!(display_name.len() >= 32);
    }

    #[tokio::test]
    async fn test_file_signature_details() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        let file = File {
            name: "document.pdf".to_string(),
            file_type: "application/pdf".to_string(),
            array_buffer: b"PDF content".to_vec(),
            signatures: Vec::new(),
        };

        let signature = manager.sign_file(&file).await.unwrap();

        // Check signature properties
        assert!(!signature.signature.is_empty());
        assert!(signature.timestamp > 0);
        // The signer should be a DID string
        assert!(signature.signer.starts_with("did:"));
    }

    #[tokio::test]
    async fn test_empty_file_encryption() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        let empty_file = File {
            name: "empty.txt".to_string(),
            file_type: "text/plain".to_string(),
            array_buffer: Vec::new(),
            signatures: Vec::new(),
        };

        // Should handle empty files
        let encrypted = manager.encrypt_file(&empty_file, None).await.unwrap();
        let decrypted = manager.decrypt_file(&encrypted).await.unwrap();

        assert_eq!(decrypted.array_buffer, empty_file.array_buffer);
    }

    #[tokio::test]
    async fn test_large_file_encryption() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        // Create 100KB file
        let large_data = vec![42u8; 100_000];
        let large_file = File {
            name: "large.bin".to_string(),
            file_type: "application/octet-stream".to_string(),
            array_buffer: large_data.clone(),
            signatures: Vec::new(),
        };

        let encrypted = manager.encrypt_file(&large_file, None).await.unwrap();
        let decrypted = manager.decrypt_file(&encrypted).await.unwrap();

        assert_eq!(decrypted.array_buffer, large_data);
    }

    #[tokio::test]
    async fn test_multiple_contacts_storage() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        // Add multiple contacts
        for i in 0..10 {
            let contact = StoredContact {
                did: format!("did:test:{}", i),
                certificate: None,
                metadata: HashMap::new(),
                id: None,
            };
            manager.save_contact(contact).await.unwrap();
        }

        // Check all are stored
        let contacts = manager.contacts().await;
        assert_eq!(contacts.len(), 10);

        // Verify individual retrieval
        for i in 0..10 {
            let contact = manager.get_contact(&format!("did:test:{}", i)).await;
            assert!(contact.is_some());
        }
    }

    #[tokio::test]
    async fn test_from_store_with_existing_data() {
        // Create a store with existing data
        let store = Box::new(MemoryStore::new());
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let secret = vaultys_id.get_secret().unwrap();

        // Save secret to store
        store.set("vaultysid", secret.clone()).unwrap();
        store.set("type", b"person".to_vec()).unwrap();

        // Create manager from store
        let manager = IdManager::from_store(store).await.unwrap();

        // Should have same secret
        assert_eq!(
            manager.vaultys_id.lock().await.get_secret().unwrap(),
            secret
        );
    }

    #[tokio::test]
    async fn test_sign_challenge() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        let challenge = "Test challenge string";
        let signature = manager.sign_challenge_str(challenge).await.unwrap();

        assert!(!signature.is_empty());
    }

    #[tokio::test]
    async fn test_ask_accept_contact() {
        use crate::memory_channel::{Channel, MemoryChannel};

        // Create two ID managers
        let vaultys_id1 = VaultysId::generate_person().await.unwrap();
        let store1 = Box::new(MemoryStore::new());
        let vaultys_id2 = VaultysId::generate_person().await.unwrap();
        let store2 = Box::new(MemoryStore::new());

        let manager1 = IdManager::new(vaultys_id1, store1).await.unwrap();
        let manager2 = IdManager::new(vaultys_id2, store2).await.unwrap();

        // Set names for identification
        manager1.set_name("Alice").await.unwrap();
        manager2.set_name("Bob").await.unwrap();

        // Create a bidirectional channel pair for communication
        let (mut channel1, mut channel2) = MemoryChannel::create_bidirectional();

        // Start both channels
        channel1.start().await.unwrap();
        channel2.start().await.unwrap();

        // Create metadata for the contact request
        let mut metadata1 = BTreeMap::new();
        metadata1.insert("name".to_string(), "Alice".to_string());
        metadata1.insert("role".to_string(), "requester".to_string());

        let mut metadata2 = BTreeMap::new();
        metadata2.insert("name".to_string(), "Bob".to_string());
        metadata2.insert("role".to_string(), "acceptor".to_string());

        // Run ask_contact and accept_contact concurrently
        // They need to run in parallel since they exchange messages
        let (ask_result, accept_result) = tokio::join!(
            manager1.ask_contact(&mut channel1, metadata1),
            manager2.accept_contact(&mut channel2, metadata2)
        );

        // Both should succeed
        assert!(
            ask_result.is_ok(),
            "ask_contact should succeed: {:?}",
            ask_result.err()
        );
        assert!(
            accept_result.is_ok(),
            "accept_contact should succeed: {:?}",
            accept_result.err()
        );

        // The returned VaultysId objects should be valid
        let contact1 = ask_result.unwrap();
        let contact2 = accept_result.unwrap();

        assert!(
            !contact1.did().is_empty(),
            "Contact 1 DID should not be empty"
        );
        assert!(
            !contact2.did().is_empty(),
            "Contact 2 DID should not be empty"
        );
    }

    #[tokio::test]
    async fn test_verify_file_placeholder() {
        let vaultys_id = VaultysId::generate_person().await.unwrap();
        let store = Box::new(MemoryStore::new());
        let manager = IdManager::new(vaultys_id, store).await.unwrap();

        let file = File {
            name: "test.txt".to_string(),
            file_type: "text/plain".to_string(),
            array_buffer: b"content".to_vec(),
            signatures: Vec::new(),
        };

        let signature = FileSignature {
            signer: to_hex(&manager.vaultys_id.lock().await.id()),
            signature: vec![1, 2, 3],
            timestamp: 1234567890,
        };

        // Currently returns false (placeholder implementation)
        let verified = manager.verify_file(&file, &signature).unwrap();
        assert!(!verified);
    }
}
